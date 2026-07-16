"""Nginx Proxy Manager facade consumed by npmctl 0.3.x."""

# ruff: noqa: B008 - Tigrbl dependencies are declared in function defaults by design.

from __future__ import annotations

import asyncio
import inspect
import os
import secrets
from collections.abc import Awaitable, Callable, Mapping
from copy import deepcopy
from types import SimpleNamespace
from typing import Any, Literal, cast

from tigrbl import (
    CORSMiddleware,
    Depends,
    HTTPException,
    Request,
    Response,
    TigrblApp,
)
from tigrbl_typing.status.mappings import status

from portwyrm.api.compat.contracts import (
    COLLECTIONS,
    SECTION_BY_COLLECTION,
    TOGGLE_COLLECTIONS,
    TOKEN_SCOPE_ACTIONS,
    TOKEN_SCOPE_SECTIONS,
    CompatibilityService,
    MFAService,
    Resource,
    TokenService,
)
from portwyrm.api.compat.resources import TableResources
from portwyrm.api.compat.transport import CompatibilityTigrblApp
from portwyrm.api.mfa import TableMFA
from portwyrm.api.middleware import ControlPlaneHTTPMiddleware
from portwyrm.api.portability import TablePortability
from portwyrm.api.security import (
    TableIdentity,
    TableSecurityDependencies,
    permissions_from_scopes,
)
from portwyrm.certificates import DEFAULT_PROVIDER_CATALOG, provider_status
from portwyrm.migration import preflight_npm
from portwyrm.security import Principal
from portwyrm.tables import CertificateStore
from portwyrm.tables.lifecycle import global_hooks


async def _identity_call(function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    value = function(*args, **kwargs)
    return await value if inspect.isawaitable(value) else value


def create_compat_app(
    service: CompatibilityService | None = None,
    *,
    tokens: TokenService | None = None,
    version: str = "0.1.0a0",
    authenticator: Any | None = None,
    certificates: Any | None = None,
    certificate_factory: Callable[[TigrblApp, CompatibilityService], Any] | None = None,
    lifespan: Any | None = None,
    portability: TablePortability | None = None,
    backend: str = "unknown",
    mfa: MFAService | None = None,
    system_status: Callable[[], Mapping[str, Any]] | None = None,
    engine: Any | None = None,
) -> TigrblApp:
    app = CompatibilityTigrblApp(
        title="Portwyrm NPM compatibility API",
        version="2.10.4",
        lifespan=lifespan,
        mount_system=False,
        engine=engine,
        router_hooks=global_hooks(),
    )
    service = service or TableResources(app)
    if certificates is None and certificate_factory is not None:
        certificates = certificate_factory(app, service)
    CertificateStore.configure_workflow(certificates)
    portability = portability or TablePortability(cast(TableResources, service), backend)
    token_store = tokens or TableIdentity(app)
    security_dependencies = TableSecurityDependencies(token_store)
    principal_from_bearer = security_dependencies.principal
    principal_from_mfa_bearer = security_dependencies.mfa_principal
    principal_for_password_change = security_dependencies.password_change_principal
    mfa = mfa or TableMFA(app)
    app.state.control_plane = service
    app.state.token_store = token_store
    app.state.certificate_manager = certificates
    app.add_middleware(ControlPlaneHTTPMiddleware)
    origins = [
        item.strip() for item in os.getenv("PORTWYRM_CORS_ORIGINS", "").split(",") if item.strip()
    ]
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type"],
        )

    @app.get("/api/", include_in_schema=True)
    async def health() -> dict[str, Any]:
        parts = version.split(".")
        numeric = [
            int("".join(character for character in part if character.isdigit()) or 0)
            for part in parts
        ]
        numeric.extend([0] * (3 - len(numeric)))
        return {
            "status": "OK",
            "version": {"major": numeric[0], "minor": numeric[1], "revision": numeric[2]},
        }

    @app.get("/api/schema", include_in_schema=False)
    async def schema() -> dict[str, Any]:
        document = deepcopy(app.openapi())
        document["info"]["version"] = "2.10.4"
        document["paths"] = {
            (path.removeprefix("/api") or "/"): operations
            for path, operations in document["paths"].items()
            if path.startswith("/api")
        }
        return document

    @app.post("/api/tokens")
    async def login(payload: dict[str, Any]) -> dict[str, Any]:
        identity = payload.get("identity")
        secret = payload.get("secret")
        scope = payload.get("scope", "user")
        if not isinstance(identity, str) or not identity.strip() or not isinstance(secret, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="identity and secret required"
            )
        if scope != "user":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unsupported scope")
        authentication = authenticator or getattr(service, "authenticate", None)
        if authentication is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="authentication service unavailable",
            )
        authenticated = await _maybe_await(
            await asyncio.to_thread(authentication, identity.strip().lower(), secret)
        )
        if authenticated is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )
        principal = _as_principal(authenticated, fallback_identity=identity)
        if mfa is not None and await _identity_call(mfa.enabled, principal.user_id):
            mfa_code = payload.get("mfa_code")
            if mfa_code is None:
                challenge = Principal(
                    user_id=principal.user_id,
                    identity=principal.identity,
                    scopes=frozenset({"mfa"}),
                )
                token, expires = await _identity_call(
                    token_store.issue_session, challenge, ttl_seconds=300
                )
                return {"result": {"token": token, "expires": expires, "scope": "mfa"}}
            if not isinstance(mfa_code, str) or not await _identity_call(
                mfa.verify, principal.user_id, mfa_code
            ):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="valid MFA code required",
                )
        token, expires = await _identity_call(token_store.issue_session, principal)
        return {"result": {"token": token, "expires": expires}}

    @app.post("/api/tokens/2fa")
    async def complete_mfa_challenge(
        payload: dict[str, Any],
        request: Request,
        challenge: Principal = Depends(principal_from_mfa_bearer),
    ) -> Resource:
        code = payload.get("code")
        if (
            mfa is None
            or not isinstance(code, str)
            or not await _identity_call(mfa.verify, challenge.user_id, code)
        ):
            raise HTTPException(status_code=401, detail="invalid MFA code")
        challenge_token = request.bearer_token or request.cookies.get("portwyrm_session")
        assert challenge_token is not None
        await _identity_call(token_store.revoke_session, challenge_token)
        user = await _service_get(service, "users", challenge.user_id, challenge)
        if user is None:
            raise HTTPException(status_code=401, detail="user is unavailable")
        principal = _as_principal(user, fallback_identity=challenge.identity)
        token, expires = await _identity_call(token_store.issue_session, principal)
        return {"result": {"token": token, "expires": expires, "scope": "user"}}

    @app.post("/api/v2/browser/login")
    async def browser_login(payload: dict[str, Any], response: Response) -> Resource:
        result = await login(payload)
        api_token = str(result["result"]["token"])
        browser_principal = await _identity_call(token_store.verify, api_token)
        await _identity_call(token_store.revoke_session, api_token)
        browser_token, expires = await _identity_call(
            token_store.issue_session,
            browser_principal,
            ttl_seconds=300 if browser_principal.scopes == frozenset({"mfa"}) else None,
        )
        _set_browser_cookies(response, browser_token)
        return {
            "result": {
                "token": browser_token,
                "expires": expires,
                "must_change_password": browser_principal.must_change_password,
                **({"scope": "mfa"} if browser_principal.scopes == frozenset({"mfa"}) else {}),
            }
        }

    @app.post("/api/v2/browser/2fa")
    async def browser_mfa(
        payload: dict[str, Any],
        response: Response,
        request: Request,
        challenge: Principal = Depends(principal_from_mfa_bearer),
    ) -> Resource:
        result = await complete_mfa_challenge(payload, request=request, challenge=challenge)
        api_token = str(result["result"]["token"])
        browser_principal = await _identity_call(token_store.verify, api_token)
        await _identity_call(token_store.revoke_session, api_token)
        browser_token, expires = await _identity_call(token_store.issue_session, browser_principal)
        _set_browser_cookies(response, browser_token)
        return {
            "result": {
                "token": browser_token,
                "expires": expires,
                "scope": "user",
                "must_change_password": browser_principal.must_change_password,
            }
        }

    @app.post("/api/v2/browser/password", status_code=status.HTTP_204_NO_CONTENT)
    async def change_bootstrap_password(
        payload: dict[str, Any],
        response: Response,
        request: Request,
        principal: Principal = Depends(principal_for_password_change),
    ) -> None:
        if not principal.must_change_password:
            raise HTTPException(status_code=409, detail="password change is not required")
        current = payload.get("current_password")
        password = payload.get("new_password")
        if not isinstance(current, str) or not isinstance(password, str):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="current and new passwords are required",
            )
        changer = getattr(service, "change_password", None)
        if changer is None:
            raise HTTPException(status_code=501, detail="password management unavailable")
        await _maybe_await(changer(principal.user_id, current, password))
        session_cookie = request.cookies.get("portwyrm_session")
        if session_cookie:
            await _identity_call(token_store.revoke_session, session_cookie)
        _expire_browser_cookies(response)

    @app.delete("/api/v2/browser/session", status_code=status.HTTP_204_NO_CONTENT)
    async def browser_logout(
        response: Response,
        request: Request,
        _: Principal = Depends(principal_from_bearer),
    ) -> None:
        session_cookie = request.cookies.get("portwyrm_session")
        if session_cookie:
            await _identity_call(token_store.revoke_session, session_cookie)
        _expire_browser_cookies(response)

    @app.get("/api/tokens")
    async def refresh(
        request: Request,
        _: Principal = Depends(principal_from_bearer),
    ) -> dict[str, Any]:
        token_value = request.bearer_token
        if token_value is None:
            raise HTTPException(status_code=401, detail="bearer token required")
        token, expires = await _identity_call(token_store.refresh_session, token_value)
        return {"token": token, "expires": expires}

    @app.delete("/api/tokens", status_code=status.HTTP_204_NO_CONTENT)
    async def logout(
        request: Request,
        _: Principal = Depends(principal_from_bearer),
    ) -> None:
        token_value = request.bearer_token
        if token_value is None:
            raise HTTPException(status_code=401, detail="bearer token required")
        await _identity_call(token_store.revoke_session, token_value)

    @app.get("/api/v2/me")
    async def profile(principal: Principal = Depends(principal_from_bearer)) -> Resource:
        user = await _service_get(service, "users", principal.user_id, principal)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
        return {
            **_copy_visible(user, principal),
            "mfa_enabled": bool(mfa and await _identity_call(mfa.enabled, principal.user_id)),
        }

    @app.get("/api/v2/system/status")
    async def authenticated_system_status(
        _: Principal = Depends(principal_from_bearer),
    ) -> Mapping[str, Any]:
        if system_status is None:
            return {"status": "unavailable", "components": {}}
        return await asyncio.to_thread(system_status)

    @app.post("/api/v2/mfa/enroll")
    async def enroll_mfa(principal: Principal = Depends(principal_from_bearer)) -> Resource:
        if mfa is None:
            raise HTTPException(status_code=501, detail="MFA unavailable")
        if await _identity_call(mfa.enabled, principal.user_id):
            raise HTTPException(status_code=409, detail="MFA is already enabled")
        result = await _identity_call(mfa.begin, principal.user_id)
        return result

    @app.post("/api/v2/mfa/confirm", status_code=status.HTTP_204_NO_CONTENT)
    async def confirm_mfa(
        payload: dict[str, Any], principal: Principal = Depends(principal_from_bearer)
    ) -> None:
        code = payload.get("code")
        if (
            mfa is None
            or not isinstance(code, str)
            or not await _identity_call(mfa.confirm, principal.user_id, code)
        ):
            raise HTTPException(status_code=422, detail="invalid enrollment code")

    @app.delete("/api/v2/mfa", status_code=status.HTTP_204_NO_CONTENT)
    async def disable_mfa(
        payload: dict[str, Any], principal: Principal = Depends(principal_from_bearer)
    ) -> None:
        code = payload.get("code")
        if (
            mfa is None
            or not isinstance(code, str)
            or not await _identity_call(mfa.disable, principal.user_id, code)
        ):
            raise HTTPException(status_code=422, detail="invalid MFA code")

    @app.post("/api/v2/mfa/recovery-codes")
    async def regenerate_mfa_recovery_codes(
        payload: dict[str, Any], principal: Principal = Depends(principal_from_bearer)
    ) -> Resource:
        code = payload.get("code")
        codes = (
            await _identity_call(mfa.regenerate_backup_codes, principal.user_id, code)
            if mfa is not None and isinstance(code, str)
            else None
        )
        if codes is None:
            raise HTTPException(status_code=422, detail="invalid MFA code")
        return {"backup_codes": codes}

    @app.put("/api/v2/me")
    async def update_profile(
        payload: dict[str, Any], principal: Principal = Depends(principal_from_bearer)
    ) -> Resource:
        allowed = {key: payload[key] for key in ("name", "nickname", "email") if key in payload}
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="no editable profile fields supplied",
            )
        updated = await _service_update(service, "users", principal.user_id, allowed, principal)
        if updated is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
        return updated

    @app.put("/api/users/{user_id}/auth", status_code=status.HTTP_204_NO_CONTENT)
    async def set_user_password(
        user_id: int,
        payload: dict[str, Any],
        principal: Principal = Depends(principal_from_bearer),
    ) -> None:
        password = payload.get("password")
        current = payload.get("current")
        if not isinstance(password, str):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="password is required"
            )
        if principal.is_admin and str(principal.user_id) != str(user_id):
            setter = getattr(service, "set_password", None)
            if setter is None:
                raise HTTPException(status_code=501, detail="password management unavailable")
            await _maybe_await(setter(user_id, password))
            return
        if str(principal.user_id) != str(user_id) or not isinstance(current, str):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="permission denied")
        changer = getattr(service, "change_password", None)
        if changer is None:
            raise HTTPException(status_code=501, detail="password management unavailable")
        await _maybe_await(changer(user_id, current, password))

    @app.post("/api/users/{user_id}/login")
    async def impersonate_user(
        user_id: int, principal: Principal = Depends(principal_from_bearer)
    ) -> Resource:
        _require_admin(principal)
        user = await _service_get(service, "users", user_id, principal)
        if user is None or user.get("is_disabled") or user.get("is_deleted"):
            raise HTTPException(status_code=404, detail="active user not found")
        impersonated = _as_principal(user, fallback_identity=str(user.get("email", user_id)))
        token, expires = await _identity_call(token_store.issue_session, impersonated)
        return {"token": token, "expires": expires, "user": user}

    @app.get("/api/v2/tokens")
    async def list_personal_tokens(
        request: Request,
        principal: Principal = Depends(principal_from_bearer),
    ) -> list[Resource]:
        include_all = _query_bool(request, "include_all")
        records = await _identity_call(token_store.list_pats, principal)
        if not (include_all and principal.is_admin):
            records = [
                record
                for record in records
                if str(record.principal.user_id) == str(principal.user_id)
            ]
        return [record.public() for record in records]

    @app.post("/api/v2/tokens", status_code=status.HTTP_201_CREATED)
    async def create_personal_token(
        payload: dict[str, Any], principal: Principal = Depends(principal_from_bearer)
    ) -> Resource:
        name = payload.get("name")
        expires_at = payload.get("expires_at")
        scopes = payload.get("scopes", sorted(principal.scopes))
        if not isinstance(name, str) or not isinstance(scopes, list):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="name and scopes are required",
            )
        requested = frozenset(str(scope).strip() for scope in scopes)
        if not requested:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="invalid token scopes"
            )
        try:
            token_permissions, token_is_admin = _validate_token_scopes(requested, principal)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        stored_scopes = requested if requested == {"user"} else requested | {"user"}
        pat_principal = Principal(
            user_id=principal.user_id,
            identity=principal.identity,
            is_admin=token_is_admin,
            permissions=token_permissions,
            visibility=principal.visibility,
            scopes=stored_scopes,
            owner=principal.owner,
        )
        try:
            record, plaintext = await _identity_call(
                token_store.create_pat,
                name=name,
                principal=pat_principal,
                expires_at=int(expires_at) if expires_at is not None else None,
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
            ) from exc
        return {**record.public(), "token": plaintext}

    @app.post("/api/v2/tokens/{token_id}/rotate", status_code=status.HTTP_201_CREATED)
    async def rotate_personal_token(
        token_id: str, principal: Principal = Depends(principal_from_bearer)
    ) -> Resource:
        record = await _owned_token(token_store, token_id, principal)
        if record.revoked_at is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="token is revoked")
        try:
            replacement, plaintext = await _identity_call(token_store.rotate_pat, token_id)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        return {**replacement.public(), "token": plaintext}

    @app.delete("/api/v2/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def revoke_personal_token(
        token_id: str, principal: Principal = Depends(principal_from_bearer)
    ) -> None:
        record = await _owned_token(token_store, token_id, principal)
        if record.revoked_at is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="token is revoked")
        await _identity_call(token_store.revoke_pat, token_id)

    @app.get("/api/v2/export")
    async def export_state(principal: Principal = Depends(principal_from_bearer)) -> Resource:
        _require_admin(principal)
        return await portability.export()

    @app.post("/api/v2/import/preview")
    async def preview_state_import(
        payload: dict[str, Any],
        request: Request,
        principal: Principal = Depends(principal_from_bearer),
    ) -> Resource:
        replace = _query_bool(request, "replace")
        _require_admin(principal)
        return await portability.preview(payload, replace=replace)

    @app.post("/api/v2/import")
    async def apply_state_import(
        payload: dict[str, Any],
        request: Request,
        principal: Principal = Depends(principal_from_bearer),
    ) -> Resource:
        replace = _query_bool(request, "replace")
        _require_admin(principal)
        result = await portability.import_(payload, replace=replace, actor=principal)
        await _reload_after_import(service)
        return result

    @app.post("/api/v2/migration/npm/preflight")
    async def npm_preflight(
        payload: dict[str, Any], principal: Principal = Depends(principal_from_bearer)
    ) -> Resource:
        _require_admin(principal)
        source = payload.get("source")
        if not isinstance(source, Mapping):
            raise HTTPException(status_code=422, detail="source must be an NPM table mapping")
        return preflight_npm(source, source_kind="api").to_dict(include_records=True)

    @app.post("/api/v2/migration/npm/import")
    async def npm_import(
        payload: dict[str, Any],
        request: Request,
        principal: Principal = Depends(principal_from_bearer),
    ) -> Resource:
        replace = _query_bool(request, "replace")
        dry_run = _query_bool(request, "dry_run", default=True)
        _require_admin(principal)
        source = payload.get("source")
        if not isinstance(source, Mapping):
            raise HTTPException(status_code=422, detail="source must be an NPM table mapping")
        report = preflight_npm(source, source_kind="api")
        result = await _apply_npm_report(service, report, dry_run=dry_run, replace=replace)
        if not dry_run:
            await _reload_after_import(service)
        return result

    @app.get("/api/nginx/certificates/dns-providers")
    async def dns_providers(
        principal: Principal = Depends(principal_from_bearer),
    ) -> list[Resource]:
        _authorize(principal, "certificates", admin_only=False, action="read")
        providers = []
        for provider in DEFAULT_PROVIDER_CATALOG:
            status = provider_status(provider)
            providers.append(
                {
                    "id": provider.id,
                    "name": provider.name,
                    "package_name": provider.package_name,
                    "credential_fields": list(provider.credential_fields),
                    "installed": status.installed,
                    "installed_version": status.version,
                    "support_tier": status.support_tier,
                }
            )
        return providers

    @app.post("/api/nginx/certificates/validate")
    async def validate_certificate(
        payload: dict[str, Any], principal: Principal = Depends(principal_from_bearer)
    ) -> Resource:
        _authorize(principal, "certificates", admin_only=False, action="create")
        return await app.core.CertificateStore.validate(
            payload, ctx={"principal": _actor(principal)}
        )

    @app.post("/api/nginx/certificates/upload", status_code=status.HTTP_201_CREATED)
    async def upload_certificate(
        payload: dict[str, Any], principal: Principal = Depends(principal_from_bearer)
    ) -> Resource:
        _authorize(principal, "certificates", admin_only=False, action="create")
        return await app.core.CertificateStore.upload(payload, ctx={"principal": _actor(principal)})

    @app.post("/api/nginx/certificates/{certificate_id}/upload")
    async def replace_certificate(
        certificate_id: int,
        payload: dict[str, Any],
        principal: Principal = Depends(principal_from_bearer),
    ) -> Resource:
        _authorize(principal, "certificates", admin_only=False, action="update")
        return await app.core.CertificateStore.upload(
            {"id": certificate_id, **payload}, ctx={"principal": _actor(principal)}
        )

    @app.post("/api/nginx/certificates/request", status_code=status.HTTP_201_CREATED)
    async def request_certificate(
        payload: dict[str, Any], principal: Principal = Depends(principal_from_bearer)
    ) -> Resource:
        _authorize(principal, "certificates", admin_only=False, action="create")
        domains = payload.get("domain_names")
        if not isinstance(domains, list):
            raise HTTPException(status_code=422, detail="domain_names must be an array")
        try:
            return await app.core.CertificateStore.request(
                payload, ctx={"principal": _actor(principal)}
            )
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/nginx/certificates/{certificate_id}/renew")
    async def renew_certificate(
        certificate_id: int,
        request: Request,
        principal: Principal = Depends(principal_from_bearer),
    ) -> Resource:
        force = _query_bool(request, "force")
        _authorize(principal, "certificates", admin_only=False, action="update")
        return await app.core.CertificateStore.renew(
            {"id": certificate_id, "force": force}, ctx={"principal": _actor(principal)}
        )

    @app.get("/api/nginx/certificates/{certificate_id}/download")
    async def download_certificate(
        certificate_id: int,
        principal: Principal = Depends(principal_from_bearer),
    ) -> Response:
        _authorize(principal, "certificates", admin_only=False, action="read")
        try:
            content = await app.core.CertificateStore.download(
                {"id": certificate_id}, ctx={"principal": _actor(principal)}
            )
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return Response(
            content=content,
            media_type="application/zip",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="portwyrm-certificate-{certificate_id}.zip"'
                )
            },
        )

    @app.delete("/api/nginx/certificates/{certificate_id}")
    async def delete_certificate(
        certificate_id: int,
        principal: Principal = Depends(principal_from_bearer),
    ) -> bool:
        _authorize(principal, "certificates", admin_only=False, action="delete")
        await app.core.CertificateStore.remove(
            {"id": certificate_id}, ctx={"principal": _actor(principal)}
        )
        return True

    _register_resource_routes(app, service, principal_from_bearer)

    @app.get("/api/audit-log")
    async def audit_log(
        request: Request,
        principal: Principal = Depends(principal_from_bearer),
    ) -> list[Resource]:
        since = request.query_param("since")
        _require_admin(principal)
        entries = await _service_audit(service, since)
        return [dict(entry) for entry in entries]

    @app.get("/api/reports/hosts")
    async def host_report(
        principal: Principal = Depends(principal_from_bearer),
    ) -> Resource:
        report: Resource = {}
        for collection in (
            "proxy_hosts",
            "redirection_hosts",
            "dead_hosts",
            "streams",
            "certificates",
            "access_lists",
        ):
            if not principal.may(SECTION_BY_COLLECTION[collection]):
                continue
            items = await _service_list(service, collection, principal)
            visible = [item for item in items if _is_visible(item, principal)]
            report[collection] = {
                "total": len(visible),
                "enabled": sum(bool(item.get("enabled", 1)) for item in visible),
                "disabled": sum(not bool(item.get("enabled", 1)) for item in visible),
            }
        return report

    return app


create_app = create_compat_app


def _register_resource_routes(
    app: TigrblApp,
    service: CompatibilityService,
    principal_dependency: Any,
) -> None:
    for public_name, (collection, admin_only) in COLLECTIONS.items():
        prefix = "/api" if public_name in {"users", "settings"} else "/api/nginx"
        path = f"{prefix}/{public_name}"

        list_items = _list_handler(service, principal_dependency, collection, admin_only)
        get_item = _get_handler(service, principal_dependency, collection, admin_only)
        create_item = _create_handler(service, principal_dependency, collection, admin_only)
        update_item = _update_handler(service, principal_dependency, collection, admin_only)
        replace_item = _replace_handler(service, principal_dependency, collection, admin_only)
        delete_item = _delete_handler(service, principal_dependency, collection, admin_only)

        app.add_route(path, list_items, methods=["GET"], name=f"list_{collection}")
        app.add_route(
            path, create_item, methods=["POST"], name=f"create_{collection}", status_code=201
        )
        app.add_route(
            f"{path}/{{resource_id}}", get_item, methods=["GET"], name=f"get_{collection}"
        )
        app.add_route(
            f"{path}/{{resource_id}}", replace_item, methods=["PUT"], name=f"replace_{collection}"
        )
        app.add_route(
            f"{path}/{{resource_id}}", update_item, methods=["PATCH"], name=f"patch_{collection}"
        )
        app.add_route(
            f"{path}/{{resource_id}}", delete_item, methods=["DELETE"], name=f"delete_{collection}"
        )
        if collection in TOGGLE_COLLECTIONS:
            app.add_route(
                f"{path}/{{resource_id}}/enable",
                _toggle_handler(service, principal_dependency, collection, admin_only, True),
                methods=["POST"],
                name=f"enable_{collection}",
            )
            app.add_route(
                f"{path}/{{resource_id}}/disable",
                _toggle_handler(service, principal_dependency, collection, admin_only, False),
                methods=["POST"],
                name=f"disable_{collection}",
            )


def _list_handler(
    service: CompatibilityService, principal_dependency: Any, collection: str, admin_only: bool
) -> Any:
    async def handler(principal: Principal = Depends(principal_dependency)) -> list[Resource]:
        _authorize(principal, collection, admin_only=admin_only, action="read")
        items = await _service_list(service, collection, principal)
        return [_copy_visible(item, principal) for item in items if _is_visible(item, principal)]

    return handler


def _get_handler(
    service: CompatibilityService, principal_dependency: Any, collection: str, admin_only: bool
) -> Any:
    async def handler(
        resource_id: str, principal: Principal = Depends(principal_dependency)
    ) -> Resource:
        _authorize(principal, collection, admin_only=admin_only, action="read")
        normalized_id = _resource_id(resource_id, allow_string=collection == "settings")
        item = await _service_get(service, collection, normalized_id, principal)
        if item is None or not _is_visible(item, principal):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="resource not found")
        return _copy_visible(item, principal)

    return handler


def _create_handler(
    service: CompatibilityService, principal_dependency: Any, collection: str, admin_only: bool
) -> Any:
    async def handler(
        payload: dict[str, Any], principal: Principal = Depends(principal_dependency)
    ) -> Resource:
        _authorize(principal, collection, admin_only=admin_only, action="create")
        _validate_payload(payload)
        created = await _service_create(service, collection, dict(payload), principal)
        return _valid_resource(created, collection)

    return handler


def _update_handler(
    service: CompatibilityService, principal_dependency: Any, collection: str, admin_only: bool
) -> Any:
    async def handler(
        resource_id: str,
        payload: dict[str, Any],
        principal: Principal = Depends(principal_dependency),
    ) -> Resource:
        _authorize(principal, collection, admin_only=admin_only, action="update")
        _validate_payload(payload)
        normalized_id = _resource_id(resource_id, allow_string=collection == "settings")
        existing = await _service_get(service, collection, normalized_id, principal)
        if existing is None or not _is_visible(existing, principal):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="resource not found")
        merged = dict(existing)
        merged.update(payload)
        merged["id"] = existing["id"]
        updated = await _service_update(service, collection, normalized_id, merged, principal)
        if updated is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="resource not found")
        return _valid_resource(updated, collection)

    return handler


def _replace_handler(
    service: CompatibilityService, principal_dependency: Any, collection: str, admin_only: bool
) -> Any:
    async def handler(
        resource_id: str,
        payload: dict[str, Any],
        principal: Principal = Depends(principal_dependency),
    ) -> Resource:
        _authorize(principal, collection, admin_only=admin_only, action="update")
        _validate_payload(payload)
        normalized_id = _resource_id(resource_id, allow_string=collection == "settings")
        existing = await _service_get(service, collection, normalized_id, principal)
        if existing is None or not _is_visible(existing, principal):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="resource not found")
        replacement = dict(payload)
        replacement["id"] = existing["id"]
        replaced = await _service_replace(
            service, collection, normalized_id, replacement, principal
        )
        if replaced is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="resource not found")
        return _valid_resource(replaced, collection)

    return handler


def _delete_handler(
    service: CompatibilityService, principal_dependency: Any, collection: str, admin_only: bool
) -> Any:
    async def handler(
        resource_id: str, principal: Principal = Depends(principal_dependency)
    ) -> bool:
        _authorize(principal, collection, admin_only=admin_only, action="delete")
        normalized_id = _resource_id(resource_id, allow_string=collection == "settings")
        existing = await _service_get(service, collection, normalized_id, principal)
        if existing is None or not _is_visible(existing, principal):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="resource not found")
        if (
            collection == "users"
            and str(normalized_id) == str(principal.user_id)
            and str(existing.get("email", "")).casefold() == principal.identity.casefold()
        ):
            raise HTTPException(status_code=409, detail="users cannot delete their own account")
        deleted = await _service_delete(service, collection, normalized_id, principal)
        if not deleted:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="resource not found")
        return True

    return handler


def _toggle_handler(
    service: CompatibilityService,
    principal_dependency: Any,
    collection: str,
    admin_only: bool,
    enabled: bool,
) -> Any:
    async def handler(
        resource_id: str, principal: Principal = Depends(principal_dependency)
    ) -> Resource:
        _authorize(principal, collection, admin_only=admin_only, action="update")
        normalized_id = _resource_id(resource_id, allow_string=False)
        existing = await _service_get(service, collection, normalized_id, principal)
        if existing is None or not _is_visible(existing, principal):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="resource not found")
        updated = await _service_toggle(
            service, collection, normalized_id, enabled=enabled, principal=principal
        )
        if updated is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="resource not found")
        return _valid_resource(updated, collection)

    return handler


def _as_principal(value: Principal | Mapping[str, Any], *, fallback_identity: str) -> Principal:
    if isinstance(value, Principal):
        return value
    permissions = value.get("permissions", {})
    normalized_permissions = dict(permissions) if isinstance(permissions, Mapping) else {}
    return Principal(
        user_id=cast(int | str, value.get("id", value.get("user_id", fallback_identity))),
        identity=str(value.get("identity", value.get("email", fallback_identity))).lower(),
        is_admin=bool(value.get("is_admin", value.get("admin", False))),
        must_change_password=bool(value.get("must_change_password", False)),
        permissions=cast(dict[str, Any], normalized_permissions),
        visibility="all" if value.get("visibility") == "all" else "user",
        owner=str(value["owner"]) if value.get("owner") is not None else None,
    )


def _permissions_from_token_scopes(scopes: frozenset[str]) -> dict[str, dict[str, bool]]:
    return {
        section: grants
        for section, grants in permissions_from_scopes(scopes).items()
        if section in TOKEN_SCOPE_SECTIONS
        and all(action in TOKEN_SCOPE_ACTIONS for action in grants)
    }


def _validate_token_scopes(
    scopes: frozenset[str], principal: Principal
) -> tuple[dict[str, Any], bool]:
    if scopes == {"user"}:
        return dict(principal.permissions), principal.is_admin
    if "user" in scopes:
        scopes = scopes - {"user"}
    if not scopes:
        raise ValueError("select at least one access scope")
    permissions = _permissions_from_token_scopes(scopes)
    if sum(len(actions) for actions in permissions.values()) != len(scopes):
        raise ValueError("invalid token scopes")
    for section, grants in permissions.items():
        for action in grants:
            if not principal.may(section, action=cast(Any, action)):
                raise ValueError(f"scope exceeds account permission: {section}:{action}")
    return permissions, False


async def _owned_token(token_store: TokenService, token_id: str, principal: Principal) -> Any:
    record = await _identity_call(token_store.get_pat, token_id)
    if record is None or (
        not principal.is_admin and str(record.principal.user_id) != str(principal.user_id)
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="token not found")
    return record


def _authorize(
    principal: Principal,
    collection: str,
    *,
    admin_only: bool,
    action: Literal["create", "read", "update", "delete"],
) -> None:
    if admin_only:
        _require_admin(principal)
        return
    section = SECTION_BY_COLLECTION[collection]
    if not principal.may(section, action=action):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="permission denied")


def _require_admin(principal: Principal) -> None:
    if not principal.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="administrator required")


def _is_visible(item: Mapping[str, Any], principal: Principal) -> bool:
    if principal.is_admin or principal.visibility == "all":
        return True
    owner = item.get("owner_user_id", item.get("owner_id"))
    return owner is not None and str(owner) == str(principal.user_id)


def _copy_visible(item: Mapping[str, Any], _: Principal) -> Resource:
    return dict(item)


def _resource_id(value: str, *, allow_string: bool) -> int | str:
    if value.isdigit() and int(value) > 0:
        return int(value)
    if allow_string and value.strip():
        return value
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="invalid resource id"
    )


def _validate_payload(payload: Mapping[str, Any]) -> None:
    if "id" in payload:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="id is server assigned")
    if "private_key" in payload or "private-key" in payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="private keys must use the certificate upload operation",
        )
    meta = payload.get("meta")
    if meta is not None and not isinstance(meta, Mapping):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="meta must be an object"
        )


def _valid_resource(resource: Mapping[str, Any], collection: str) -> Resource:
    item = dict(resource)
    resource_id = item.get("id")
    if collection == "settings" and isinstance(resource_id, str) and resource_id:
        return item
    if isinstance(resource_id, bool) or not isinstance(resource_id, int) or resource_id < 1:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="service returned invalid id"
        )
    return item


def _set_browser_cookies(response: Response, token: str) -> None:
    secure = os.getenv("PORTWYRM_SECURE_COOKIES", "0").lower() in {"1", "true", "yes"}
    csrf = secrets.token_urlsafe(24)
    _append_cookie(
        response,
        "portwyrm_session",
        token,
        max_age=86_400,
        httponly=True,
        secure=secure,
    )
    _append_cookie(
        response,
        "portwyrm_csrf",
        csrf,
        max_age=86_400,
        httponly=False,
        secure=secure,
    )


def _expire_browser_cookies(response: Response) -> None:
    for name in ("portwyrm_session", "portwyrm_csrf"):
        _append_cookie(response, name, "", max_age=0, expires="Thu, 01 Jan 1970 00:00:00 GMT")


def _append_cookie(
    response: Response,
    name: str,
    value: str,
    *,
    max_age: int,
    httponly: bool = False,
    secure: bool = False,
    expires: str | None = None,
) -> None:
    cookie = Response()
    cookie.set_cookie(
        name,
        value,
        max_age=max_age,
        expires=expires,
        httponly=httponly,
        secure=secure,
        samesite="strict",
        path="/",
    )
    response.headers.append(("set-cookie", str(cookie.headers.get("set-cookie"))))


def _query_bool(request: Request, name: str, *, default: bool = False) -> bool:
    value = request.query_param(name)
    if value is None:
        return default
    return value.strip().casefold() in {"1", "true", "yes", "on"}


async def _maybe_await[T](value: T | Awaitable[T]) -> T:
    if inspect.isawaitable(value):
        return await value
    return cast(T, value)


async def _reload_after_import(service: CompatibilityService) -> None:
    reload_service = getattr(service, "reload", None)
    if reload_service is not None:
        await _maybe_await(reload_service())


def _control_plane_collection(collection: str) -> str:
    return collection.replace("_", "-")


def _actor(principal: Principal) -> SimpleNamespace:
    return SimpleNamespace(
        id=principal.user_id,
        email=principal.identity,
        is_admin=principal.is_admin,
        permissions=dict(principal.permissions),
        visibility=principal.visibility,
        scopes=frozenset(principal.scopes),
        owner=principal.owner,
    )


async def _service_list(
    service: CompatibilityService, collection: str, principal: Principal
) -> list[Resource]:
    if method := getattr(service, "list_resources", None):
        return await _maybe_await(method(collection))
    control_plane = cast(Any, service)
    return await _call_service(
        control_plane.list, _control_plane_collection(collection), actor=_actor(principal)
    )


async def _service_get(
    service: CompatibilityService,
    collection: str,
    resource_id: int | str,
    principal: Principal,
) -> Resource | None:
    if method := getattr(service, "get_resource", None):
        return await _maybe_await(method(collection, resource_id))
    control_plane = cast(Any, service)
    try:
        return await _call_service(
            control_plane.get,
            _control_plane_collection(collection),
            resource_id,
            actor=_actor(principal),
        )
    except HTTPException as exc:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            return None
        raise


async def _service_create(
    service: CompatibilityService,
    collection: str,
    payload: Resource,
    principal: Principal,
) -> Resource:
    if method := getattr(service, "create_resource", None):
        kwargs = {"actor": _actor(principal)} if isinstance(service, TableResources) else {}
        return await _maybe_await(method(collection, payload, **kwargs))
    control_plane = cast(Any, service)
    return await _call_service(
        control_plane.create,
        _control_plane_collection(collection),
        payload,
        actor=_actor(principal),
    )


async def _service_update(
    service: CompatibilityService,
    collection: str,
    resource_id: int | str,
    payload: Resource,
    principal: Principal,
) -> Resource | None:
    if method := getattr(service, "update_resource", None):
        kwargs = {"actor": _actor(principal)} if isinstance(service, TableResources) else {}
        return await _maybe_await(method(collection, resource_id, payload, **kwargs))
    control_plane = cast(Any, service)
    try:
        return await _call_service(
            control_plane.update,
            _control_plane_collection(collection),
            resource_id,
            payload,
            actor=_actor(principal),
            adopt=True,
        )
    except HTTPException as exc:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            return None
        raise


async def _service_delete(
    service: CompatibilityService,
    collection: str,
    resource_id: int | str,
    principal: Principal,
) -> bool:
    if method := getattr(service, "delete_resource", None):
        kwargs = {"actor": _actor(principal)} if isinstance(service, TableResources) else {}
        return await _maybe_await(method(collection, resource_id, **kwargs))
    control_plane = cast(Any, service)
    try:
        return await _call_service(
            control_plane.delete,
            _control_plane_collection(collection),
            resource_id,
            actor=_actor(principal),
        )
    except HTTPException as exc:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            return False
        raise


async def _service_replace(
    service: CompatibilityService,
    collection: str,
    resource_id: int | str,
    payload: Resource,
    principal: Principal,
) -> Resource | None:
    if method := getattr(service, "replace_resource", None):
        kwargs = {"actor": _actor(principal)} if isinstance(service, TableResources) else {}
        return await _maybe_await(method(collection, resource_id, payload, **kwargs))
    control_plane = cast(Any, service)
    try:
        return await _call_service(
            control_plane.replace,
            _control_plane_collection(collection),
            resource_id,
            payload,
            actor=_actor(principal),
        )
    except HTTPException as exc:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            return None
        raise


async def _service_toggle(
    service: CompatibilityService,
    collection: str,
    resource_id: int | str,
    *,
    enabled: bool,
    principal: Principal,
) -> Resource | None:
    if method := getattr(service, "set_enabled", None):
        kwargs = {"actor": _actor(principal)} if isinstance(service, TableResources) else {}
        return await _maybe_await(method(collection, resource_id, enabled=enabled, **kwargs))
    control_plane = cast(Any, service)
    operation = control_plane.enable if enabled else control_plane.disable
    try:
        return await _call_service(
            operation,
            _control_plane_collection(collection),
            resource_id,
            actor=_actor(principal),
        )
    except HTTPException as exc:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            return None
        raise


async def _service_audit(service: CompatibilityService, since: str | None) -> list[Resource]:
    if method := getattr(service, "list_audit", None):
        return await _maybe_await(method(since))
    return await _call_service(cast(Any, service).audit_since, since)


async def _apply_npm_report(
    service: CompatibilityService,
    report: Any,
    *,
    dry_run: bool,
    replace: bool,
) -> Resource:
    created = replaced = unchanged = conflicts = 0
    unsupported = {"_credentials", "audit_log"}
    for collection, records in report.records.items():
        if collection in unsupported:
            conflicts += len(records)
            continue
        for resource in records:
            existing = await _maybe_await(service.get_resource(collection, resource["id"]))
            if existing == resource:
                unchanged += 1
            elif existing is not None and not replace:
                conflicts += 1
            else:
                created += existing is None
                replaced += existing is not None
                if not dry_run:
                    if existing is None:
                        await _maybe_await(service.create_resource(collection, resource))
                    else:
                        await _maybe_await(
                            service.update_resource(collection, resource["id"], resource)
                        )
    return {
        "created": created,
        "replaced": replaced,
        "unchanged": unchanged,
        "quarantined": len(report.quarantine) + conflicts,
        "dry_run": dry_run,
    }


async def _call_service[T](method: Any, *args: Any, **kwargs: Any) -> T:
    try:
        return await _maybe_await(method(*args, **kwargs))
    except HTTPException:
        raise
    except Exception as exc:
        status_code = getattr(exc, "status_code", status.HTTP_500_INTERNAL_SERVER_ERROR)
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc
