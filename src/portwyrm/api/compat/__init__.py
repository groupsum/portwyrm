"""Nginx Proxy Manager facade consumed by npmctl 0.3.x."""

# ruff: noqa: B008 - Tigrbl dependencies are declared in function defaults by design.

from __future__ import annotations

import asyncio
import inspect
import os
import secrets
import tempfile
from collections.abc import Awaitable, Callable, Mapping
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal, Protocol, cast

from tigrbl import (
    CORSMiddleware,
    Depends,
    HTTPException,
    Request,
    Response,
    TigrblApp,
)
from tigrbl_typing.status.mappings import status

from portwyrm.api.compat.transport import CompatibilityTigrblApp
from portwyrm.api.middleware import ControlPlaneHTTPMiddleware
from portwyrm.application import MFAStore
from portwyrm.certificates import (
    DEFAULT_PROVIDER_CATALOG,
    CertificateManager,
    CertificateRequest,
    ChallengeType,
    CustomCertificateBundle,
)
from portwyrm.migration import import_npm, preflight_npm
from portwyrm.persistence import Repository, export_bundle, import_bundle, preview_import
from portwyrm.security import Principal, TokenStore

Resource = dict[str, Any]


async def _identity_call(function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    value = function(*args, **kwargs)
    return await value if inspect.isawaitable(value) else value


class CompatibilityService(Protocol):
    """Application-service port required by the compatibility facade."""

    def list_resources(self, collection: str) -> list[Resource]: ...

    def get_resource(self, collection: str, resource_id: int | str) -> Resource | None: ...

    def create_resource(self, collection: str, payload: Resource) -> Resource: ...

    def update_resource(
        self, collection: str, resource_id: int | str, payload: Resource
    ) -> Resource | None: ...

    def delete_resource(self, collection: str, resource_id: int | str) -> bool: ...

    def list_audit(self, since: str | None = None) -> list[Resource]: ...


COLLECTIONS: dict[str, tuple[str, bool]] = {
    "proxy-hosts": ("proxy_hosts", False),
    "certificates": ("certificates", False),
    "access-lists": ("access_lists", False),
    "redirection-hosts": ("redirection_hosts", False),
    "dead-hosts": ("dead_hosts", False),
    "streams": ("streams", False),
    "users": ("users", True),
    "settings": ("settings", True),
}

SECTION_BY_COLLECTION = {
    "proxy_hosts": "proxy_hosts",
    "certificates": "certificates",
    "access_lists": "access_lists",
    "redirection_hosts": "redirection_hosts",
    "dead_hosts": "dead_hosts",
    "streams": "streams",
}

TOKEN_SCOPE_ACTIONS = frozenset({"create", "read", "update", "delete"})
TOKEN_SCOPE_SECTIONS = frozenset(SECTION_BY_COLLECTION.values())

TOGGLE_COLLECTIONS = {"proxy_hosts", "redirection_hosts", "dead_hosts", "streams"}


def create_compat_app(
    service: CompatibilityService,
    *,
    tokens: TokenStore | None = None,
    version: str = "0.1.0a0",
    authenticator: Any | None = None,
    certificates: CertificateManager | None = None,
    lifespan: Any | None = None,
    repository: Repository | None = None,
    mfa: MFAStore | None = None,
    system_status: Callable[[], Mapping[str, Any]] | None = None,
    engine: Any | None = None,
) -> TigrblApp:
    token_store = tokens or TokenStore()
    app = CompatibilityTigrblApp(
        title="Portwyrm NPM compatibility API",
        version="2.10.4",
        lifespan=lifespan,
        mount_system=False,
        engine=engine,
    )
    app.state.control_plane = service
    app.state.token_store = token_store
    app.state.certificate_manager = certificates
    app.state.repository = repository
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

    async def principal_from_bearer(request: Request) -> Principal:
        authorization = request.headers.get("authorization")
        session_cookie = request.cookies.get("portwyrm_session")
        if authorization and authorization.startswith("Bearer "):
            token = authorization.removeprefix("Bearer ").strip()
        elif session_cookie:
            token = session_cookie
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="bearer token required"
            )
        try:
            principal = await _identity_call(token_store.verify, token)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
        if "user" not in principal.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="MFA challenge pending"
            )
        # Sessions and PATs carry an identity snapshot for durable verification. Rehydrate
        # mutable authorization fields so an administrator's permission changes take effect
        # on the user's very next request instead of waiting for a new login.
        current_user = await _service_get(service, "users", principal.user_id, principal)
        current_identity = str((current_user or {}).get("email", principal.identity)).casefold()
        if current_user is not None and current_identity == principal.identity.casefold():
            if current_user.get("is_deleted") or current_user.get("is_disabled"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="user is disabled"
                )
            permissions = dict(current_user.get("permissions") or {})
            is_admin = bool(current_user.get("is_admin"))
            # ``user`` is the backward-compatible full-account PAT scope. Tokens
            # carrying resource scopes are deliberately narrowed on every request,
            # even when their owner is an administrator.
            resource_scopes = principal.scopes - {"user"}
            if resource_scopes:
                permissions = _permissions_from_token_scopes(resource_scopes)
                is_admin = False
            principal = Principal(
                user_id=principal.user_id,
                identity=str(current_user.get("email") or principal.identity),
                is_admin=is_admin,
                permissions=permissions,
                visibility="all" if current_user.get("visibility") == "all" else "user",
                scopes=principal.scopes,
                owner=principal.owner,
            )
        return principal

    async def principal_from_mfa_bearer(request: Request) -> Principal:
        authorization = request.headers.get("authorization")
        session_cookie = request.cookies.get("portwyrm_session")
        if authorization and authorization.startswith("Bearer "):
            token = authorization.removeprefix("Bearer ").strip()
        elif session_cookie:
            token = session_cookie
        else:
            raise HTTPException(status_code=401, detail="MFA challenge token required")
        try:
            principal = await _identity_call(token_store.verify, token)
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        if principal.scopes != frozenset({"mfa"}):
            raise HTTPException(status_code=403, detail="MFA challenge token required")
        return principal

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
                status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials"
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
        await _record_event(service, "authenticated", "users", principal.user_id, principal)
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
        return {"result": {"token": browser_token, "expires": expires, "scope": "user"}}

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
        await _record_event(service, "session.revoked", "users", _.user_id, _)

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
        await _record_event(
            service, "mfa.enrollment.started", "users", principal.user_id, principal
        )
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
        await _record_event(service, "mfa.enabled", "users", principal.user_id, principal)

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
        await _record_event(service, "mfa.disabled", "users", principal.user_id, principal)

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
        await _record_event(
            service, "mfa.recovery-codes.regenerated", "users", principal.user_id, principal
        )
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
            await _record_event(service, "password.reset", "users", user_id, principal)
            return
        if str(principal.user_id) != str(user_id) or not isinstance(current, str):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="permission denied")
        changer = getattr(service, "change_password", None)
        if changer is None:
            raise HTTPException(status_code=501, detail="password management unavailable")
        await _maybe_await(changer(user_id, current, password))
        await _record_event(service, "password.changed", "users", user_id, principal)

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
        await _record_event(
            service,
            "user.impersonated",
            "users",
            user_id,
            principal,
            {"impersonated_by": principal.user_id},
        )
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
        await _record_event(
            service,
            "access-token.created",
            "access-tokens",
            record.id,
            principal,
            {"name": record.name, "scopes": sorted(record.principal.scopes)},
        )
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
        await _record_event(
            service,
            "access-token.rotated",
            "access-tokens",
            replacement.id,
            principal,
            {"replaces": token_id, "name": replacement.name},
        )
        return {**replacement.public(), "token": plaintext}

    @app.delete("/api/v2/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def revoke_personal_token(
        token_id: str, principal: Principal = Depends(principal_from_bearer)
    ) -> None:
        record = await _owned_token(token_store, token_id, principal)
        if record.revoked_at is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="token is revoked")
        await _identity_call(token_store.revoke_pat, token_id)
        await _record_event(service, "access-token.revoked", "access-tokens", token_id, principal)

    @app.get("/api/v2/export")
    async def export_state(principal: Principal = Depends(principal_from_bearer)) -> Resource:
        _require_admin(principal)
        if repository is None:
            raise HTTPException(status_code=501, detail="state export unavailable")
        return export_bundle(repository)

    @app.post("/api/v2/import/preview")
    async def preview_state_import(
        payload: dict[str, Any],
        request: Request,
        principal: Principal = Depends(principal_from_bearer),
    ) -> Resource:
        replace = _query_bool(request, "replace")
        _require_admin(principal)
        if repository is None:
            raise HTTPException(status_code=501, detail="state import unavailable")
        return preview_import(repository, payload, replace=replace)

    @app.post("/api/v2/import")
    async def apply_state_import(
        payload: dict[str, Any],
        request: Request,
        principal: Principal = Depends(principal_from_bearer),
    ) -> Resource:
        replace = _query_bool(request, "replace")
        _require_admin(principal)
        if repository is None:
            raise HTTPException(status_code=501, detail="state import unavailable")
        result = import_bundle(repository, payload, replace=replace)
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
        if repository is None:
            raise HTTPException(status_code=501, detail="NPM import unavailable")
        source = payload.get("source")
        if not isinstance(source, Mapping):
            raise HTTPException(status_code=422, detail="source must be an NPM table mapping")
        report = preflight_npm(source, source_kind="api")
        result = asdict(import_npm(repository, report, dry_run=dry_run, replace=replace))
        if not dry_run:
            await _reload_after_import(service)
        return result

    @app.get("/api/nginx/certificates/dns-providers")
    async def dns_providers(
        principal: Principal = Depends(principal_from_bearer),
    ) -> list[Resource]:
        _authorize(principal, "certificates", admin_only=False, action="read")
        return [
            {
                "id": provider.id,
                "name": provider.name,
                "package_name": provider.package_name,
                "credential_fields": list(provider.credential_fields),
            }
            for provider in DEFAULT_PROVIDER_CATALOG
        ]

    @app.post("/api/nginx/certificates/validate")
    async def validate_certificate(
        payload: dict[str, Any], principal: Principal = Depends(principal_from_bearer)
    ) -> Resource:
        _authorize(principal, "certificates", admin_only=False, action="create")
        manager = _require_certificate_manager(certificates)
        bundle = _certificate_bundle(payload)
        info = manager.validator.validate(bundle)
        return {
            "subject": info.subject,
            "issuer": info.issuer,
            "serial": info.serial,
            "domain_names": list(info.domain_names),
            "not_before": info.not_before.isoformat(),
            "not_after": info.not_after.isoformat(),
        }

    @app.post("/api/nginx/certificates/upload", status_code=status.HTTP_201_CREATED)
    async def upload_certificate(
        payload: dict[str, Any], principal: Principal = Depends(principal_from_bearer)
    ) -> Resource:
        _authorize(principal, "certificates", admin_only=False, action="create")
        manager = _require_certificate_manager(certificates)
        return manager.upload(
            _certificate_bundle(payload), nice_name=str(payload.get("nice_name", ""))
        )

    @app.post("/api/nginx/certificates/{certificate_id}/upload")
    async def replace_certificate(
        certificate_id: int,
        payload: dict[str, Any],
        principal: Principal = Depends(principal_from_bearer),
    ) -> Resource:
        _authorize(principal, "certificates", admin_only=False, action="update")
        manager = _require_certificate_manager(certificates)
        return manager.upload(
            _certificate_bundle(payload),
            nice_name=str(payload.get("nice_name", "")),
            certificate_id=certificate_id,
        )

    @app.post("/api/nginx/certificates/request", status_code=status.HTTP_201_CREATED)
    async def request_certificate(
        payload: dict[str, Any], principal: Principal = Depends(principal_from_bearer)
    ) -> Resource:
        _authorize(principal, "certificates", admin_only=False, action="create")
        manager = _require_certificate_manager(certificates)
        domains = payload.get("domain_names")
        if not isinstance(domains, list):
            raise HTTPException(status_code=422, detail="domain_names must be an array")
        try:
            request = CertificateRequest(
                nice_name=str(payload.get("nice_name", "Certificate")),
                domain_names=tuple(str(item) for item in domains),
                email=str(payload.get("email", "")),
                challenge_type=ChallengeType(str(payload.get("challenge_type", "http-01"))),
                key_type=str(payload.get("key_type", "rsa")),
                provider=(str(payload["dns_provider"]) if payload.get("dns_provider") else None),
            )
            credentials = payload.get("dns_credentials")
            if request.challenge_type == ChallengeType.DNS_01:
                if not request.provider or not isinstance(credentials, Mapping):
                    raise ValueError("DNS-01 requires dns_provider and dns_credentials")
                normalized_credentials = {
                    str(key): str(value) for key, value in credentials.items()
                }
                DEFAULT_PROVIDER_CATALOG.validate_credentials(
                    request.provider, normalized_credentials
                )
                descriptor, name = tempfile.mkstemp(prefix="portwyrm-dns-", text=True)
                try:
                    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                        for key, value in normalized_credentials.items():
                            handle.write(f"{key} = {value}\n")
                    os.chmod(name, 0o600)
                    return manager.request(request, credentials_file=Path(name))
                finally:
                    Path(name).unlink(missing_ok=True)
            return manager.request(request)
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
        return _require_certificate_manager(certificates).renew(certificate_id, force=force)

    @app.get("/api/nginx/certificates/{certificate_id}/download")
    async def download_certificate(
        certificate_id: int,
        principal: Principal = Depends(principal_from_bearer),
    ) -> Response:
        _authorize(principal, "certificates", admin_only=False, action="read")
        try:
            content = _require_certificate_manager(certificates).download(certificate_id)
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
        if certificates is None:
            deleted = await _service_delete(service, "certificates", certificate_id, principal)
            if not deleted:
                raise HTTPException(status_code=404, detail="resource not found")
            return True
        certificates.delete(certificate_id)
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
        delete_item = _delete_handler(service, principal_dependency, collection, admin_only)

        app.add_route(path, list_items, methods=["GET"], name=f"list_{collection}")
        app.add_route(
            path, create_item, methods=["POST"], name=f"create_{collection}", status_code=201
        )
        app.add_route(
            f"{path}/{{resource_id}}", get_item, methods=["GET"], name=f"get_{collection}"
        )
        app.add_route(
            f"{path}/{{resource_id}}", update_item, methods=["PUT"], name=f"update_{collection}"
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
        merged = dict(existing)
        merged["enabled"] = int(enabled)
        updated = await _service_update(service, collection, normalized_id, merged, principal)
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
        permissions=cast(dict[str, Any], normalized_permissions),
        visibility="all" if value.get("visibility") == "all" else "user",
        owner=str(value["owner"]) if value.get("owner") is not None else None,
    )


def _permissions_from_token_scopes(scopes: frozenset[str]) -> dict[str, dict[str, bool]]:
    permissions: dict[str, dict[str, bool]] = {}
    for scope in scopes:
        section, separator, action = scope.partition(":")
        if (
            not separator
            or section not in TOKEN_SCOPE_SECTIONS
            or action not in TOKEN_SCOPE_ACTIONS
        ):
            continue
        permissions.setdefault(section, {})[action] = True
    return permissions


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


async def _owned_token(token_store: TokenStore, token_id: str, principal: Principal) -> Any:
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


def _require_certificate_manager(value: CertificateManager | None) -> CertificateManager:
    if value is None:
        raise HTTPException(status_code=501, detail="certificate management unavailable")
    return value


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


def _certificate_bundle(payload: Mapping[str, Any]) -> CustomCertificateBundle:
    certificate = payload.get("certificate")
    private_key = payload.get("private_key")
    intermediate = payload.get("intermediate_certificate", "")
    if not isinstance(certificate, str) or not isinstance(private_key, str):
        raise HTTPException(status_code=422, detail="certificate and private_key are required")
    if not isinstance(intermediate, str):
        raise HTTPException(status_code=422, detail="intermediate_certificate must be text")
    return CustomCertificateBundle(certificate, private_key, intermediate)


async def _maybe_await[T](value: T | Awaitable[T]) -> T:
    if inspect.isawaitable(value):
        return await value
    return cast(T, value)


async def _reload_after_import(service: CompatibilityService) -> None:
    reload_service = getattr(service, "reload", None)
    if reload_service is not None:
        await _maybe_await(reload_service())


async def _record_event(
    service: CompatibilityService,
    action: str,
    object_type: str,
    object_id: int | str,
    principal: Principal,
    details: Resource | None = None,
) -> None:
    recorder = getattr(service, "record_event", None)
    if recorder is not None:
        await _maybe_await(
            recorder(
                action,
                object_type,
                object_id,
                details=details,
                actor=_actor(principal),
            )
        )


def _control_plane_collection(collection: str) -> str:
    return collection.replace("_", "-")


def _actor(principal: Principal) -> SimpleNamespace:
    return SimpleNamespace(
        id=principal.user_id,
        email=principal.identity,
        is_admin=principal.is_admin,
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
        return await _maybe_await(method(collection, payload))
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
        return await _maybe_await(method(collection, resource_id, payload))
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
        return await _maybe_await(method(collection, resource_id))
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


async def _service_audit(service: CompatibilityService, since: str | None) -> list[Resource]:
    if method := getattr(service, "list_audit", None):
        return await _maybe_await(method(since))
    return await _call_service(cast(Any, service).audit_since, since)


async def _call_service[T](method: Any, *args: Any, **kwargs: Any) -> T:
    try:
        return await _maybe_await(method(*args, **kwargs))
    except HTTPException:
        raise
    except Exception as exc:
        status_code = getattr(exc, "status_code", status.HTTP_500_INTERNAL_SERVER_ERROR)
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc
