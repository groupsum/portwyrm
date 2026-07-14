"""Nginx Proxy Manager facade consumed by npmctl 0.3.x."""

# ruff: noqa: B008 - FastAPI dependencies are declared in function defaults by design.

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Mapping
from types import SimpleNamespace
from typing import Any, Protocol, cast

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status

from portwyrm.security import Principal, TokenStore

Resource = dict[str, Any]


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

TOGGLE_COLLECTIONS = {"proxy_hosts", "redirection_hosts", "dead_hosts", "streams"}


def create_compat_app(
    service: CompatibilityService,
    *,
    tokens: TokenStore | None = None,
    version: str = "0.1.0a0",
    authenticator: Any | None = None,
) -> FastAPI:
    token_store = tokens or TokenStore()
    app = FastAPI(title="Portwyrm NPM compatibility API", version="2.10.4")
    app.state.control_plane = service
    app.state.token_store = token_store

    async def principal_from_bearer(
        authorization: str | None = Header(default=None),
    ) -> Principal:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="bearer token required"
            )
        token = authorization.removeprefix("Bearer ").strip()
        try:
            return token_store.verify(token)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

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
        document = app.openapi()
        document["info"]["version"] = "2.10.4"
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
        authenticated = await _maybe_await(authentication(identity.strip().lower(), secret))
        if authenticated is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials"
            )
        principal = _as_principal(authenticated, fallback_identity=identity)
        token, expires = token_store.issue_session(principal)
        return {"result": {"token": token, "expires": expires}}

    @app.get("/api/tokens")
    async def refresh(
        authorization: str | None = Header(default=None),
        _: Principal = Depends(principal_from_bearer),
    ) -> dict[str, Any]:
        assert authorization is not None
        token, expires = token_store.refresh_session(authorization.removeprefix("Bearer ").strip())
        return {"token": token, "expires": expires}

    @app.delete("/api/tokens", status_code=status.HTTP_204_NO_CONTENT)
    async def logout(
        authorization: str | None = Header(default=None),
        _: Principal = Depends(principal_from_bearer),
    ) -> None:
        assert authorization is not None
        token_store.revoke_session(authorization.removeprefix("Bearer ").strip())

    @app.get("/api/v2/me")
    async def profile(principal: Principal = Depends(principal_from_bearer)) -> Resource:
        user = await _service_get(service, "users", principal.user_id, principal)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")
        return _copy_visible(user, principal)

    @app.put("/api/v2/me")
    async def update_profile(
        payload: dict[str, Any], principal: Principal = Depends(principal_from_bearer)
    ) -> Resource:
        allowed = {key: payload[key] for key in ("name", "nickname", "email") if key in payload}
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
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
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="password is required"
            )
        if principal.is_admin:
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

    @app.get("/api/v2/tokens")
    async def list_personal_tokens(
        principal: Principal = Depends(principal_from_bearer),
    ) -> list[Resource]:
        return [record.public() for record in token_store.list_pats(principal)]

    @app.post("/api/v2/tokens", status_code=status.HTTP_201_CREATED)
    async def create_personal_token(
        payload: dict[str, Any], principal: Principal = Depends(principal_from_bearer)
    ) -> Resource:
        name = payload.get("name")
        expires_at = payload.get("expires_at")
        scopes = payload.get("scopes", sorted(principal.scopes))
        if not isinstance(name, str) or not isinstance(scopes, list):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="name and scopes are required",
            )
        requested = frozenset(str(scope) for scope in scopes)
        if not requested or not requested.issubset(principal.scopes):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="invalid token scopes"
            )
        pat_principal = Principal(
            user_id=principal.user_id,
            identity=principal.identity,
            is_admin=principal.is_admin,
            permissions=principal.permissions,
            visibility=principal.visibility,
            scopes=requested,
            owner=principal.owner,
        )
        try:
            record, plaintext = token_store.create_pat(
                name=name,
                principal=pat_principal,
                expires_at=int(expires_at) if expires_at is not None else None,
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
            ) from exc
        return {**record.public(), "token": plaintext}

    @app.delete("/api/v2/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def revoke_personal_token(
        token_id: str, principal: Principal = Depends(principal_from_bearer)
    ) -> None:
        record = token_store.get_pat(token_id)
        if record is None or (
            not principal.is_admin and str(record.principal.user_id) != str(principal.user_id)
        ):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="token not found")
        token_store.revoke_pat(token_id)

    _register_resource_routes(app, service, principal_from_bearer)

    @app.get("/api/audit-log")
    async def audit_log(
        since: str | None = Query(default=None),
        principal: Principal = Depends(principal_from_bearer),
    ) -> list[Resource]:
        _require_admin(principal)
        entries = await _service_audit(service, since)
        return [dict(entry) for entry in entries]

    return app


create_app = create_compat_app


def _register_resource_routes(
    app: FastAPI,
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

        app.add_api_route(path, list_items, methods=["GET"], name=f"list_{collection}")
        app.add_api_route(
            path, create_item, methods=["POST"], name=f"create_{collection}", status_code=201
        )
        app.add_api_route(
            f"{path}/{{resource_id}}", get_item, methods=["GET"], name=f"get_{collection}"
        )
        app.add_api_route(
            f"{path}/{{resource_id}}", update_item, methods=["PUT"], name=f"update_{collection}"
        )
        app.add_api_route(
            f"{path}/{{resource_id}}", update_item, methods=["PATCH"], name=f"patch_{collection}"
        )
        app.add_api_route(
            f"{path}/{{resource_id}}", delete_item, methods=["DELETE"], name=f"delete_{collection}"
        )
        if collection in TOGGLE_COLLECTIONS:
            app.add_api_route(
                f"{path}/{{resource_id}}/enable",
                _toggle_handler(service, principal_dependency, collection, admin_only, True),
                methods=["POST"],
                name=f"enable_{collection}",
            )
            app.add_api_route(
                f"{path}/{{resource_id}}/disable",
                _toggle_handler(service, principal_dependency, collection, admin_only, False),
                methods=["POST"],
                name=f"disable_{collection}",
            )


def _list_handler(
    service: CompatibilityService, principal_dependency: Any, collection: str, admin_only: bool
) -> Any:
    async def handler(principal: Principal = Depends(principal_dependency)) -> list[Resource]:
        _authorize(principal, collection, admin_only=admin_only, write=False)
        items = await _service_list(service, collection, principal)
        return [_copy_visible(item, principal) for item in items if _is_visible(item, principal)]

    return handler


def _get_handler(
    service: CompatibilityService, principal_dependency: Any, collection: str, admin_only: bool
) -> Any:
    async def handler(
        resource_id: str, principal: Principal = Depends(principal_dependency)
    ) -> Resource:
        _authorize(principal, collection, admin_only=admin_only, write=False)
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
        _authorize(principal, collection, admin_only=admin_only, write=True)
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
        _authorize(principal, collection, admin_only=admin_only, write=True)
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
        _authorize(principal, collection, admin_only=admin_only, write=True)
        normalized_id = _resource_id(resource_id, allow_string=collection == "settings")
        existing = await _service_get(service, collection, normalized_id, principal)
        if existing is None or not _is_visible(existing, principal):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="resource not found")
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
        _authorize(principal, collection, admin_only=admin_only, write=True)
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


def _authorize(principal: Principal, collection: str, *, admin_only: bool, write: bool) -> None:
    if admin_only:
        _require_admin(principal)
        return
    section = SECTION_BY_COLLECTION[collection]
    if not principal.may(section, write=write):
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
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="invalid resource id"
    )


def _validate_payload(payload: Mapping[str, Any]) -> None:
    if "id" in payload:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="id is server assigned")
    meta = payload.get("meta")
    if meta is not None and not isinstance(meta, Mapping):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="meta must be an object"
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


async def _maybe_await[T](value: T | Awaitable[T]) -> T:
    if inspect.isawaitable(value):
        return await value
    return cast(T, value)


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
