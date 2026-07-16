"""Durable identities and their authorization as Tigrbl operations."""

from __future__ import annotations

import asyncio
import inspect
from typing import Any, Literal

from tigrbl import op_ctx, schema_ctx
from tigrbl.types import (
    BaseModel,
    Boolean,
    Field,
    String,
    UniqueConstraint,
    relationship,
)

from portwyrm.identity.passwords import hash_secret
from portwyrm.identity.permissions import PermissionAction, PermissionGrant, permission_allows
from portwyrm.kernel_support import delete, select

from .base import ManagedPortwyrmTable, acol
from .credentials import CredentialStore
from .rbac import (
    PermissionStore,
    PrincipalPermissionStore,
    PrincipalRoleStore,
    RolePermissionStore,
    RoleStore,
)


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


async def _scalar(db: Any, statement: Any) -> Any:
    result = await _await(db.execute(statement))
    return result.scalar_one_or_none()


def _role_names(value: Any, is_admin: bool) -> list[str]:
    names = {str(item).strip().casefold() for item in (value or []) if str(item).strip()}
    if is_admin:
        names.add("admin")
    return sorted(names)


def _permission_effects(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    effects: dict[str, str] = {}
    for section, grant in value.items():
        section_key = str(section).strip()
        if not section_key:
            continue
        if isinstance(grant, dict):
            for action, allowed in grant.items():
                effects[f"{section_key}.{str(action).strip()}"] = (
                    "allow" if bool(allowed) else "deny"
                )
        else:
            level = str(grant).strip().casefold()
            if level in {"manage", "view"}:
                effects[f"{section_key}.{level}"] = "allow"
            elif level == "hidden":
                effects[f"{section_key}.view"] = "deny"
    return effects


def _permission_projection(grants: dict[str, str]) -> dict[str, dict[str, bool]]:
    projected: dict[str, dict[str, bool]] = {}
    for key, effect in grants.items():
        section, separator, action = key.partition(".")
        if separator and action:
            projected.setdefault(section, {})[action] = effect == "allow"
    return projected


class PrincipalStore(ManagedPortwyrmTable):
    __tablename__ = "principals"
    __table_args__ = (UniqueConstraint("email", name="uq_principals_email"),)

    email = acol(String(320), nullable=False, index=True)
    display_name = acol(String(255), nullable=False, default="")
    nickname = acol(String(255), nullable=False, default="")
    is_admin = acol(Boolean, nullable=False, default=False)
    must_change_password = acol(Boolean, nullable=False, default=False)
    is_disabled = acol(Boolean, nullable=False, default=False)
    is_deleted = acol(Boolean, nullable=False, default=False)
    visibility = acol(String(32), nullable=False, default="user")

    @schema_ctx(alias="register", kind="in")
    class RegisterRequest(BaseModel):
        email: str
        password: str
        display_name: str = ""
        nickname: str = ""
        is_admin: bool = False
        must_change_password: bool = False
        roles: list[str] = Field(default_factory=list)
        permissions: dict[str, Any] = Field(default_factory=dict)
        metadata_json: dict[str, Any] = Field(default_factory=dict)

    @schema_ctx(alias="resolve", kind="in")
    class ResolveRequest(BaseModel):
        principal_id: int
        scopes: list[str] = Field(default_factory=lambda: ["user"])
        owner: str | None = None

    @schema_ctx(alias="resolve", kind="out")
    class SecurityPrincipal(BaseModel):
        """Authenticated request principal exported by the owning table."""

        user_id: int | str
        identity: str
        display_name: str = ""
        is_admin: bool = False
        must_change_password: bool = False
        permissions: dict[str, PermissionGrant] = Field(default_factory=dict)
        visibility: Literal["all", "user"] = "user"
        scopes: frozenset[str] = Field(default_factory=lambda: frozenset({"user"}))
        owner: str | None = None

        def may(
            self,
            section: str,
            *,
            write: bool = False,
            action: PermissionAction | None = None,
        ) -> bool:
            if self.is_admin:
                return True
            requested = action or ("update" if write else "read")
            normalized = section.replace("-", "_")
            return permission_allows(self.permissions.get(normalized, "hidden"), requested)

    @schema_ctx(alias="set_authorization", kind="in")
    class SetAuthorizationRequest(BaseModel):
        principal_id: int
        roles: list[str] = Field(default_factory=list)
        permissions: dict[str, Any] = Field(default_factory=dict)

    @schema_ctx(alias="update_identity", kind="in")
    class UpdateIdentityRequest(BaseModel):
        principal_id: int
        email: str
        display_name: str = ""
        nickname: str = ""
        is_admin: bool = False
        is_disabled: bool = False
        is_deleted: bool = False
        visibility: str = "user"
        roles: list[str] = Field(default_factory=list)
        permissions: dict[str, Any] = Field(default_factory=dict)
        metadata_json: dict[str, Any] = Field(default_factory=dict)

    @op_ctx(alias="register", target="custom", arity="collection")
    async def register(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        email = str(payload.get("email") or "").strip().casefold()
        password = str(payload.get("password") or "")
        if not email or "@" not in email:
            raise ValueError("a valid email is required")
        if len(password) < 8:
            raise ValueError("password must contain at least 8 characters")
        existing = await _await(ctx["db"].execute(select(cls).where(cls.email == email)))
        if existing.scalar_one_or_none() is not None:
            raise ValueError("email is already registered")
        principal = cls(
            email=email,
            display_name=str(payload.get("display_name") or ""),
            nickname=str(payload.get("nickname") or ""),
            is_admin=bool(payload.get("is_admin")),
            must_change_password=bool(payload.get("must_change_password")),
            is_disabled=False,
            is_deleted=False,
            visibility="all" if payload.get("is_admin") else "user",
            metadata_json=dict(payload.get("metadata_json") or {}),
        )
        ctx["db"].add(principal)
        digest = await asyncio.to_thread(hash_secret, password)
        principal.credentials.append(CredentialStore(password_hash=digest))
        await cls._replace_authorization(ctx["db"], principal, payload)
        return principal

    @op_ctx(alias="set_authorization", target="custom", arity="collection")
    async def set_authorization(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        principal_id = int(payload["principal_id"])
        principal = await _await(ctx["db"].get(cls, principal_id))
        if principal is None:
            raise ValueError(f"principal does not exist: {principal_id}")

        await cls._replace_authorization(ctx["db"], principal, payload)
        return await cls._authorization(ctx["db"], principal)

    @op_ctx(alias="update_identity", target="custom", arity="collection")
    async def update_identity(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        principal_id = int(payload["principal_id"])
        principal = await _await(ctx["db"].get(cls, principal_id))
        if principal is None:
            raise ValueError(f"principal does not exist: {principal_id}")
        principal.email = str(payload["email"]).strip().casefold()
        principal.display_name = str(payload.get("display_name") or "")
        principal.nickname = str(payload.get("nickname") or "")
        principal.is_admin = bool(payload.get("is_admin"))
        principal.is_disabled = bool(payload.get("is_disabled"))
        principal.is_deleted = bool(payload.get("is_deleted"))
        principal.visibility = str(payload.get("visibility") or "user")
        principal.metadata_json = dict(payload.get("metadata_json") or {})
        await cls._replace_authorization(ctx["db"], principal, payload)
        result = {
            "id": principal.id,
            "email": principal.email,
            "display_name": principal.display_name,
            "nickname": principal.nickname,
            "is_admin": bool(principal.is_admin),
            "must_change_password": bool(principal.must_change_password),
            "is_disabled": bool(principal.is_disabled),
            "is_deleted": bool(principal.is_deleted),
            "visibility": principal.visibility,
            "metadata_json": principal.metadata_json,
        }
        return result

    @classmethod
    async def _replace_authorization(cls, db: Any, principal: Any, payload: dict[str, Any]) -> None:
        if principal.id is not None:
            principal_id = int(principal.id)
            await _await(
                db.execute(
                    delete(PrincipalRoleStore).where(
                        PrincipalRoleStore.principal_id == principal_id
                    )
                )
            )
            await _await(
                db.execute(
                    delete(PrincipalPermissionStore).where(
                        PrincipalPermissionStore.principal_id == principal_id
                    )
                )
            )
        for name in _role_names(payload.get("roles"), bool(principal.is_admin)):
            role = await _scalar(db, select(RoleStore).where(RoleStore.name == name))
            if role is None:
                role = RoleStore(
                    name=name,
                    description="Portwyrm administrator" if name == "admin" else "",
                    is_system=name == "admin",
                )
                db.add(role)
            db.add(PrincipalRoleStore(principal=principal, role=role))

        normalized = _permission_effects(payload.get("permissions"))
        for key, effect in normalized.items():
            section, _, action = key.partition(".")
            permission = await _scalar(
                db, select(PermissionStore).where(PermissionStore.key == key)
            )
            if permission is None:
                permission = PermissionStore(
                    key=key,
                    section=section,
                    action=action or "manage",
                    description="",
                )
                db.add(permission)
            db.add(
                PrincipalPermissionStore(
                    principal=principal,
                    permission=permission,
                    effect=effect,
                )
            )

    @op_ctx(alias="authorization", target="custom", arity="collection")
    async def authorization(cls, ctx: Any) -> dict[str, Any]:
        principal_id = int((ctx.get("payload") or {})["principal_id"])
        principal = await _await(ctx["db"].get(cls, principal_id))
        if principal is None:
            raise ValueError(f"principal does not exist: {principal_id}")
        return await cls._authorization(ctx["db"], principal)

    @op_ctx(alias="resolve", target="custom", arity="collection")
    async def resolve(cls, ctx: Any) -> dict[str, Any]:
        """Resolve the current durable identity and authorization for a token subject."""
        payload = dict(ctx.get("payload") or {})
        principal = await _await(ctx["db"].get(cls, int(payload["principal_id"])))
        if principal is None or principal.is_disabled or principal.is_deleted:
            raise ValueError("principal is unavailable")
        authorization = await cls._authorization(ctx["db"], principal)
        return {
            "user_id": principal.id,
            "identity": principal.email,
            "display_name": principal.display_name,
            "is_admin": bool(principal.is_admin),
            "must_change_password": bool(principal.must_change_password),
            "permissions": authorization["permissions"],
            "visibility": "all" if principal.visibility == "all" else "user",
            "scopes": list(payload.get("scopes") or ["user"]),
            "owner": payload.get("owner"),
        }

    @classmethod
    async def _principal_result(cls, db: Any, principal: Any) -> dict[str, Any]:
        authorization = await cls._authorization(db, principal)
        return {
            "principal_id": principal.id,
            "email": principal.email,
            "display_name": principal.display_name,
            "is_admin": bool(principal.is_admin),
            "must_change_password": bool(principal.must_change_password),
            "permissions": authorization["permissions"],
            "roles": authorization["roles"],
            "scopes": ["user"],
        }

    @staticmethod
    async def _authorization(db: Any, principal: Any) -> dict[str, Any]:
        roles_result = await _await(
            db.execute(
                select(RoleStore)
                .join(PrincipalRoleStore, PrincipalRoleStore.role_id == RoleStore.id)
                .where(PrincipalRoleStore.principal_id == principal.id)
            )
        )
        roles = list(roles_result.scalars())
        direct_result = await _await(
            db.execute(
                select(PermissionStore.key, PrincipalPermissionStore.effect)
                .join(
                    PrincipalPermissionStore,
                    PrincipalPermissionStore.permission_id == PermissionStore.id,
                )
                .where(PrincipalPermissionStore.principal_id == principal.id)
            )
        )
        grants = {key: effect for key, effect in direct_result.all()}
        if roles:
            inherited_result = await _await(
                db.execute(
                    select(PermissionStore.key)
                    .join(
                        RolePermissionStore,
                        RolePermissionStore.permission_id == PermissionStore.id,
                    )
                    .where(RolePermissionStore.role_id.in_([role.id for role in roles]))
                )
            )
            for key in inherited_result.scalars():
                grants.setdefault(key, "allow")
        return {
            "principal_id": principal.id,
            "roles": [role.name for role in roles],
            "permissions": _permission_projection(grants),
        }


Principal = PrincipalStore
SecurityPrincipal = PrincipalStore.SecurityPrincipal

PrincipalStore.credentials = relationship(CredentialStore, cascade="all, delete-orphan")
PrincipalRoleStore.principal = relationship(PrincipalStore)
PrincipalRoleStore.role = relationship(RoleStore)
PrincipalPermissionStore.principal = relationship(PrincipalStore)
PrincipalPermissionStore.permission = relationship(PermissionStore)

__all__ = [
    "Principal",
    "PrincipalStore",
    "SecurityPrincipal",
]
