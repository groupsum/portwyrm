"""Principals, credentials, and browser sessions as Tigrbl operations."""

from __future__ import annotations

import asyncio
import inspect
import secrets
import time
from typing import Any

from pydantic import Field
from sqlalchemy import delete, select
from tigrbl import op_ctx, schema_ctx
from tigrbl.factories.table import defineTableSpec
from tigrbl.types import (
    JSON,
    BaseModel,
    Boolean,
    Column,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from portwyrm.identity.passwords import hash_secret, verify_secret

from .base import ManagedPortwyrmTable, PortwyrmTable
from .compat import add_audit
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

    email = Column(String(320), nullable=False, index=True)
    display_name = Column(String(255), nullable=False, default="")
    nickname = Column(String(255), nullable=False, default="")
    is_admin = Column(Boolean, nullable=False, default=False)
    is_disabled = Column(Boolean, nullable=False, default=False)
    is_deleted = Column(Boolean, nullable=False, default=False)
    visibility = Column(String(32), nullable=False, default="user")

    @schema_ctx(alias="register", kind="in")
    class RegisterRequest(BaseModel):
        email: str
        password: str
        display_name: str = ""
        nickname: str = ""
        is_admin: bool = False
        roles: list[str] = Field(default_factory=list)
        permissions: dict[str, Any] = Field(default_factory=dict)
        metadata_json: dict[str, Any] = Field(default_factory=dict)

    @schema_ctx(alias="authenticate", kind="in")
    class AuthenticateRequest(BaseModel):
        email: str
        password: str

    @schema_ctx(alias="authenticate", kind="out")
    class AuthenticatedPrincipal(BaseModel):
        principal_id: int
        email: str
        display_name: str
        is_admin: bool
        permissions: dict[str, Any] = Field(default_factory=dict)
        scopes: list[str] = Field(default_factory=lambda: ["user"])

    @schema_ctx(alias="change_password", kind="in")
    class ChangePasswordRequest(BaseModel):
        principal_id: int
        old_password: str
        new_password: str

    @schema_ctx(alias="set_password", kind="in")
    class SetPasswordRequest(BaseModel):
        principal_id: int
        new_password: str

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
            is_disabled=False,
            is_deleted=False,
            visibility="all" if payload.get("is_admin") else "user",
            metadata_json=dict(payload.get("metadata_json") or {}),
        )
        ctx["db"].add(principal)
        await _await(ctx["db"].flush())
        digest = await asyncio.to_thread(hash_secret, password)
        ctx["db"].add(CredentialStore(principal_id=principal.id, password_hash=digest))
        await cls._replace_authorization(ctx["db"], principal, payload)
        result = {
            "id": principal.id,
            "email": principal.email,
            "display_name": principal.display_name,
            "nickname": principal.nickname,
            "is_admin": bool(principal.is_admin),
            "is_disabled": False,
            "is_deleted": False,
            "visibility": principal.visibility,
        }
        await add_audit(
            ctx["db"], action="created", object_type="users", object_id=principal.id, details=result
        )
        return result

    @op_ctx(alias="authenticate", target="custom", arity="collection")
    async def authenticate(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        email = str(payload.get("email") or "").strip().casefold()
        result = await _await(ctx["db"].execute(select(cls).where(cls.email == email)))
        principal = result.scalar_one_or_none()
        credential = None
        if principal is not None:
            credentials = await _await(
                ctx["db"].execute(
                    select(CredentialStore).where(CredentialStore.principal_id == principal.id)
                )
            )
            credential = credentials.scalar_one_or_none()
        digest = credential.password_hash if credential is not None else "invalid"
        valid = await asyncio.to_thread(verify_secret, digest, str(payload.get("password") or ""))
        if (
            principal is None
            or credential is None
            or not valid
            or principal.is_disabled
            or principal.is_deleted
        ):
            raise ValueError("invalid credentials")
        return await cls._principal_result(ctx["db"], principal)

    @op_ctx(alias="change_password", target="custom", arity="collection")
    async def change_password(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        new_password = str(payload.get("new_password") or "")
        if len(new_password) < 8:
            raise ValueError("password must contain at least 8 characters")
        result = await _await(
            ctx["db"].execute(
                select(CredentialStore).where(
                    CredentialStore.principal_id == int(payload["principal_id"])
                )
            )
        )
        credential = result.scalar_one_or_none()
        old_password = str(payload.get("old_password") or "")
        if credential is None or not await asyncio.to_thread(
            verify_secret, credential.password_hash, old_password
        ):
            raise ValueError("current password is invalid")
        credential.password_hash = await asyncio.to_thread(hash_secret, new_password)
        credential.password_version += 1
        return {"changed": True, "principal_id": credential.principal_id}

    @op_ctx(alias="set_password", target="custom", arity="collection")
    async def set_password(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        new_password = str(payload.get("new_password") or "")
        if len(new_password) < 8:
            raise ValueError("password must contain at least 8 characters")
        credential = await _scalar(
            ctx["db"],
            select(CredentialStore).where(
                CredentialStore.principal_id == int(payload["principal_id"])
            ),
        )
        if credential is None:
            raise ValueError("principal credential does not exist")
        credential.password_hash = await asyncio.to_thread(hash_secret, new_password)
        credential.password_version += 1
        return {"changed": True, "principal_id": credential.principal_id}

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
            "is_disabled": bool(principal.is_disabled),
            "is_deleted": bool(principal.is_deleted),
            "visibility": principal.visibility,
            "metadata_json": principal.metadata_json,
        }
        await add_audit(
            ctx["db"], action="updated", object_type="users", object_id=principal.id, details=result
        )
        return result

    @classmethod
    async def _replace_authorization(cls, db: Any, principal: Any, payload: dict[str, Any]) -> None:
        principal_id = int(principal.id)

        await _await(
            db.execute(
                delete(PrincipalRoleStore).where(PrincipalRoleStore.principal_id == principal_id)
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
                await _await(db.flush())
            db.add(PrincipalRoleStore(principal_id=principal_id, role_id=role.id))

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
                await _await(db.flush())
            db.add(
                PrincipalPermissionStore(
                    principal_id=principal_id,
                    permission_id=permission.id,
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

    @classmethod
    async def _principal_result(cls, db: Any, principal: Any) -> dict[str, Any]:
        authorization = await cls._authorization(db, principal)
        return {
            "principal_id": principal.id,
            "email": principal.email,
            "display_name": principal.display_name,
            "is_admin": bool(principal.is_admin),
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


class CredentialStore(PortwyrmTable, defineTableSpec(ops=())):
    __tablename__ = "credentials"
    __table_args__ = (UniqueConstraint("principal_id", name="uq_credentials_principal"),)
    principal_id = Column(Integer, ForeignKey("principals.id"), nullable=False, index=True)
    password_hash = Column(Text, nullable=False)
    password_version = Column(Integer, nullable=False, default=1)


class BrowserSessionStore(PortwyrmTable, defineTableSpec(ops=())):
    __tablename__ = "browser_sessions"
    __table_args__ = (UniqueConstraint("token_id", name="uq_browser_session_token_id"),)
    token_id = Column(String(64), nullable=False, index=True)
    token_digest = Column(String(255), nullable=False)
    principal_snapshot = Column(JSON, nullable=False)
    expires_at = Column(Integer, nullable=False, index=True)

    @op_ctx(alias="issue", target="custom", arity="collection")
    async def issue(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        token_id = secrets.token_hex(12)
        plaintext = f"pws_{token_id}_{secrets.token_urlsafe(32)}"
        expires_at = int(payload.get("expires_at") or int(time.time()) + 86_400)
        ctx["db"].add(
            cls(
                token_id=token_id,
                token_digest=await asyncio.to_thread(hash_secret, plaintext),
                principal_snapshot=dict(payload.get("principal") or {}),
                expires_at=expires_at,
            )
        )
        return {"token": plaintext, "expires_at": expires_at}

    @op_ctx(alias="verify", target="custom", arity="collection")
    async def verify(cls, ctx: Any) -> dict[str, Any]:
        token = str((ctx.get("payload") or {}).get("token") or "")
        parts = token.split("_", 2)
        if len(parts) != 3 or parts[0] != "pws":
            raise ValueError("invalid token")
        result = await _await(ctx["db"].execute(select(cls).where(cls.token_id == parts[1])))
        row = result.scalar_one_or_none()
        digest = row.token_digest if row is not None else "invalid"
        if (
            row is None
            or row.expires_at <= int(time.time())
            or not await asyncio.to_thread(verify_secret, digest, token)
        ):
            raise ValueError("invalid token")
        return dict(row.principal_snapshot)

    @op_ctx(alias="revoke", target="custom", arity="collection")
    async def revoke(cls, ctx: Any) -> dict[str, Any]:
        token = str((ctx.get("payload") or {}).get("token") or "")
        parts = token.split("_", 2)
        if len(parts) != 3 or parts[0] != "pws":
            return {"revoked": False}
        result = await _await(ctx["db"].execute(select(cls).where(cls.token_id == parts[1])))
        row = result.scalar_one_or_none()
        if row is None or not await asyncio.to_thread(verify_secret, row.token_digest, token):
            return {"revoked": False}
        await _await(ctx["db"].delete(row))
        return {"revoked": True}


Principal = PrincipalStore
Credential = CredentialStore
BrowserSession = BrowserSessionStore
AuthenticatedPrincipal = PrincipalStore.AuthenticatedPrincipal

__all__ = [
    "AuthenticatedPrincipal",
    "BrowserSession",
    "BrowserSessionStore",
    "Credential",
    "CredentialStore",
    "Principal",
    "PrincipalStore",
]
