"""Write-only principal credentials and authentication operations."""

from __future__ import annotations

import asyncio
import inspect
from typing import Any

from tigrbl import hook_ctx, op_ctx, schema_ctx
from tigrbl.types import BaseModel, Field, ForeignKey, Integer, Text, UniqueConstraint

from portwyrm.identity.passwords import hash_secret, verify_secret
from portwyrm.kernel_support import select

from .base import PortwyrmTable, acol


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class CredentialStore(PortwyrmTable):
    """Own password persistence, verification, and rotation for principals."""

    __tablename__ = "credentials"
    __table_args__ = (UniqueConstraint("principal_id", name="uq_credentials_principal"),)

    principal_id = acol(Integer, ForeignKey("principals.id"), nullable=False, index=True)
    password_hash = acol(Text, nullable=False)
    password_version = acol(Integer, nullable=False, default=1)

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
        must_change_password: bool = False
        permissions: dict[str, Any] = Field(default_factory=dict)
        roles: list[str] = Field(default_factory=list)
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

    @op_ctx(alias="authenticate", target="custom", arity="collection")
    async def authenticate(cls, ctx: Any) -> dict[str, Any]:
        from .identities import PrincipalStore

        payload = dict(ctx.get("payload") or {})
        email = str(payload.get("email") or "").strip().casefold()
        principal_result = await _await(
            ctx["db"].execute(select(PrincipalStore).where(PrincipalStore.email == email))
        )
        principal = principal_result.scalar_one_or_none()
        credential = None
        if principal is not None:
            credential_result = await _await(
                ctx["db"].execute(select(cls).where(cls.principal_id == principal.id))
            )
            credential = credential_result.scalar_one_or_none()
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
        return await PrincipalStore._principal_result(ctx["db"], principal)

    @op_ctx(alias="change_password", target="custom", arity="collection")
    async def change_password(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        credential = await cls._for_principal(ctx["db"], int(payload["principal_id"]))
        old_password = str(payload.get("old_password") or "")
        new_password = str(payload.get("new_password") or "")
        if credential is None or not await asyncio.to_thread(
            verify_secret, credential.password_hash, old_password
        ):
            raise ValueError("current password is invalid")
        if new_password == old_password:
            raise ValueError("new password must differ from the current password")
        await cls._replace_password(credential, new_password)
        return {"changed": True, "principal_id": credential.principal_id}

    @op_ctx(alias="set_password", target="custom", arity="collection")
    async def set_password(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        credential = await cls._for_principal(ctx["db"], int(payload["principal_id"]))
        if credential is None:
            raise ValueError("principal credential does not exist")
        await cls._replace_password(credential, str(payload.get("new_password") or ""))
        return {"changed": True, "principal_id": credential.principal_id}

    @hook_ctx(ops="change_password", phase="POST_HANDLER")
    async def clear_password_change_requirement(cls, ctx: dict[str, Any]) -> None:
        """Complete the forced-change lifecycle in the operation transaction."""

        from .identities import PrincipalStore

        principal_id = int((ctx.get("payload") or {})["principal_id"])
        principal = await _await(ctx["db"].get(PrincipalStore, principal_id))
        if principal is not None:
            principal.must_change_password = False

    @hook_ctx(ops="set_password", phase="POST_HANDLER")
    async def require_password_change_after_reset(cls, ctx: dict[str, Any]) -> None:
        """Require recipients of an administrator reset to choose their own secret."""

        from .identities import PrincipalStore

        principal_id = int((ctx.get("payload") or {})["principal_id"])
        principal = await _await(ctx["db"].get(PrincipalStore, principal_id))
        if principal is not None:
            principal.must_change_password = True

    HOOKS = (clear_password_change_requirement, require_password_change_after_reset)

    @classmethod
    async def _for_principal(cls, db: Any, principal_id: int) -> Any:
        result = await _await(db.execute(select(cls).where(cls.principal_id == principal_id)))
        return result.scalar_one_or_none()

    @staticmethod
    async def _replace_password(credential: Any, password: str) -> None:
        if len(password) < 8:
            raise ValueError("password must contain at least 8 characters")
        credential.password_hash = await asyncio.to_thread(hash_secret, password)
        credential.password_version += 1


Credential = CredentialStore
AuthenticatedPrincipal = CredentialStore.AuthenticatedPrincipal

__all__ = ["AuthenticatedPrincipal", "Credential", "CredentialStore"]
