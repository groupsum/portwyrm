"""Personal access tokens as first-class Tigrbl table operations."""

from __future__ import annotations

import asyncio
import inspect
import secrets
import time
from typing import Any

from tigrbl import op_ctx, schema_ctx
from tigrbl.types import (
    JSON,
    BaseModel,
    Field,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    relationship,
)

from portwyrm.identity.passwords import hash_secret, verify_secret
from portwyrm.kernel_support import select

from .base import READ_ONLY_PROFILE, PortwyrmTable, acol
from .principals import PrincipalStore


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class PATStore(PortwyrmTable):
    __tablename__ = "personal_access_tokens"
    TABLE_PROFILE = READ_ONLY_PROFILE
    __table_args__ = (UniqueConstraint("token_prefix", name="uq_pat_prefix"),)

    principal_id = acol(Integer, ForeignKey("principals.id"), nullable=False, index=True)
    name = acol(String(255), nullable=False)
    token_prefix = acol(String(64), nullable=False)
    token_digest = acol(String(255), nullable=False)
    scopes = acol(JSON, nullable=False, default=list)
    expires_at = acol(Integer, nullable=True)
    last_used_at = acol(Integer, nullable=True)
    revoked_at = acol(Integer, nullable=True)
    replaced_by_id = acol(Integer, ForeignKey("personal_access_tokens.id"), nullable=True)
    replaced_by = relationship(
        "PATStore",
        remote_side="PATStore.id",
        foreign_keys=[replaced_by_id],
    )

    @schema_ctx(alias="issue", kind="in")
    class IssueRequest(BaseModel):
        principal_id: int
        name: str
        scopes: list[str] = Field(default_factory=list)
        expires_at: int | None = None

    @schema_ctx(alias="issue", kind="out")
    class IssueResult(BaseModel):
        id: int
        name: str
        token: str
        token_prefix: str
        scopes: list[str]
        expires_at: int | None

    @schema_ctx(alias="verify", kind="in")
    class VerifyRequest(BaseModel):
        token: str

    @schema_ctx(alias="verify", kind="out")
    class Verification(BaseModel):
        principal_id: int
        email: str
        display_name: str
        is_admin: bool
        scopes: list[str]

    @schema_ctx(alias="revoke", kind="in")
    class RevokeRequest(BaseModel):
        token_prefix: str

    @schema_ctx(alias="refresh", kind="in")
    class RefreshRequest(BaseModel):
        token_prefix: str
        expires_at: int

    @schema_ctx(alias="rotate", kind="in")
    class RotateRequest(BaseModel):
        token_prefix: str

    @schema_ctx(alias="rotate", kind="out")
    class RotateResult(IssueResult):
        replaced_token_prefix: str

    class TokenRecord(BaseModel):
        """Write-only-secret PAT projection exported by the owning table."""

        id: str
        name: str
        principal: PrincipalStore.SecurityPrincipal
        created_at: int
        expires_at: int | None
        last_used_at: int | None = None
        revoked_at: int | None = None

        def public(self) -> dict[str, Any]:
            return {
                "id": self.id,
                "name": self.name,
                "user_id": self.principal.user_id,
                "scopes": sorted(self.principal.scopes),
                "created_at": self.created_at,
                "expires_at": self.expires_at,
                "last_used_at": self.last_used_at,
                "revoked_at": self.revoked_at,
            }

    @op_ctx(alias="issue", target="custom", arity="collection")
    async def issue(cls, ctx: Any) -> dict[str, Any]:
        row, result = await cls._new_token(dict(ctx.get("payload") or {}))
        ctx["db"].add(row)
        return result

    @classmethod
    async def _new_token(cls, payload: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
        name = str(payload.get("name") or "").strip()
        if not name:
            raise ValueError("PAT name must not be empty")
        now = int(time.time())
        expires_at = payload.get("expires_at")
        if expires_at is not None and int(expires_at) <= now:
            raise ValueError("PAT expiry must be in the future")
        prefix = secrets.token_hex(12)
        plaintext = f"pwyrm_{prefix}_{secrets.token_urlsafe(32)}"
        digest = await asyncio.to_thread(hash_secret, plaintext)
        row = cls(
            id=secrets.randbelow(2**63 - 1) + 1,
            principal_id=int(payload["principal_id"]),
            name=name,
            token_prefix=prefix,
            token_digest=digest,
            scopes=sorted(set(payload.get("scopes") or [])),
            expires_at=int(expires_at) if expires_at is not None else None,
        )
        return row, {
            "id": row.id,
            "name": row.name,
            "token": plaintext,
            "token_prefix": prefix,
            "scopes": list(row.scopes),
            "expires_at": row.expires_at,
        }

    @op_ctx(alias="revoke", target="custom", arity="collection")
    async def revoke(cls, ctx: Any) -> dict[str, Any]:
        prefix = str((ctx.get("payload") or {}).get("token_prefix") or "")
        row = await cls._by_prefix(ctx["db"], prefix)
        if row is None:
            return {"revoked": False, "token_prefix": prefix}
        if row.revoked_at is None:
            row.revoked_at = int(time.time())
        return {"revoked": True, "token_prefix": prefix, "revoked_at": row.revoked_at}

    @op_ctx(alias="refresh", target="custom", arity="collection")
    async def refresh(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        prefix = str(payload.get("token_prefix") or "")
        row = await cls._by_prefix(ctx["db"], prefix)
        if row is None or row.revoked_at is not None:
            raise ValueError("token not found or revoked")
        expires_at = int(payload["expires_at"])
        if expires_at <= int(time.time()):
            raise ValueError("PAT expiry must be in the future")
        row.expires_at = expires_at
        return {"token_prefix": prefix, "expires_at": expires_at}

    @op_ctx(alias="rotate", target="custom", arity="collection")
    async def rotate(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        prefix = str(payload.get("token_prefix") or "")
        row = await cls._by_prefix(ctx["db"], prefix)
        if row is None or row.revoked_at is not None:
            raise ValueError("token not found or revoked")
        replacement, result = await cls._new_token(
            {
                "principal_id": row.principal_id,
                "name": row.name,
                "scopes": list(row.scopes or []),
                "expires_at": row.expires_at,
            }
        )
        ctx["db"].add(replacement)
        row.revoked_at = int(time.time())
        row.replaced_by = replacement
        return {**result, "replaced_token_prefix": prefix}

    @op_ctx(alias="verify", target="custom", arity="collection")
    async def verify(cls, ctx: Any) -> dict[str, Any]:
        token = str((ctx.get("payload") or {}).get("token") or "")
        parts = token.split("_", 2)
        if len(parts) != 3 or parts[0] != "pwyrm":
            raise ValueError("invalid token")
        row = await cls._by_prefix(ctx["db"], parts[1])
        now = int(time.time())
        digest = (
            row.token_digest
            if row is not None
            else "$argon2id$v=19$m=8,t=1,p=1$AAAAAAAAAAA$AAAAAAAAAAA"
        )
        matches = await asyncio.to_thread(verify_secret, digest, token)
        if (
            row is None
            or not matches
            or row.revoked_at is not None
            or (row.expires_at is not None and now >= row.expires_at)
        ):
            raise ValueError("invalid token")
        result = await _await(
            ctx["db"].execute(select(PrincipalStore).where(PrincipalStore.id == row.principal_id))
        )
        principal = result.scalar_one_or_none()
        if principal is None or principal.is_disabled or principal.is_deleted:
            raise ValueError("principal is unavailable")
        row.last_used_at = now
        return {
            "principal_id": principal.id,
            "email": principal.email,
            "display_name": principal.display_name,
            "is_admin": bool(principal.is_admin),
            "scopes": list(row.scopes or []),
        }

    @classmethod
    async def _by_prefix(cls, db: Any, prefix: str) -> Any:
        result = await _await(db.execute(select(cls).where(cls.token_prefix == prefix)))
        return result.scalar_one_or_none()


PersonalAccessToken = PATStore
PATIssueRequest = PATStore.IssueRequest
PATIssueResult = PATStore.IssueResult
PATVerifyRequest = PATStore.VerifyRequest
PATVerification = PATStore.Verification
PATRotateRequest = PATStore.RotateRequest
PATRotateResult = PATStore.RotateResult
PATRecord = PATStore.TokenRecord

__all__ = [
    "PATIssueRequest",
    "PATIssueResult",
    "PATRecord",
    "PATRotateRequest",
    "PATRotateResult",
    "PATStore",
    "PATVerification",
    "PATVerifyRequest",
    "PersonalAccessToken",
]
