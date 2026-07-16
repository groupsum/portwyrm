"""Durable browser sessions and their lifecycle operations."""

from __future__ import annotations

import asyncio
import inspect
import secrets
import time
from typing import Any

from tigrbl import op_ctx
from tigrbl.types import JSON, Integer, String, UniqueConstraint

from portwyrm.identity.passwords import hash_secret, verify_secret
from portwyrm.kernel_support import select

from .base import PortwyrmTable, acol


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class BrowserSessionStore(PortwyrmTable):
    """Issue, verify, and revoke opaque browser-session credentials."""

    __tablename__ = "browser_sessions"
    __table_args__ = (UniqueConstraint("token_id", name="uq_browser_session_token_id"),)

    token_id = acol(String(64), nullable=False, index=True)
    token_digest = acol(String(255), nullable=False)
    principal_snapshot = acol(JSON, nullable=False)
    expires_at = acol(Integer, nullable=False, index=True)

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
        token_id = cls._token_id(token)
        if token_id is None:
            raise ValueError("invalid token")
        result = await _await(ctx["db"].execute(select(cls).where(cls.token_id == token_id)))
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
        token_id = cls._token_id(token)
        if token_id is None:
            return {"revoked": False}
        result = await _await(ctx["db"].execute(select(cls).where(cls.token_id == token_id)))
        row = result.scalar_one_or_none()
        if row is None or not await asyncio.to_thread(verify_secret, row.token_digest, token):
            return {"revoked": False}
        await _await(ctx["db"].delete(row))
        return {"revoked": True}

    @staticmethod
    def _token_id(token: str) -> str | None:
        parts = token.split("_", 2)
        return parts[1] if len(parts) == 3 and parts[0] == "pws" else None


BrowserSession = BrowserSessionStore

__all__ = ["BrowserSession", "BrowserSessionStore"]
