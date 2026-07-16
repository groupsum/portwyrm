"""API authentication adapters backed exclusively by Tigrbl table operations."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any

from portwyrm.identity.models import PersonalAccessToken, Principal


def _snapshot(principal: Principal) -> dict[str, Any]:
    return {
        "principal_id": int(principal.user_id),
        "email": principal.identity,
        "display_name": principal.identity,
        "is_admin": principal.is_admin,
        "permissions": dict(principal.permissions),
        "scopes": sorted(principal.scopes),
        "visibility": principal.visibility,
        "owner": principal.owner,
    }


def _principal(payload: dict[str, Any]) -> Principal:
    return Principal(
        user_id=payload.get("principal_id", payload.get("user_id")),
        identity=str(payload.get("email", payload.get("identity", ""))),
        is_admin=bool(payload.get("is_admin")),
        permissions=dict(payload.get("permissions") or {}),
        visibility=payload.get("visibility", "all" if payload.get("is_admin") else "user"),
        scopes=frozenset(payload.get("scopes") or {"user"}),
        owner=payload.get("owner"),
    )


class TableIdentity:
    """Frozen compatibility methods delegating to public Tigrbl core proxies."""

    def __init__(self, app: Any, *, session_ttl_seconds: int = 86_400) -> None:
        self.app = app
        self.session_ttl_seconds = session_ttl_seconds

    async def issue_session(
        self,
        principal: Principal,
        *,
        now: int | None = None,
        ttl_seconds: int | None = None,
    ) -> tuple[str, int]:
        issued_at = int(time.time()) if now is None else int(now)
        expires_at = issued_at + (
            self.session_ttl_seconds if ttl_seconds is None else int(ttl_seconds)
        )
        result = await self.app.core.BrowserSessionStore.issue(
            {"principal": _snapshot(principal), "expires_at": expires_at}
        )
        return str(result["token"]), int(result["expires_at"])

    async def revoke_session(self, token: str) -> bool:
        result = await self.app.core.BrowserSessionStore.revoke({"token": token})
        return bool(result["revoked"])

    async def refresh_session(self, token: str, *, now: int | None = None) -> tuple[str, int]:
        principal = await self.verify(token, now=now)
        await self.revoke_session(token)
        return await self.issue_session(principal, now=now)

    async def verify(self, token: str, *, now: int | None = None) -> Principal:
        del now
        if token.startswith("pws_"):
            result = await self.app.core.BrowserSessionStore.verify({"token": token})
        else:
            result = await self.app.core.PATStore.verify({"token": token})
        return _principal(dict(result))

    async def create_pat(
        self,
        *,
        name: str,
        principal: Principal,
        expires_at: int | None = None,
        now: int | None = None,
    ) -> tuple[PersonalAccessToken, str]:
        del now
        result = await self.app.core.PATStore.issue(
            {
                "principal_id": int(principal.user_id),
                "name": name,
                "scopes": sorted(principal.scopes),
                "expires_at": expires_at,
            }
        )
        return self._pat(result, principal), str(result["token"])

    async def list_pats(self, principal: Principal) -> list[PersonalAccessToken]:
        rows = await self.app.core.PATStore.list({})
        return [
            self._pat(
                row,
                Principal(
                    user_id=row["principal_id"],
                    identity=principal.identity,
                    is_admin=principal.is_admin,
                    permissions=principal.permissions,
                    visibility=principal.visibility,
                    scopes=frozenset(row.get("scopes") or []),
                    owner=principal.owner,
                ),
            )
            for row in rows
            if principal.is_admin or str(row["principal_id"]) == str(principal.user_id)
        ]

    async def get_pat(self, token_id: str) -> PersonalAccessToken | None:
        rows = await self.app.core.PATStore.list({})
        row = next((item for item in rows if item["token_prefix"] == token_id), None)
        if row is None:
            return None
        principal = await self._principal_by_id(int(row["principal_id"]), row.get("scopes") or [])
        return self._pat(row, principal)

    async def revoke_pat(self, token_id: str, *, now: int | None = None) -> bool:
        del now
        result = await self.app.core.PATStore.revoke({"token_prefix": token_id})
        return bool(result["revoked"])

    async def rotate_pat(
        self, token_id: str, *, now: int | None = None
    ) -> tuple[PersonalAccessToken, str]:
        del now
        existing = await self.get_pat(token_id)
        if existing is None:
            raise ValueError("token not found")
        result = await self.app.core.PATStore.rotate({"token_prefix": token_id})
        return self._pat(result, existing.principal), str(result["token"])

    async def _principal_by_id(self, principal_id: int, scopes: list[str]) -> Principal:
        row = await self.app.core.PrincipalStore.read({"id": principal_id})
        return _principal(
            {
                "principal_id": row["id"],
                "email": row["email"],
                "display_name": row["display_name"],
                "is_admin": row["is_admin"],
                "scopes": scopes,
            }
        )

    @staticmethod
    def _pat(payload: dict[str, Any], principal: Principal) -> PersonalAccessToken:
        created = payload.get("created_at")
        if isinstance(created, datetime):
            created_at = int(created.timestamp())
        elif isinstance(created, str):
            created_at = int(datetime.fromisoformat(created).timestamp())
        else:
            created_at = int(created or 0)
        return PersonalAccessToken(
            id=str(payload["token_prefix"]),
            name=str(payload["name"]),
            token_hash="",
            principal=principal,
            created_at=created_at,
            expires_at=payload.get("expires_at"),
            last_used_at=payload.get("last_used_at"),
            revoked_at=payload.get("revoked_at"),
        )


__all__ = ["TableIdentity"]
