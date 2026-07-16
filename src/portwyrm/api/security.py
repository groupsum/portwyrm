"""Tigrbl table operations and security dependencies for API identity."""

from __future__ import annotations

import inspect
import time
from datetime import datetime
from typing import Any

from tigrbl import HTTPBearer, HTTPException, Request
from tigrbl_typing.status.mappings import status

from portwyrm.tables import PATRecord, SecurityPrincipal


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def permissions_from_scopes(scopes: frozenset[str]) -> dict[str, dict[str, bool]]:
    """Project ``section:action`` PAT scopes into the principal permission shape."""
    permissions: dict[str, dict[str, bool]] = {}
    for scope in scopes:
        section, separator, action = scope.partition(":")
        if separator and section and action in {"create", "read", "update", "delete"}:
            permissions.setdefault(section, {})[action] = True
    return permissions


def _snapshot(principal: SecurityPrincipal) -> dict[str, Any]:
    return {
        "principal_id": int(principal.user_id),
        "email": principal.identity,
        "display_name": principal.display_name,
        "is_admin": principal.is_admin,
        "must_change_password": principal.must_change_password,
        "permissions": dict(principal.permissions),
        "scopes": sorted(principal.scopes),
        "visibility": principal.visibility,
        "owner": principal.owner,
    }


class TableIdentity:
    """Identity workflows composed only from public Tigrbl table operations."""

    def __init__(self, app: Any, *, session_ttl_seconds: int = 86_400) -> None:
        self.app = app
        self.session_ttl_seconds = session_ttl_seconds

    async def issue_session(
        self,
        principal: SecurityPrincipal,
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

    async def verify(self, token: str, *, now: int | None = None) -> SecurityPrincipal:
        del now
        if token.startswith("pws_"):
            verified = await self.app.core.BrowserSessionStore.verify({"token": token})
        else:
            verified = await self.app.core.PATStore.verify({"token": token})
        payload = dict(verified)
        scopes = frozenset(payload.get("scopes") or {"user"})
        resolved = await self.app.core.PrincipalStore.resolve(
            {
                "principal_id": int(payload.get("principal_id", payload.get("user_id"))),
                "scopes": sorted(scopes),
                "owner": payload.get("owner"),
            }
        )
        principal = SecurityPrincipal.model_validate(resolved)
        resource_scopes = scopes - {"user"}
        if resource_scopes:
            principal = principal.model_copy(
                update={
                    "is_admin": False,
                    "permissions": permissions_from_scopes(resource_scopes),
                }
            )
        return principal

    async def create_pat(
        self,
        *,
        name: str,
        principal: SecurityPrincipal,
        expires_at: int | None = None,
        now: int | None = None,
    ) -> tuple[PATRecord, str]:
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

    async def list_pats(self, principal: SecurityPrincipal) -> list[PATRecord]:
        rows = await self.app.core.PATStore.list({})
        records: list[PATRecord] = []
        for row in rows:
            if not principal.is_admin and str(row["principal_id"]) != str(principal.user_id):
                continue
            owner = await self._principal_by_id(int(row["principal_id"]), row.get("scopes") or [])
            records.append(self._pat(row, owner))
        return records

    async def get_pat(self, token_id: str) -> PATRecord | None:
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

    async def rotate_pat(self, token_id: str, *, now: int | None = None) -> tuple[PATRecord, str]:
        del now
        existing = await self.get_pat(token_id)
        if existing is None:
            raise ValueError("token not found")
        result = await self.app.core.PATStore.rotate({"token_prefix": token_id})
        return self._pat(result, existing.principal), str(result["token"])

    async def _principal_by_id(self, principal_id: int, scopes: list[str]) -> SecurityPrincipal:
        payload = await self.app.core.PrincipalStore.resolve(
            {"principal_id": principal_id, "scopes": scopes}
        )
        return SecurityPrincipal.model_validate(payload)

    @staticmethod
    def _pat(payload: dict[str, Any], principal: SecurityPrincipal) -> PATRecord:
        created = payload.get("created_at")
        if isinstance(created, datetime):
            created_at = int(created.timestamp())
        elif isinstance(created, str):
            created_at = int(datetime.fromisoformat(created).timestamp())
        else:
            created_at = int(created or 0)
        return PATRecord(
            id=str(payload["token_prefix"]),
            name=str(payload["name"]),
            principal=principal,
            created_at=created_at,
            expires_at=payload.get("expires_at"),
            last_used_at=payload.get("last_used_at"),
            revoked_at=payload.get("revoked_at"),
        )


class PrincipalSecurityDependency(HTTPBearer):
    """HTTP bearer/cookie security dependency that returns a table schema."""

    def __init__(
        self,
        identity: Any,
        *,
        mfa_only: bool = False,
        allow_password_change: bool = False,
    ) -> None:
        super().__init__(auto_error=False, scheme_name="PortwyrmBearer")
        self.identity = identity
        self.mfa_only = mfa_only
        self.allow_password_change = allow_password_change

    async def __call__(self, request: Request) -> SecurityPrincipal:
        credentials = super().__call__(request)
        token = (
            str(credentials.credentials)
            if credentials is not None
            else request.cookies.get("portwyrm_session")
        )
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=(
                    "MFA challenge token required" if self.mfa_only else "bearer token required"
                ),
            )
        try:
            principal = await _await(self.identity.verify(token))
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
        if self.mfa_only and principal.scopes != frozenset({"mfa"}):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="MFA challenge token required",
            )
        if not self.mfa_only and "user" not in principal.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="MFA challenge pending"
            )
        if principal.must_change_password and not self.allow_password_change:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="password change required",
            )
        return principal


class TableSecurityDependencies:
    """Named dependency set shared by the compatibility API routes."""

    def __init__(self, identity: Any) -> None:
        self.principal = PrincipalSecurityDependency(identity)
        self.mfa_principal = PrincipalSecurityDependency(identity, mfa_only=True)
        self.password_change_principal = PrincipalSecurityDependency(
            identity,
            allow_password_change=True,
        )


__all__ = [
    "PrincipalSecurityDependency",
    "TableIdentity",
    "TableSecurityDependencies",
    "permissions_from_scopes",
]
