"""Table-native browser session and personal-access-token service."""

from __future__ import annotations

import inspect
import secrets
import time
from typing import Any

from sqlalchemy import select

from portwyrm.tables import KernelUnitOfWork
from portwyrm.tables.models import BrowserSession
from portwyrm.tables.models import PersonalAccessToken as PATRow

from .models import PersonalAccessToken, Principal
from .tokens import _principal_from_record, _principal_record, _token_hash, _token_matches


async def _result(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class KernelTokenStore:
    """Identity tokens persisted directly by Tigrbl table operations."""

    def __init__(self, app: Any, *, session_ttl_seconds: int = 86_400) -> None:
        self.uow = KernelUnitOfWork(app)
        self.session_ttl_seconds = session_ttl_seconds

    async def issue_session(
        self, principal: Principal, *, now: int | None = None, ttl_seconds: int | None = None
    ) -> tuple[str, int]:
        issued_at = int(time.time()) if now is None else int(now)
        token_id = secrets.token_hex(12)
        plaintext = f"pws_{token_id}_{secrets.token_urlsafe(32)}"
        expires = issued_at + (self.session_ttl_seconds if ttl_seconds is None else ttl_seconds)

        async def create(db: Any) -> None:
            db.add(
                BrowserSession(
                    token_id=token_id,
                    token_digest=_token_hash(plaintext),
                    principal_snapshot=_principal_record(principal),
                    expires_at=expires,
                )
            )

        await self.uow.run(create)
        return plaintext, expires

    async def revoke_session(self, token: str) -> bool:
        token_id = self._token_id(token, "pws")
        if token_id is None:
            return False

        async def revoke(db: Any) -> bool:
            result = await _result(
                db.execute(select(BrowserSession).where(BrowserSession.token_id == token_id))
            )
            row = result.scalar_one_or_none()
            if row is None or not _token_matches(row.token_digest, token):
                return False
            await _result(db.delete(row))
            return True

        return await self.uow.run(revoke)

    async def refresh_session(self, token: str, *, now: int | None = None) -> tuple[str, int]:
        principal = await self.verify(token, now=now)
        await self.revoke_session(token)
        return await self.issue_session(principal, now=now)

    async def create_pat(
        self,
        *,
        name: str,
        principal: Principal,
        expires_at: int | None = None,
        now: int | None = None,
    ) -> tuple[PersonalAccessToken, str]:
        if not name.strip():
            raise ValueError("PAT name must not be empty")
        created_at = int(time.time()) if now is None else int(now)
        if expires_at is not None and expires_at <= created_at:
            raise ValueError("PAT expiry must be in the future")
        token_id = secrets.token_hex(12)
        plaintext = f"pwyrm_{token_id}_{secrets.token_urlsafe(32)}"
        record = PersonalAccessToken(
            id=token_id,
            name=name.strip(),
            token_hash=_token_hash(plaintext),
            principal=principal,
            created_at=created_at,
            expires_at=expires_at,
        )

        async def create(db: Any) -> None:
            db.add(
                PATRow(
                    principal_id=int(principal.user_id),
                    name=record.name,
                    token_prefix=token_id,
                    token_digest=record.token_hash,
                    scopes=sorted(principal.scopes),
                    expires_at=expires_at,
                    metadata_json={
                        "created_at": created_at,
                        "principal": _principal_record(principal),
                    },
                )
            )

        await self.uow.run(create)
        return record, plaintext

    async def list_pats(self, principal: Principal) -> list[PersonalAccessToken]:
        async def read(db: Any) -> list[PersonalAccessToken]:
            result = await _result(db.execute(select(PATRow).order_by(PATRow.id)))
            records = [self._pat(row) for row in result.scalars()]
            return [
                item
                for item in records
                if principal.is_admin or str(item.principal.user_id) == str(principal.user_id)
            ]

        return await self.uow.run(read)

    async def get_pat(self, token_id: str) -> PersonalAccessToken | None:
        async def read(db: Any) -> PersonalAccessToken | None:
            result = await _result(
                db.execute(select(PATRow).where(PATRow.token_prefix == token_id))
            )
            row = result.scalar_one_or_none()
            return self._pat(row) if row is not None else None

        return await self.uow.run(read)

    async def revoke_pat(self, token_id: str, *, now: int | None = None) -> bool:
        async def revoke(db: Any) -> bool:
            result = await _result(
                db.execute(select(PATRow).where(PATRow.token_prefix == token_id))
            )
            row = result.scalar_one_or_none()
            if row is None or row.revoked_at is not None:
                return False
            row.revoked_at = int(time.time()) if now is None else int(now)
            return True

        return await self.uow.run(revoke)

    async def rotate_pat(
        self, token_id: str, *, now: int | None = None
    ) -> tuple[PersonalAccessToken, str]:
        record = await self.get_pat(token_id)
        if record is None:
            raise ValueError("token not found")
        if record.revoked_at is not None:
            raise ValueError("token is revoked")
        replacement, plaintext = await self.create_pat(
            name=record.name,
            principal=record.principal,
            expires_at=record.expires_at,
            now=now,
        )
        await self.revoke_pat(token_id, now=now)
        return replacement, plaintext

    async def verify(self, token: str, *, now: int | None = None) -> Principal:
        checked_at = int(time.time()) if now is None else int(now)
        prefix, model = ("pws", BrowserSession) if token.startswith("pws_") else ("pwyrm", PATRow)
        token_id = self._token_id(token, prefix)
        if token_id is None:
            raise ValueError("invalid token")

        async def verify_row(db: Any) -> Principal:
            column = model.token_id if model is BrowserSession else model.token_prefix
            result = await _result(db.execute(select(model).where(column == token_id)))
            row = result.scalar_one_or_none()
            digest = getattr(row, "token_digest", "") if row is not None else ""
            if row is None or not _token_matches(digest, token):
                raise ValueError("invalid token")
            expires_at = row.expires_at
            if expires_at is not None and checked_at >= expires_at:
                raise ValueError("token expired")
            if isinstance(row, PATRow):
                if row.revoked_at is not None:
                    raise ValueError("invalid token")
                row.last_used_at = checked_at
                return self._pat(row).principal
            return _principal_from_record(dict(row.principal_snapshot))

        return await self.uow.run(verify_row)

    @staticmethod
    def _token_id(token: str, prefix: str) -> str | None:
        parts = token.split("_", 2)
        return parts[1] if len(parts) == 3 and parts[0] == prefix else None

    @staticmethod
    def _pat(row: PATRow) -> PersonalAccessToken:
        metadata = row.metadata_json if isinstance(row.metadata_json, dict) else {}
        compat = metadata.get("compat") if isinstance(metadata.get("compat"), dict) else {}
        principal_record = metadata.get("principal", compat.get("principal", {}))
        principal = _principal_from_record(dict(principal_record))
        return PersonalAccessToken(
            id=row.token_prefix,
            name=row.name,
            token_hash=row.token_digest,
            principal=principal,
            created_at=int(metadata.get("created_at", compat.get("created_at", 0))),
            expires_at=row.expires_at,
            last_used_at=row.last_used_at,
            revoked_at=row.revoked_at,
        )
