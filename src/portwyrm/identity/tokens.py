"""Hash-at-rest durable sessions and personal access tokens."""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

from portwyrm.persistence import Repository

from .models import PersonalAccessToken, Principal


@dataclass(slots=True)
class _Session:
    principal: Principal
    expires: int
    token_hash: str


_TOKEN_HASHER = PasswordHasher(
    time_cost=2, memory_cost=19_456, parallelism=1, hash_len=32, salt_len=16
)


def _token_hash(token: str) -> str:
    return _TOKEN_HASHER.hash(token)


def _token_matches(stored: str, token: str) -> bool:
    try:
        return _TOKEN_HASHER.verify(stored, token)
    except VerificationError:
        return False


def _principal_record(principal: Principal) -> dict[str, Any]:
    return {
        "user_id": principal.user_id,
        "identity": principal.identity,
        "is_admin": principal.is_admin,
        "permissions": dict(principal.permissions),
        "visibility": principal.visibility,
        "scopes": sorted(principal.scopes),
        "owner": principal.owner,
    }


def _principal_from_record(value: dict[str, Any]) -> Principal:
    return Principal(
        user_id=value["user_id"],
        identity=str(value["identity"]),
        is_admin=bool(value.get("is_admin")),
        permissions=dict(value.get("permissions", {})),
        visibility="all" if value.get("visibility") == "all" else "user",
        scopes=frozenset(str(scope) for scope in value.get("scopes", ["user"])),
        owner=str(value["owner"]) if value.get("owner") is not None else None,
    )


class TokenStore:
    """Session and PAT registry with optional repository durability."""

    def __init__(
        self,
        *,
        session_ttl_seconds: int = 86_400,
        repository: Repository | None = None,
    ) -> None:
        if session_ttl_seconds < 1:
            raise ValueError("session_ttl_seconds must be positive")
        self.session_ttl_seconds = session_ttl_seconds
        self.repository = repository
        self._sessions: dict[str, _Session] = {}
        self._pats: dict[str, PersonalAccessToken] = {}
        self._hydrate()

    def _hydrate(self) -> None:
        if self.repository is None:
            return
        with self.repository.transaction() as tx:
            for row in tx.list("_sessions"):
                token_hash = row.get("token_hash")
                if not isinstance(token_hash, str) or not token_hash.startswith("$argon2id$"):
                    continue
                self._sessions[str(row["id"])] = _Session(
                    _principal_from_record(dict(row["principal"])),
                    int(row["expires"]),
                    token_hash,
                )
            for row in tx.list("_personal_access_tokens"):
                self._pats[str(row["id"])] = PersonalAccessToken(
                    id=str(row["id"]),
                    name=str(row["name"]),
                    token_hash=str(row["token_hash"]),
                    principal=_principal_from_record(dict(row["principal"])),
                    created_at=int(row["created_at"]),
                    expires_at=(int(row["expires_at"]) if row.get("expires_at") else None),
                    last_used_at=(int(row["last_used_at"]) if row.get("last_used_at") else None),
                    revoked_at=(int(row["revoked_at"]) if row.get("revoked_at") else None),
                )

    def _persist_session(self, token_hash: str, session: _Session) -> None:
        if self.repository is None:
            return
        with self.repository.transaction() as tx:
            tx.upsert(
                "_sessions",
                {
                    "id": token_hash,
                    "token_hash": session.token_hash,
                    "principal": _principal_record(session.principal),
                    "expires": session.expires,
                },
            )

    def _delete_session(self, token_hash: str) -> None:
        if self.repository is not None:
            with self.repository.transaction() as tx:
                tx.delete("_sessions", token_hash)

    def _persist_pat(self, record: PersonalAccessToken) -> None:
        if self.repository is None:
            return
        with self.repository.transaction() as tx:
            tx.upsert(
                "_personal_access_tokens",
                {
                    "id": record.id,
                    "name": record.name,
                    "token_hash": record.token_hash,
                    "principal": _principal_record(record.principal),
                    "created_at": record.created_at,
                    "expires_at": record.expires_at,
                    "last_used_at": record.last_used_at,
                    "revoked_at": record.revoked_at,
                },
            )

    def issue_session(
        self,
        principal: Principal,
        *,
        now: int | None = None,
        ttl_seconds: int | None = None,
    ) -> tuple[str, int]:
        issued_at = int(time.time()) if now is None else int(now)
        token_id = secrets.token_hex(12)
        token = f"pws_{token_id}_{secrets.token_urlsafe(32)}"
        expires = issued_at + (self.session_ttl_seconds if ttl_seconds is None else ttl_seconds)
        token_hash = _token_hash(token)
        session = _Session(principal=principal, expires=expires, token_hash=token_hash)
        self._sessions[token_id] = session
        self._persist_session(token_id, session)
        return token, expires

    def revoke_session(self, token: str) -> bool:
        token_id, session = self._session_from_plaintext(token)
        if token_id is None or session is None:
            return False
        existed = self._sessions.pop(token_id, None) is not None
        self._delete_session(token_id)
        return existed

    def refresh_session(self, token: str, *, now: int | None = None) -> tuple[str, int]:
        principal = self.verify(token, now=now)
        self.revoke_session(token)
        return self.issue_session(principal, now=now)

    def create_pat(
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
        self._pats[token_id] = record
        self._persist_pat(record)
        return record, plaintext

    def list_pats(self, principal: Principal) -> list[PersonalAccessToken]:
        return [
            record
            for record in sorted(self._pats.values(), key=lambda item: item.created_at)
            if principal.is_admin or str(record.principal.user_id) == str(principal.user_id)
        ]

    def get_pat(self, token_id: str) -> PersonalAccessToken | None:
        return self._pats.get(token_id)

    def revoke_pat(self, token_id: str, *, now: int | None = None) -> bool:
        record = self._pats.get(token_id)
        if record is None or record.revoked_at is not None:
            return False
        record.revoked_at = int(time.time()) if now is None else int(now)
        self._persist_pat(record)
        return True

    def verify(self, token: str, *, now: int | None = None) -> Principal:
        checked_at = int(time.time()) if now is None else int(now)
        token_id, session = self._session_from_plaintext(token)
        if session is not None:
            if checked_at >= session.expires:
                assert token_id is not None
                self._sessions.pop(token_id, None)
                self._delete_session(token_id)
                raise ValueError("token expired")
            return session.principal
        record = self._pat_from_plaintext(token)
        if record is None or record.revoked_at is not None:
            raise ValueError("invalid token")
        if record.expires_at is not None and checked_at >= record.expires_at:
            raise ValueError("token expired")
        record.last_used_at = checked_at
        self._persist_pat(record)
        return record.principal

    def _session_from_plaintext(self, token: str) -> tuple[str | None, _Session | None]:
        parts = token.split("_", 2)
        if len(parts) != 3 or parts[0] != "pws":
            return None, None
        session = self._sessions.get(parts[1])
        if session is None or not _token_matches(session.token_hash, token):
            return None, None
        return parts[1], session

    def _pat_from_plaintext(self, token: str) -> PersonalAccessToken | None:
        parts = token.split("_", 2)
        if len(parts) != 3 or parts[0] != "pwyrm":
            return None
        record = self._pats.get(parts[1])
        if record is None or not _token_matches(record.token_hash, token):
            return None
        return record
