"""Authentication primitives shared by the compatibility and native APIs.

The NPM compatibility token is deliberately opaque.  npmctl treats it as a
bearer credential and does not depend on JWT claims, so keeping token parsing
inside this module avoids leaking NPM-specific authentication choices into the
domain model.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from dataclasses import dataclass, field
from typing import Literal

Permission = Literal["hidden", "view", "manage"]


@dataclass(frozen=True, slots=True)
class Principal:
    """Authenticated operator identity used at the API authorization boundary."""

    user_id: int | str
    identity: str
    is_admin: bool = False
    permissions: dict[str, Permission] = field(default_factory=dict)
    visibility: Literal["all", "user"] = "user"
    scopes: frozenset[str] = frozenset({"user"})
    owner: str | None = None

    def may(self, section: str, *, write: bool = False) -> bool:
        if self.is_admin:
            return True
        permission = self.permissions.get(section, "hidden")
        return permission == "manage" if write else permission in {"view", "manage"}


@dataclass(slots=True)
class _Session:
    principal: Principal
    expires: int


@dataclass(slots=True)
class PersonalAccessToken:
    """Hash-at-rest metadata for a named personal or service token."""

    id: str
    name: str
    token_hash: str
    principal: Principal
    created_at: int
    expires_at: int | None
    last_used_at: int | None = None
    revoked_at: int | None = None


class TokenStore:
    """In-process session and PAT registry suitable for the API boundary.

    Durable deployments can wrap or replace this object with a repository-backed
    implementation while preserving the same small interface.
    """

    def __init__(self, *, session_ttl_seconds: int = 86_400) -> None:
        if session_ttl_seconds < 1:
            raise ValueError("session_ttl_seconds must be positive")
        self.session_ttl_seconds = session_ttl_seconds
        self._sessions: dict[str, _Session] = {}
        self._pats: dict[str, PersonalAccessToken] = {}

    def issue_session(self, principal: Principal, *, now: int | None = None) -> tuple[str, int]:
        issued_at = int(time.time()) if now is None else int(now)
        token = secrets.token_urlsafe(32)
        expires = issued_at + self.session_ttl_seconds
        self._sessions[token] = _Session(principal=principal, expires=expires)
        return token, expires

    def refresh_session(self, token: str, *, now: int | None = None) -> tuple[str, int]:
        principal = self.verify(token, now=now)
        self._sessions.pop(token, None)
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
        secret = secrets.token_urlsafe(32)
        plaintext = f"pwyrm_{token_id}_{secret}"
        record = PersonalAccessToken(
            id=token_id,
            name=name.strip(),
            token_hash=_token_hash(plaintext),
            principal=principal,
            created_at=created_at,
            expires_at=expires_at,
        )
        self._pats[token_id] = record
        return record, plaintext

    def revoke_pat(self, token_id: str, *, now: int | None = None) -> bool:
        record = self._pats.get(token_id)
        if record is None or record.revoked_at is not None:
            return False
        record.revoked_at = int(time.time()) if now is None else int(now)
        return True

    def verify(self, token: str, *, now: int | None = None) -> Principal:
        checked_at = int(time.time()) if now is None else int(now)
        session = self._sessions.get(token)
        if session is not None:
            if checked_at >= session.expires:
                self._sessions.pop(token, None)
                raise ValueError("token expired")
            return session.principal
        record = self._pat_from_plaintext(token)
        if record is None or record.revoked_at is not None:
            raise ValueError("invalid token")
        if record.expires_at is not None and checked_at >= record.expires_at:
            raise ValueError("token expired")
        record.last_used_at = checked_at
        return record.principal

    def _pat_from_plaintext(self, token: str) -> PersonalAccessToken | None:
        parts = token.split("_", 2)
        if len(parts) != 3 or parts[0] != "pwyrm":
            return None
        record = self._pats.get(parts[1])
        if record is None or not hmac.compare_digest(record.token_hash, _token_hash(token)):
            return None
        return record


def generate_totp_secret(*, bytes_count: int = 20) -> str:
    if bytes_count < 16:
        raise ValueError("TOTP secrets must contain at least 128 bits")
    return base64.b32encode(secrets.token_bytes(bytes_count)).decode("ascii").rstrip("=")


def totp_code(
    secret: str,
    *,
    at: int | float | None = None,
    period: int = 30,
    digits: int = 6,
) -> str:
    """Return an RFC 6238 compatible SHA-1 TOTP code."""

    if period < 1 or digits not in {6, 7, 8}:
        raise ValueError("invalid TOTP parameters")
    moment = time.time() if at is None else float(at)
    counter = int(moment // period)
    key = _decode_base32(secret)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFF_FFFF
    return str(binary % (10**digits)).zfill(digits)


def verify_totp(
    secret: str,
    code: str,
    *,
    at: int | float | None = None,
    window: int = 1,
    period: int = 30,
    digits: int = 6,
) -> bool:
    if window < 0 or not code.isdigit() or len(code) != digits:
        return False
    moment = time.time() if at is None else float(at)
    return any(
        hmac.compare_digest(
            totp_code(secret, at=moment + offset * period, period=period, digits=digits), code
        )
        for offset in range(-window, window + 1)
    )


def generate_backup_codes(*, count: int = 8) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if count < 1:
        raise ValueError("backup code count must be positive")
    codes = tuple(secrets.token_hex(5) for _ in range(count))
    return codes, tuple(_token_hash(code) for code in codes)


def consume_backup_code(code: str, hashes: list[str]) -> bool:
    candidate = _token_hash(code)
    for index, stored in enumerate(hashes):
        if hmac.compare_digest(candidate, stored):
            del hashes[index]
            return True
    return False


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _decode_base32(secret: str) -> bytes:
    normalized = "".join(secret.upper().split())
    padding = "=" * ((8 - len(normalized) % 8) % 8)
    try:
        return base64.b32decode(normalized + padding, casefold=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("invalid base32 TOTP secret") from exc
