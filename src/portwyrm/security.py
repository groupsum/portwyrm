"""Compatibility imports and MFA primitives.

New identity code belongs under :mod:`portwyrm.identity`. This module remains a
stable import surface for existing callers while the product migrates.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time

from portwyrm.identity import Permission, PersonalAccessToken, Principal, TokenStore

__all__ = [
    "Permission",
    "PersonalAccessToken",
    "Principal",
    "TokenStore",
    "consume_backup_code",
    "generate_backup_codes",
    "generate_totp_secret",
    "totp_code",
    "verify_totp",
]


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
