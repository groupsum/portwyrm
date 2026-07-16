"""Write-only password and token digest primitives."""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError

_HASHER = PasswordHasher(
    time_cost=2,
    memory_cost=19_456,
    parallelism=1,
    hash_len=32,
    salt_len=16,
)


def hash_secret(secret: str) -> str:
    if not isinstance(secret, str) or not secret:
        raise ValueError("secret must not be empty")
    return _HASHER.hash(secret)


def verify_secret(digest: str, secret: str) -> bool:
    try:
        return _HASHER.verify(digest, secret)
    except (VerificationError, TypeError, ValueError):
        return False


def needs_rehash(digest: str) -> bool:
    try:
        return _HASHER.check_needs_rehash(digest)
    except (TypeError, ValueError):
        return True
