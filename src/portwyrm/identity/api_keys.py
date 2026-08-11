"""Standalone Tigrbl Auth primitives for personal API-key credentials."""

from __future__ import annotations

import hashlib

from tigrbl_secret_hashing_bcrypt_provider import BcryptSecretHasher

from .passwords import verify_secret as verify_legacy_argon2_secret

_HASHER = BcryptSecretHasher()
_DUMMY_DIGEST = _HASHER.hash_secret("portwyrm-invalid-api-key").encoded


def _bcrypt_input(secret: str) -> bytes:
    if not isinstance(secret, str) or not secret:
        raise ValueError("API key must not be empty")
    return hashlib.sha256(f"portwyrm-pat-v1:{secret}".encode()).digest()


def hash_api_key(secret: str) -> str:
    """Hash a new API key with the focused Tigrbl Auth provider."""

    encoded = _HASHER.hash_secret(_bcrypt_input(secret)).encoded
    return encoded.decode("utf-8") if isinstance(encoded, bytes) else encoded


def verify_api_key(digest: str, secret: str) -> bool:
    """Verify bcrypt keys while retaining compatibility with issued Argon2 keys."""

    if digest.startswith("$argon2"):
        return verify_legacy_argon2_secret(digest, secret)
    return _HASHER.verify_secret(_bcrypt_input(secret), digest or _DUMMY_DIGEST).verified


__all__ = ["hash_api_key", "verify_api_key"]
