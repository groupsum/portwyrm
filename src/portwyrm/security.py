"""Stable compatibility imports for identity policy and MFA primitives."""

from portwyrm.identity.mfa import (
    consume_backup_code,
    generate_backup_codes,
    generate_totp_secret,
    totp_code,
    verify_totp,
)
from portwyrm.identity.models import Permission, PersonalAccessToken, Principal

__all__ = [
    "Permission",
    "PersonalAccessToken",
    "Principal",
    "consume_backup_code",
    "generate_backup_codes",
    "generate_totp_secret",
    "totp_code",
    "verify_totp",
]
