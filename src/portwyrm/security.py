"""Stable compatibility imports for table-owned identity security schemas."""

from portwyrm.identity.mfa import (
    consume_backup_code,
    generate_backup_codes,
    generate_totp_secret,
    totp_code,
    verify_totp,
)
from portwyrm.identity.permissions import PermissionLevel as Permission
from portwyrm.tables import PATRecord as PersonalAccessToken
from portwyrm.tables import SecurityPrincipal as Principal

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
