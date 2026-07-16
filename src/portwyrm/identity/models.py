"""Compatibility exports for table-owned identity schemas.

New code should import these schemas from :mod:`portwyrm.tables` directly.
"""

from portwyrm.identity.permissions import (
    PERMISSION_ACTIONS,
    PermissionAction,
    PermissionGrant,
    PermissionLevel,
    permission_allows,
)
from portwyrm.tables.principals import SecurityPrincipal
from portwyrm.tables.tokens import PATRecord

Permission = PermissionLevel
Principal = SecurityPrincipal
PersonalAccessToken = PATRecord

__all__ = [
    "PERMISSION_ACTIONS",
    "Permission",
    "PermissionAction",
    "PermissionGrant",
    "PersonalAccessToken",
    "Principal",
    "permission_allows",
]
