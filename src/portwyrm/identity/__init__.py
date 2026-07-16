"""Identity cryptography and authorization policy.

Durable identity records and operations live in :mod:`portwyrm.tables`.
"""

from .passwords import hash_secret, needs_rehash, verify_secret
from .permissions import (
    PERMISSION_ACTIONS,
    PermissionAction,
    PermissionGrant,
    PermissionLevel,
    permission_allows,
)

Permission = PermissionLevel


def __getattr__(name: str) -> object:
    """Lazily expose table schemas without creating a table/identity import cycle."""
    if name == "Principal":
        from portwyrm.tables import SecurityPrincipal

        return SecurityPrincipal
    if name == "PersonalAccessToken":
        from portwyrm.tables import PATRecord

        return PATRecord
    raise AttributeError(name)


__all__ = [
    "PERMISSION_ACTIONS",
    "Permission",
    "PermissionAction",
    "PermissionGrant",
    "PermissionLevel",
    "PersonalAccessToken",
    "Principal",
    "hash_secret",
    "needs_rehash",
    "permission_allows",
    "verify_secret",
]
