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
from .token_policy import (
    PortwyrmScopeMatcher,
    effective_token_authority,
    may_manage_foreign_tokens,
    normalize_token_scopes,
    validate_requested_scopes,
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
    "PortwyrmScopeMatcher",
    "Principal",
    "effective_token_authority",
    "hash_secret",
    "may_manage_foreign_tokens",
    "needs_rehash",
    "normalize_token_scopes",
    "permission_allows",
    "validate_requested_scopes",
    "verify_secret",
]
