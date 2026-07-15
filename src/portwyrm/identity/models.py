"""Storage-neutral identity models."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal

Permission = Literal["hidden", "view", "manage"]
PermissionAction = Literal["create", "read", "update", "delete"]
PermissionGrant = Permission | dict[str, bool]
PERMISSION_ACTIONS: tuple[PermissionAction, ...] = ("create", "read", "update", "delete")


def permission_allows(grant: object, action: PermissionAction) -> bool:
    """Evaluate legacy levels and action-level grants through one compatibility boundary."""
    if grant == "manage":
        return True
    if grant == "view":
        return action == "read"
    if grant == "hidden" or grant is None:
        return False
    if isinstance(grant, Mapping):
        value = grant.get(action, False)
        return value is True
    return False


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: int | str
    identity: str
    is_admin: bool = False
    permissions: dict[str, PermissionGrant] = field(default_factory=dict)
    visibility: Literal["all", "user"] = "user"
    scopes: frozenset[str] = frozenset({"user"})
    owner: str | None = None

    def may(
        self,
        section: str,
        *,
        write: bool = False,
        action: PermissionAction | None = None,
    ) -> bool:
        if self.is_admin:
            return True
        normalized = section.replace("-", "_")
        requested = action or ("update" if write else "read")
        return permission_allows(self.permissions.get(normalized, "hidden"), requested)


@dataclass(slots=True)
class PersonalAccessToken:
    id: str
    name: str
    token_hash: str
    principal: Principal
    created_at: int
    expires_at: int | None
    last_used_at: int | None = None
    revoked_at: int | None = None

    def public(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "user_id": self.principal.user_id,
            "scopes": sorted(self.principal.scopes),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "last_used_at": self.last_used_at,
            "revoked_at": self.revoked_at,
        }
