"""Pure permission evaluation shared by table hooks and API dependencies."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

PermissionLevel = Literal["hidden", "view", "manage"]
PermissionAction = Literal["create", "read", "update", "delete"]
PermissionGrant = PermissionLevel | dict[str, bool]
PERMISSION_ACTIONS: tuple[PermissionAction, ...] = ("create", "read", "update", "delete")


def permission_allows(grant: object, action: PermissionAction) -> bool:
    if grant == "manage":
        return True
    if grant == "view":
        return action == "read"
    if grant in {"hidden", None}:
        return False
    return isinstance(grant, Mapping) and grant.get(action) is True
