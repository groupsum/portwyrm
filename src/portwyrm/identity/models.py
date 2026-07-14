"""Storage-neutral identity models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Permission = Literal["hidden", "view", "manage"]


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: int | str
    identity: str
    is_admin: bool = False
    permissions: dict[str, Permission] = field(default_factory=dict)
    visibility: Literal["all", "user"] = "user"
    scopes: frozenset[str] = frozenset({"user"})
    owner: str | None = None

    def may(self, section: str, *, write: bool = False) -> bool:
        if self.is_admin:
            return True
        permission = self.permissions.get(section, "hidden")
        return permission == "manage" if write else permission in {"view", "manage"}


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
