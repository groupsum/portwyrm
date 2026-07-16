"""Frozen npmctl service ports and collection vocabulary."""

from __future__ import annotations

from typing import Any, Protocol

Resource = dict[str, Any]


class CompatibilityService(Protocol):
    async def list_resources(self, collection: str) -> list[Resource]: ...
    async def get_resource(self, collection: str, resource_id: int | str) -> Resource | None: ...
    async def create_resource(self, collection: str, payload: Resource) -> Resource: ...
    async def update_resource(
        self, collection: str, resource_id: int | str, payload: Resource
    ) -> Resource | None: ...
    async def delete_resource(self, collection: str, resource_id: int | str) -> bool: ...
    async def list_audit(self, since: str | None = None) -> list[Resource]: ...


class TokenService(Protocol):
    def verify(self, token: str, *, now: int | None = None) -> Any: ...


class MFAService(Protocol):
    def enabled(self, user_id: int | str) -> Any: ...
    def begin(self, user_id: int | str) -> Any: ...
    def confirm(self, user_id: int | str, code: str) -> Any: ...
    def verify(self, user_id: int | str, code: str) -> Any: ...
    def disable(self, user_id: int | str, code: str) -> Any: ...


COLLECTIONS: dict[str, tuple[str, bool]] = {
    "proxy-hosts": ("proxy_hosts", False),
    "certificates": ("certificates", False),
    "access-lists": ("access_lists", False),
    "redirection-hosts": ("redirection_hosts", False),
    "dead-hosts": ("dead_hosts", False),
    "streams": ("streams", False),
    "users": ("users", True),
    "settings": ("settings", True),
}
SECTION_BY_COLLECTION = {
    "proxy_hosts": "proxy_hosts",
    "certificates": "certificates",
    "access_lists": "access_lists",
    "redirection_hosts": "redirection_hosts",
    "dead_hosts": "dead_hosts",
    "streams": "streams",
}
TOKEN_SCOPE_ACTIONS = frozenset({"create", "read", "update", "delete"})
TOKEN_SCOPE_SECTIONS = frozenset(SECTION_BY_COLLECTION.values())
TOGGLE_COLLECTIONS = {"proxy_hosts", "redirection_hosts", "dead_hosts", "streams"}

__all__ = [
    "COLLECTIONS",
    "SECTION_BY_COLLECTION",
    "TOGGLE_COLLECTIONS",
    "TOKEN_SCOPE_ACTIONS",
    "TOKEN_SCOPE_SECTIONS",
    "CompatibilityService",
    "MFAService",
    "Resource",
    "TokenService",
]
