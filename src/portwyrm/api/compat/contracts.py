"""Frozen npmctl service ports and collection vocabulary."""

from __future__ import annotations

from typing import Any, Protocol

Resource = dict[str, Any]


class CompatibilityService(Protocol):
    async def list_resources(self, collection: str) -> list[Resource]: ...
    async def get_resource(self, collection: str, resource_id: int | str) -> Resource | None: ...
    async def create_resource(
        self, collection: str, payload: Resource, *, actor: Any | None = None
    ) -> Resource: ...
    async def update_resource(
        self,
        collection: str,
        resource_id: int | str,
        payload: Resource,
        *,
        actor: Any | None = None,
    ) -> Resource | None: ...
    async def replace_resource(
        self,
        collection: str,
        resource_id: int | str,
        payload: Resource,
        *,
        actor: Any | None = None,
    ) -> Resource | None: ...
    async def delete_resource(
        self, collection: str, resource_id: int | str, *, actor: Any | None = None
    ) -> bool: ...
    async def set_enabled(
        self,
        collection: str,
        resource_id: int | str,
        *,
        enabled: bool,
        actor: Any | None = None,
    ) -> Resource | None: ...
    async def list_audit(self, since: str | None = None) -> list[Resource]: ...


class TokenService(Protocol):
    def verify(self, token: str, *, now: int | None = None) -> Any: ...
    def list_pats(self, principal: Any, *, target_principal_id: int | None = None) -> Any: ...
    def create_pat(
        self,
        *,
        name: str,
        principal: Any,
        actor: Any | None = None,
        expires_at: int | None = None,
    ) -> Any: ...
    def get_pat(self, token_id: str, *, actor: Any | None = None, action: str = "read") -> Any: ...
    def update_pat_expiry(self, token_id: str, expires_at: int, *, actor: Any) -> Any: ...
    def rotate_pat(self, token_id: str, *, actor: Any | None = None) -> Any: ...
    def revoke_pat(self, token_id: str, *, actor: Any | None = None) -> Any: ...


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
TOGGLE_COLLECTIONS = {"proxy_hosts", "redirection_hosts", "dead_hosts", "streams"}

__all__ = [
    "COLLECTIONS",
    "SECTION_BY_COLLECTION",
    "TOGGLE_COLLECTIONS",
    "CompatibilityService",
    "MFAService",
    "Resource",
    "TokenService",
]
