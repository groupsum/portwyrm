"""NPM wire projections backed directly by Portwyrm Tigrbl table operations."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

from portwyrm.tables import SecurityPrincipal as Principal

Resource = dict[str, Any]

_HOST_KIND = {
    "proxy_hosts": "proxy",
    "redirection_hosts": "redirect",
    "dead_hosts": "dead",
}

_TABLE = {
    "access_lists": "AccessListStore",
    "certificates": "CertificateStore",
    "settings": "SettingStore",
    "streams": "StreamRouteStore",
    "users": "PrincipalStore",
}


def _iso(value: Any) -> str:
    if value is None:
        return datetime.now(UTC).isoformat()
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    return str(value)


class TableResources:
    """Compatibility boundary; business state remains owned by table operations."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self.after_change: Callable[[str], Awaitable[Any]] | None = None

    async def authenticate(self, identity: str, secret: str) -> Principal | None:
        try:
            payload = await self.app.core.PrincipalStore.authenticate(
                {"email": identity, "password": secret}
            )
        except ValueError:
            return None
        return Principal(
            user_id=payload["principal_id"],
            identity=payload["email"],
            is_admin=bool(payload["is_admin"]),
            permissions=dict(payload.get("permissions") or {}),
            visibility="all" if payload["is_admin"] else "user",
            scopes=frozenset(payload.get("scopes") or {"user"}),
        )

    async def bootstrap_admin(self, email: str, password: str) -> Resource:
        return await self.create_resource(
            "users",
            {
                "email": email,
                "password": password,
                "name": "Administrator",
                "nickname": "admin",
                "is_admin": True,
                "roles": ["admin"],
                "permissions": {},
                "visibility": "all",
            },
        )

    async def list_resources(self, collection: str) -> list[Resource]:
        if collection in _HOST_KIND:
            return await self.app.core.RoutingHostStore.compat_list(
                {"kind": _HOST_KIND[collection]}
            )
        if collection in {"access_lists", "certificates"}:
            return await getattr(self.app.core, self._table_name(collection)).compat_list({})
        else:
            rows = await getattr(self.app.core, self._table_name(collection)).list({})
        projected = [self._project(collection, row) for row in rows]
        if collection == "users":
            for item in projected:
                await self._attach_authorization(item)
        return projected

    async def get_resource(self, collection: str, resource_id: int | str) -> Resource | None:
        try:
            if collection in _HOST_KIND:
                row = await self.app.core.RoutingHostStore.compat_read({"id": int(resource_id)})
                if row.get("kind") != _HOST_KIND[collection]:
                    return None
                return self._clean_aggregate(collection, row)
            elif collection in {"access_lists", "certificates"}:
                row = await getattr(self.app.core, self._table_name(collection)).compat_read(
                    {"id": int(resource_id)}
                )
                return self._clean_aggregate(collection, row)
            else:
                row = await getattr(self.app.core, self._table_name(collection)).read(
                    {"id": int(resource_id)}
                )
        except (LookupError, ValueError):
            return None
        projected = self._project(collection, row)
        if collection == "users":
            await self._attach_authorization(projected)
        return projected

    async def create_resource(self, collection: str, payload: Resource) -> Resource:
        candidate = dict(payload)
        if collection in _HOST_KIND:
            candidate["kind"] = _HOST_KIND[collection]
            row = await self.app.core.RoutingHostStore.create_compat(candidate)
        elif collection in {"access_lists", "certificates"}:
            table = getattr(self.app.core, self._table_name(collection))
            row = await table.create_compat(candidate)
        elif collection == "users":
            row = await self.app.core.PrincipalStore.register(
                {
                    "email": candidate["email"],
                    "password": candidate.pop("password"),
                    "display_name": candidate.get("name", candidate.get("display_name", "")),
                    "nickname": candidate.get("nickname", ""),
                    "is_admin": bool(candidate.get("is_admin")),
                    "roles": candidate.get("roles") or [],
                    "permissions": candidate.get("permissions") or {},
                    "metadata_json": {"compat": candidate},
                }
            )
            row = {**row, "metadata_json": {"compat": candidate}}
        elif collection == "streams":
            values = self._values(collection, candidate)
            await self.app.core.StreamRouteStore.validate(values)
            row = await self.app.core.StreamRouteStore.create(values)
        else:
            row = await getattr(self.app.core, self._table_name(collection)).create(
                self._values(collection, candidate)
            )
        result = self._project(collection, row)
        if collection in {*_HOST_KIND, "access_lists", "certificates"}:
            result = await self.get_resource(collection, row["id"]) or result
        elif collection == "users":
            await self._attach_authorization(result)
        if collection not in {*_HOST_KIND, "access_lists", "certificates", "users"}:
            await self.record_event("created", collection, result["id"], details=result)
        if self.after_change is not None:
            await self.after_change(collection)
        return result

    async def update_resource(
        self, collection: str, resource_id: int | str, payload: Resource
    ) -> Resource | None:
        current = await self.get_resource(collection, resource_id)
        if current is None:
            return None
        candidate = {**current, **payload}
        if collection in _HOST_KIND:
            candidate.update({"id": int(resource_id), "kind": _HOST_KIND[collection]})
            row = await self.app.core.RoutingHostStore.update_compat(candidate)
        elif collection in {"access_lists", "certificates"}:
            table = getattr(self.app.core, self._table_name(collection))
            row = await table.update_compat({"id": int(resource_id), **candidate})
        elif collection == "users":
            values = self._values(collection, candidate)
            row = await self.app.core.PrincipalStore.update_identity(
                {
                    "principal_id": int(resource_id),
                    **values,
                    "roles": candidate.get("roles") or [],
                    "permissions": candidate.get("permissions") or {},
                }
            )
        elif collection == "streams":
            values = self._values(collection, candidate)
            await self.app.core.StreamRouteStore.validate({"id": int(resource_id), **values})
            row = await self.app.core.StreamRouteStore.update(
                {"id": int(resource_id), **values}
            )
        else:
            row = await getattr(self.app.core, self._table_name(collection)).update(
                {"id": int(resource_id), **self._values(collection, candidate)}
            )
        result = self._project(collection, row)
        if collection in {*_HOST_KIND, "access_lists", "certificates"}:
            result = await self.get_resource(collection, resource_id) or result
        elif collection == "users":
            await self._attach_authorization(result)
        if collection not in {*_HOST_KIND, "access_lists", "certificates", "users"}:
            await self.record_event("updated", collection, result["id"], details=result)
        if self.after_change is not None:
            await self.after_change(collection)
        return result

    async def change_password(
        self, principal_id: int | str, old_password: str, new_password: str
    ) -> dict[str, Any]:
        return await self.app.core.PrincipalStore.change_password(
            {
                "principal_id": int(principal_id),
                "old_password": old_password,
                "new_password": new_password,
            }
        )

    async def set_password(self, principal_id: int | str, new_password: str) -> dict[str, Any]:
        return await self.app.core.PrincipalStore.set_password(
            {"principal_id": int(principal_id), "new_password": new_password}
        )

    async def _attach_authorization(self, resource: Resource) -> None:
        authorization = await self.app.core.PrincipalStore.authorization(
            {"principal_id": int(resource["id"])}
        )
        resource["roles"] = authorization["roles"]
        resource["permissions"] = authorization["permissions"]

    async def delete_resource(self, collection: str, resource_id: int | str) -> bool:
        current = await self.get_resource(collection, resource_id)
        if current is None:
            return False
        if collection in _HOST_KIND:
            await self.app.core.RoutingHostStore.delete_compat({"id": int(resource_id)})
        elif collection in {"access_lists", "certificates"}:
            table = getattr(self.app.core, self._table_name(collection))
            await table.delete_compat({"id": int(resource_id)})
        else:
            await getattr(self.app.core, self._table_name(collection)).delete(
                {"id": int(resource_id)}
            )
        if collection not in {*_HOST_KIND, "access_lists", "certificates"}:
            await self.record_event("deleted", collection, resource_id)
        if self.after_change is not None:
            await self.after_change(collection)
        return True

    async def list_audit(self, since: str | None = None) -> list[Resource]:
        rows = await self.app.core.AuditEventStore.list({})
        projected = [
            {
                "id": row["id"],
                "created_on": _iso(row.get("created_at")),
                "action": row["action"],
                "object_type": row["object_type"],
                "object_id": row["object_id"],
                "user_id": row.get("actor_principal_id"),
                "meta": row.get("details") or {},
            }
            for row in rows
        ]
        return [item for item in projected if since is None or item["created_on"] >= since]

    async def record_event(
        self,
        action: str,
        object_type: str,
        object_id: int | str,
        *,
        details: Resource | None = None,
        actor: Any | None = None,
    ) -> None:
        await self.app.core.AuditEventStore.record(
            {
                "actor_principal_id": getattr(actor, "user_id", getattr(actor, "id", None)),
                "action": action,
                "object_type": object_type,
                "object_id": str(object_id),
                "details": details or {},
            }
        )

    @staticmethod
    def _table_name(collection: str) -> str:
        try:
            return _TABLE[collection]
        except KeyError as exc:
            raise ValueError(f"unknown compatibility collection {collection!r}") from exc

    @staticmethod
    def _clean_aggregate(collection: str, row: Resource) -> Resource:
        ignored = {"metadata_json", "created_at", "updated_at"}
        if collection in _HOST_KIND:
            ignored |= {
                "force_ssl",
                "websocket_enabled",
                "cache_enabled",
                "http2_enabled",
                "redirect_target",
                "redirect_scheme",
                "redirect_code",
            }
        return {key: value for key, value in row.items() if key not in ignored}

    @staticmethod
    def _project(collection: str, row: Resource) -> Resource:
        metadata = dict(row.get("metadata_json") or {})
        payload = dict(metadata.get("compat") or {})
        payload.update({"id": row["id"]})
        payload.setdefault("created_on", _iso(row.get("created_at")))
        payload["modified_on"] = _iso(row.get("updated_at", row.get("created_at")))
        if collection in _HOST_KIND:
            payload["kind"] = _HOST_KIND[collection]
            payload["enabled"] = int(row.get("enabled", payload.get("enabled", 1)))
        if collection == "users":
            payload.update(
                {
                    "email": row["email"],
                    "name": row.get("display_name", ""),
                    "nickname": row.get("nickname", ""),
                    "is_admin": bool(row.get("is_admin")),
                    "is_disabled": bool(row.get("is_disabled")),
                    "is_deleted": bool(row.get("is_deleted")),
                    "visibility": row.get("visibility", "user"),
                }
            )
        return payload

    @staticmethod
    def _values(collection: str, payload: Resource) -> Resource:
        compat = {
            key: value
            for key, value in payload.items()
            if key not in {"id", "created_at", "updated_at", "created_on", "modified_on"}
        }
        if collection == "access_lists":
            return {
                "name": str(payload.get("name") or ""),
                "satisfy_any": bool(payload.get("satisfy_any")),
                "pass_auth": bool(payload.get("pass_auth")),
                "metadata_json": {"compat": compat},
            }
        if collection == "certificates":
            return {
                "nice_name": str(payload.get("nice_name") or "Certificate"),
                "provider": str(payload.get("provider") or "custom"),
                "challenge_type": payload.get("challenge_type"),
                "key_type": str(payload.get("key_type") or "rsa"),
                "material_ref": payload.get("material_ref"),
                "expires_at": payload.get("expires_at"),
                "status": str(payload.get("status") or "pending"),
                "metadata_json": {"compat": compat},
            }
        if collection == "settings":
            return {
                "key": str(payload.get("key", payload.get("id", ""))),
                "value": payload.get("value", compat),
                "metadata_json": {"compat": compat},
            }
        if collection == "streams":
            if payload.get("tcp_forwarding") and payload.get("udp_forwarding"):
                protocol = "tcp+udp"
            else:
                protocol = "udp" if payload.get("udp_forwarding") else "tcp"
            return {
                "owner_principal_id": payload.get("owner_principal_id"),
                "protocol": protocol,
                "incoming_port": int(payload.get("incoming_port") or 0),
                "target_kind": str(payload.get("target_kind") or "dns"),
                "target": str(payload.get("forwarding_host") or ""),
                "target_port": int(payload.get("forwarding_port") or 0),
                "certificate_id": int(payload.get("certificate_id") or 0) or None,
                "enabled": bool(payload.get("enabled", True)),
                "metadata_json": {"compat": compat},
            }
        if collection == "users":
            return {
                "email": str(payload["email"]).casefold(),
                "display_name": str(payload.get("name", payload.get("display_name", ""))),
                "nickname": str(payload.get("nickname") or ""),
                "is_admin": bool(payload.get("is_admin")),
                "is_disabled": bool(payload.get("is_disabled")),
                "is_deleted": bool(payload.get("is_deleted")),
                "visibility": str(payload.get("visibility") or "user"),
                "metadata_json": {"compat": compat},
            }
        raise ValueError(f"unknown compatibility collection {collection!r}")


__all__ = ["TableResources"]
