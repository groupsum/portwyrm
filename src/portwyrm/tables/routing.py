"""Reverse proxy, redirect, dead-host, stream, and revision tables."""

from __future__ import annotations

import inspect
from typing import Any

from sqlalchemy import delete, select
from tigrbl import op_ctx
from tigrbl.types import Boolean, Column, ForeignKey, Integer, String, Text, UniqueConstraint

from .base import ManagedPortwyrmTable
from .compat import add_audit, extension_metadata, extensions, iso

_HOST_KNOWN = {
    "id",
    "kind",
    "owner_principal_id",
    "owner_user_id",
    "enabled",
    "certificate_id",
    "ssl_forced",
    "force_ssl",
    "hsts_enabled",
    "hsts_subdomains",
    "http2_support",
    "trust_forwarded_proto",
    "allow_websocket_upgrade",
    "caching_enabled",
    "block_exploits",
    "forward_domain_name",
    "forward_scheme",
    "forward_http_code",
    "preserve_path",
    "advanced_config",
    "domain_names",
    "forward_host",
    "forward_port",
    "target_kind",
    "locations",
    "custom_locations",
    "access_list_id",
    "access_list_ids",
    "created_on",
    "modified_on",
    "created_at",
    "updated_at",
}


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class RoutingHostStore(ManagedPortwyrmTable):
    __tablename__ = "routing_hosts"

    kind = Column(String(32), nullable=False, index=True)
    owner_principal_id = Column(Integer, ForeignKey("principals.id"), nullable=True, index=True)
    enabled = Column(Boolean, nullable=False, default=True)
    certificate_id = Column(Integer, ForeignKey("certificates.id"), nullable=True)
    force_ssl = Column(Boolean, nullable=False, default=False)
    hsts_enabled = Column(Boolean, nullable=False, default=False)
    hsts_subdomains = Column(Boolean, nullable=False, default=False)
    websocket_enabled = Column(Boolean, nullable=False, default=True)
    cache_enabled = Column(Boolean, nullable=False, default=False)
    block_exploits = Column(Boolean, nullable=False, default=True)
    redirect_target = Column(String(1024), nullable=True)
    redirect_scheme = Column(String(16), nullable=True)
    redirect_code = Column(Integer, nullable=True)
    preserve_path = Column(Boolean, nullable=False, default=False)
    advanced_config = Column(Text, nullable=False, default="")

    @op_ctx(alias="create_compat", target="custom", arity="collection")
    async def create_compat(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        row = cls(**cls._host_values(payload))
        ctx["db"].add(row)
        await _await(ctx["db"].flush())
        await cls._replace_children(ctx["db"], row.id, payload)
        result = await cls._project(ctx["db"], row)
        await add_audit(
            ctx["db"],
            action="created",
            object_type=cls._collection(row.kind),
            object_id=row.id,
            details=result,
        )
        return result

    @op_ctx(alias="update_compat", target="custom", arity="collection")
    async def update_compat(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        result = await _await(
            ctx["db"].execute(select(cls).where(cls.id == int(payload.pop("id"))))
        )
        row = result.scalar_one_or_none()
        if row is None:
            raise ValueError("routing host not found")
        for key, value in cls._host_values(payload).items():
            setattr(row, key, value)
        await cls._replace_children(ctx["db"], row.id, payload)
        result = await cls._project(ctx["db"], row)
        await add_audit(
            ctx["db"],
            action="updated",
            object_type=cls._collection(row.kind),
            object_id=row.id,
            details=result,
        )
        return result

    @op_ctx(alias="delete_compat", target="custom", arity="collection")
    async def delete_compat(cls, ctx: Any) -> dict[str, Any]:
        host_id = int((ctx.get("payload") or {})["id"])
        await cls._replace_children(ctx["db"], host_id, {})
        kind = (
            await _await(ctx["db"].execute(select(cls.kind).where(cls.id == host_id)))
        ).scalar_one_or_none()
        result = await _await(ctx["db"].execute(delete(cls).where(cls.id == host_id)))
        if result.rowcount:
            await add_audit(
                ctx["db"],
                action="deleted",
                object_type=cls._collection(kind or "proxy"),
                object_id=host_id,
            )
        return {"deleted": bool(result.rowcount), "id": host_id}

    @op_ctx(alias="compat_list", target="custom", arity="collection")
    async def compat_list(cls, ctx: Any) -> list[dict[str, Any]]:
        payload = dict(ctx.get("payload") or {})
        statement = select(cls).order_by(cls.id)
        if payload.get("kind"):
            statement = statement.where(cls.kind == str(payload["kind"]))
        rows = list((await _await(ctx["db"].execute(statement))).scalars())
        return [await cls._project(ctx["db"], row) for row in rows]

    @op_ctx(alias="compat_read", target="custom", arity="collection")
    async def compat_read(cls, ctx: Any) -> dict[str, Any]:
        host_id = int((ctx.get("payload") or {})["id"])
        row = (
            await _await(ctx["db"].execute(select(cls).where(cls.id == host_id)))
        ).scalar_one_or_none()
        if row is None:
            raise ValueError("routing host not found")
        return await cls._project(ctx["db"], row)

    @staticmethod
    def _host_values(payload: dict[str, Any]) -> dict[str, Any]:
        kind = str(payload.get("kind") or "proxy")
        certificate_id = int(payload.get("certificate_id") or 0) or None
        return {
            "kind": kind,
            "owner_principal_id": payload.get("owner_principal_id"),
            "enabled": bool(payload.get("enabled", True)),
            "certificate_id": certificate_id,
            "force_ssl": bool(payload.get("ssl_forced", payload.get("force_ssl", False))),
            "hsts_enabled": bool(payload.get("hsts_enabled", False)),
            "hsts_subdomains": bool(payload.get("hsts_subdomains", False)),
            "websocket_enabled": bool(payload.get("allow_websocket_upgrade", True)),
            "cache_enabled": bool(payload.get("caching_enabled", False)),
            "block_exploits": bool(payload.get("block_exploits", True)),
            "redirect_target": payload.get("forward_domain_name"),
            "redirect_scheme": payload.get("forward_scheme"),
            "redirect_code": payload.get("forward_http_code"),
            "preserve_path": bool(payload.get("preserve_path", False)),
            "advanced_config": str(payload.get("advanced_config") or ""),
            "metadata_json": extension_metadata(payload, _HOST_KNOWN),
        }

    @staticmethod
    async def _replace_children(db: Any, host_id: int, payload: dict[str, Any]) -> None:
        for table in (
            RoutingSourceStore,
            RoutingUpstreamStore,
            RoutingLocationStore,
            RoutingHostAccessListStore,
        ):
            await _await(db.execute(delete(table).where(table.routing_host_id == host_id)))
        for domain in payload.get("domain_names") or []:
            db.add(RoutingSourceStore(routing_host_id=host_id, domain_name=str(domain)))
        if payload.get("forward_host"):
            db.add(
                RoutingUpstreamStore(
                    routing_host_id=host_id,
                    protocol=str(payload.get("forward_scheme") or "http"),
                    target_kind=str(payload.get("target_kind") or "dns"),
                    target=str(payload["forward_host"]),
                    port=int(payload.get("forward_port") or 80),
                    position=0,
                    weight=1,
                )
            )
        for position, location in enumerate(
            payload.get("locations", payload.get("custom_locations", [])) or []
        ):
            db.add(
                RoutingLocationStore(
                    routing_host_id=host_id,
                    path=str(location.get("path") or "/"),
                    protocol=str(location.get("forward_scheme") or "http"),
                    target_kind=str(location.get("target_kind") or "dns"),
                    target=str(location.get("forward_host") or ""),
                    port=int(location.get("forward_port") or 80),
                    forward_path=str(location.get("forward_path") or ""),
                    advanced_config=str(location.get("advanced_config") or ""),
                    metadata_json={"position": position},
                )
            )
        access_ids = payload.get("access_list_ids")
        if access_ids is None:
            access_ids = [payload["access_list_id"]] if payload.get("access_list_id") else []
        for access_id in access_ids:
            db.add(
                RoutingHostAccessListStore(
                    routing_host_id=host_id,
                    access_list_id=int(access_id),
                )
            )

    @staticmethod
    def _collection(kind: str) -> str:
        return {"proxy": "proxy_hosts", "redirect": "redirection_hosts", "dead": "dead_hosts"}.get(
            kind, "proxy_hosts"
        )

    @classmethod
    async def _project(cls, db: Any, row: Any) -> dict[str, Any]:
        sources = list(
            (
                await _await(
                    db.execute(
                        select(RoutingSourceStore)
                        .where(RoutingSourceStore.routing_host_id == row.id)
                        .order_by(RoutingSourceStore.id)
                    )
                )
            ).scalars()
        )
        upstreams = list(
            (
                await _await(
                    db.execute(
                        select(RoutingUpstreamStore)
                        .where(RoutingUpstreamStore.routing_host_id == row.id)
                        .order_by(RoutingUpstreamStore.position, RoutingUpstreamStore.id)
                    )
                )
            ).scalars()
        )
        locations = list(
            (
                await _await(
                    db.execute(
                        select(RoutingLocationStore)
                        .where(RoutingLocationStore.routing_host_id == row.id)
                        .order_by(RoutingLocationStore.id)
                    )
                )
            ).scalars()
        )
        access_ids = list(
            (
                await _await(
                    db.execute(
                        select(RoutingHostAccessListStore.access_list_id)
                        .where(RoutingHostAccessListStore.routing_host_id == row.id)
                        .order_by(RoutingHostAccessListStore.id)
                    )
                )
            ).scalars()
        )
        first = upstreams[0] if upstreams else None
        result = extensions(row)
        result.update(
            {
                "id": row.id,
                "kind": row.kind,
                "owner_user_id": row.owner_principal_id,
                "owner_principal_id": row.owner_principal_id,
                "enabled": int(row.enabled),
                "certificate_id": row.certificate_id or 0,
                "ssl_forced": bool(row.force_ssl),
                "hsts_enabled": bool(row.hsts_enabled),
                "hsts_subdomains": bool(row.hsts_subdomains),
                "allow_websocket_upgrade": bool(row.websocket_enabled),
                "caching_enabled": bool(row.cache_enabled),
                "block_exploits": bool(row.block_exploits),
                "advanced_config": row.advanced_config,
                "domain_names": [item.domain_name for item in sources],
                "forward_scheme": first.protocol if first else (row.redirect_scheme or "http"),
                "forward_host": first.target if first else None,
                "forward_port": first.port if first else None,
                "target_kind": first.target_kind if first else None,
                "forward_domain_name": row.redirect_target,
                "forward_http_code": row.redirect_code,
                "preserve_path": bool(row.preserve_path),
                "access_list_ids": access_ids,
                "access_list_id": access_ids[0] if access_ids else 0,
                "locations": [
                    {
                        "path": item.path,
                        "forward_scheme": item.protocol,
                        "target_kind": item.target_kind,
                        "forward_host": item.target,
                        "forward_port": item.port,
                        "forward_path": item.forward_path,
                        "advanced_config": item.advanced_config,
                    }
                    for item in locations
                ],
                "created_on": iso(row.created_at),
                "modified_on": iso(row.updated_at),
            }
        )
        return result

    @op_ctx(alias="preview", target="custom", arity="member")
    def preview(cls, ctx: Any) -> dict[str, Any]:
        callback = getattr(getattr(getattr(ctx, "app", None), "state", None), "preview_host", None)
        return callback(ctx) if callable(callback) else {"status": "preview-unavailable"}


class RoutingSourceStore(ManagedPortwyrmTable):
    __tablename__ = "routing_sources"
    __table_args__ = (
        UniqueConstraint("routing_host_id", "domain_name", name="uq_routing_source_domain"),
    )
    routing_host_id = Column(Integer, ForeignKey("routing_hosts.id"), nullable=False, index=True)
    domain_name = Column(String(253), nullable=False, index=True)


class RoutingUpstreamStore(ManagedPortwyrmTable):
    __tablename__ = "routing_upstreams"
    routing_host_id = Column(Integer, ForeignKey("routing_hosts.id"), nullable=False, index=True)
    protocol = Column(String(16), nullable=False, default="http")
    target_kind = Column(String(16), nullable=False)
    target = Column(String(1024), nullable=False)
    port = Column(Integer, nullable=False)
    position = Column(Integer, nullable=False, default=0)
    weight = Column(Integer, nullable=False, default=1)


class RoutingLocationStore(ManagedPortwyrmTable):
    __tablename__ = "routing_locations"
    __table_args__ = (UniqueConstraint("routing_host_id", "path", name="uq_routing_location_path"),)
    routing_host_id = Column(Integer, ForeignKey("routing_hosts.id"), nullable=False, index=True)
    path = Column(String(1024), nullable=False)
    protocol = Column(String(16), nullable=False, default="http")
    target_kind = Column(String(16), nullable=False)
    target = Column(String(1024), nullable=False)
    port = Column(Integer, nullable=False)
    forward_path = Column(String(1024), nullable=False, default="")
    advanced_config = Column(Text, nullable=False, default="")


class RoutingHostAccessListStore(ManagedPortwyrmTable):
    __tablename__ = "routing_host_access_lists"
    __table_args__ = (
        UniqueConstraint("routing_host_id", "access_list_id", name="uq_routing_host_access_list"),
    )
    routing_host_id = Column(Integer, ForeignKey("routing_hosts.id"), nullable=False, index=True)
    access_list_id = Column(Integer, ForeignKey("access_lists.id"), nullable=False, index=True)


class StreamRouteStore(ManagedPortwyrmTable):
    __tablename__ = "stream_routes"
    owner_principal_id = Column(Integer, ForeignKey("principals.id"), nullable=True, index=True)
    protocol = Column(String(8), nullable=False)
    incoming_port = Column(Integer, nullable=False, index=True)
    target_kind = Column(String(16), nullable=False)
    target = Column(String(1024), nullable=False)
    target_port = Column(Integer, nullable=False)
    enabled = Column(Boolean, nullable=False, default=True)


class HostConfigRevisionStore(ManagedPortwyrmTable):
    __tablename__ = "config_revisions"
    __table_args__ = (UniqueConstraint("routing_host_id", "generation", name="uq_host_generation"),)
    routing_host_id = Column(Integer, ForeignKey("routing_hosts.id"), nullable=False, index=True)
    generation = Column(String(64), nullable=False)
    config_text = Column(Text, nullable=False)
    config_digest = Column(String(64), nullable=False)
    applied = Column(Boolean, nullable=False, default=False)
    applied_at = Column(Integer, nullable=True)

    @op_ctx(alias="compare", target="custom", arity="member")
    def compare(cls, ctx: Any) -> dict[str, Any]:
        callback = getattr(
            getattr(getattr(ctx, "app", None), "state", None),
            "compare_revisions",
            None,
        )
        return callback(ctx) if callable(callback) else {"status": "compare-unavailable"}


RoutingHost = RoutingHostStore
RoutingSource = RoutingSourceStore
RoutingUpstream = RoutingUpstreamStore
RoutingHostAccessList = RoutingHostAccessListStore
StreamRoute = StreamRouteStore
ConfigRevision = HostConfigRevisionStore

__all__ = [
    "ConfigRevision",
    "HostConfigRevisionStore",
    "RoutingHost",
    "RoutingHostAccessList",
    "RoutingHostAccessListStore",
    "RoutingHostStore",
    "RoutingLocationStore",
    "RoutingSource",
    "RoutingSourceStore",
    "RoutingUpstream",
    "RoutingUpstreamStore",
    "StreamRoute",
    "StreamRouteStore",
]
