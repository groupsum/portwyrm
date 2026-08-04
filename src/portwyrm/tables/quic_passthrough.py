"""Native hostname-routed QUIC passthrough resources."""

from __future__ import annotations

import inspect
import re
from typing import Any, Self

from tigrbl import hook_ctx, op_alias, op_ctx, schema_ctx
from tigrbl.types import (
    BaseModel,
    Boolean,
    CheckConstraint,
    Field,
    Integer,
    String,
    UniqueConstraint,
)

from portwyrm.errors import CollisionError, DomainValidationError
from portwyrm.kernel_support import ConfigDict, model_validator, select

from .base import ManagedPortwyrmTable, acol
from .compat import extension_metadata, extensions
from .routing import TargetKind


async def _await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


_QUIC_KNOWN = {
    "id",
    "listen_address",
    "incoming_port",
    "server_name",
    "alpn",
    "target_kind",
    "target",
    "target_port",
    "idle_timeout_seconds",
    "enabled",
    "owner_principal_id",
    "metadata_json",
}

_DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.I,
)


def canonical_server_name(value: str) -> str:
    name = str(value).strip().rstrip(".").casefold()
    if not _DOMAIN_RE.fullmatch(name):
        raise DomainValidationError(f"invalid QUIC server name: {value!r}")
    return name


def _port(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise DomainValidationError(f"{name} must be between 1 and 65535")
    return value


@op_alias(alias="enable", target="update", arity="member", http_methods=("POST",))
@op_alias(alias="disable", target="update", arity="member", http_methods=("POST",))
class QuicPassthroughRouteStore(ManagedPortwyrmTable):
    """One SNI hostname mapping on a shared UDP listener."""

    __tablename__ = "quic_passthrough_routes"
    __table_args__ = (
        UniqueConstraint("listen_address", "incoming_port", "server_name", name="uq_quic_sni"),
        CheckConstraint("incoming_port BETWEEN 1 AND 65535", name="ck_quic_incoming_port"),
        CheckConstraint("target_port BETWEEN 1 AND 65535", name="ck_quic_target_port"),
        CheckConstraint("target_kind IN ('ip','dns','docker')", name="ck_quic_target_kind"),
    )

    owner_principal_id = acol(Integer, nullable=True, index=True)
    listen_address = acol(String(255), nullable=False, default="0.0.0.0")
    incoming_port = acol(Integer, nullable=False, default=443, index=True)
    server_name = acol(String(253), nullable=False, index=True)
    alpn = acol(String(64), nullable=False, default="h3")
    target_kind = acol(String(16), nullable=False, default="docker")
    target = acol(String(1024), nullable=False)
    target_port = acol(Integer, nullable=False)
    idle_timeout_seconds = acol(Integer, nullable=False, default=1800)
    enabled = acol(Boolean, nullable=False, default=True)

    @schema_ctx(alias="runtime_list", kind="out")
    class RuntimeRoute(BaseModel):
        model_config = ConfigDict(frozen=True, extra="forbid", use_enum_values=True)

        id: int
        listen_address: str = "0.0.0.0"
        incoming_port: int = 443
        server_name: str
        alpn: str = "h3"
        target_kind: TargetKind = TargetKind.DOCKER
        target: str
        target_port: int
        idle_timeout_seconds: int = 1800
        enabled: bool = True
        meta: dict[str, Any] = Field(default_factory=dict)

        @model_validator(mode="after")
        def validate_route(self) -> Self:
            object.__setattr__(self, "server_name", canonical_server_name(self.server_name))
            _port(self.incoming_port, "incoming_port")
            _port(self.target_port, "target_port")
            if not self.target.strip():
                raise DomainValidationError("target is required")
            if self.alpn != "h3":
                raise DomainValidationError("QUIC passthrough currently requires ALPN h3")
            if not 5 <= self.idle_timeout_seconds <= 86400:
                raise DomainValidationError("idle_timeout_seconds must be between 5 and 86400")
            return self

    @hook_ctx(ops=("create", "update", "replace"), phase="PRE_HANDLER")
    async def prepare_route(cls, ctx: dict[str, Any]) -> None:
        payload = dict(ctx.get("payload") or {})
        op = ctx.get("op") or ctx.get("alias") or ""
        alias = str(getattr(op, "alias", op)).casefold()
        if alias == "update" and payload.get("id") is not None:
            row = await _await(ctx["db"].get(cls, int(payload["id"])))
            if row is not None:
                payload = {**cls._wire_projection(row), **payload}
        accepted = set(cls.RuntimeRoute.model_fields) - {"id", "meta"}
        route = cls.RuntimeRoute(
            id=int(payload.get("id") or 0),
            **{key: value for key, value in payload.items() if key in accepted},
        )
        statement = select(cls).where(
            cls.listen_address == route.listen_address,
            cls.incoming_port == route.incoming_port,
            cls.server_name == route.server_name,
        )
        if payload.get("id") is not None:
            statement = statement.where(cls.id != int(payload["id"]))
        if (await _await(ctx["db"].execute(statement))).scalars().first() is not None:
            raise CollisionError(
                f"QUIC route already owns {route.server_name}:{route.incoming_port}/udp"
            )
        normalized = {
            "listen_address": route.listen_address,
            "incoming_port": route.incoming_port,
            "server_name": route.server_name,
            "alpn": route.alpn,
            "target_kind": route.target_kind,
            "target": route.target,
            "target_port": route.target_port,
            "idle_timeout_seconds": route.idle_timeout_seconds,
            "enabled": route.enabled,
            "owner_principal_id": payload.get("owner_principal_id"),
            "metadata_json": payload.get("metadata_json")
            or extension_metadata(payload, _QUIC_KNOWN),
        }
        if payload.get("id") is not None:
            normalized["id"] = int(payload["id"])
        ctx["payload"] = normalized

    @hook_ctx(ops=("create", "update", "replace"), phase="POST_HANDLER")
    def project_mutation(cls, ctx: dict[str, Any]) -> None:
        ctx["result"] = cls._wire_projection(ctx["result"])

    @hook_ctx(ops=("read", "list"), phase="POST_HANDLER")
    def project_read(cls, ctx: dict[str, Any]) -> None:
        result = ctx["result"]
        if isinstance(result, list):
            ctx["result"] = [cls._wire_projection(row) for row in result]
        else:
            ctx["result"] = cls._wire_projection(result)

    HOOKS = (prepare_route, project_mutation, project_read)

    @schema_ctx(alias="runtime_list", kind="out")
    class RuntimeRouteList(BaseModel):
        items: list[QuicPassthroughRouteStore.RuntimeRoute] = Field(default_factory=list)

    @op_ctx(alias="runtime_list", target="custom", arity="collection")
    async def runtime_list(cls, ctx: Any) -> dict[str, Any]:
        rows = list((await _await(ctx["db"].execute(select(cls).order_by(cls.id)))).scalars())
        return {"items": [cls._runtime_projection(row).model_dump(mode="json") for row in rows]}

    @op_ctx(alias="validate", target="custom", arity="collection")
    async def validate(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        accepted = set(cls.RuntimeRoute.model_fields) - {"id", "meta"}
        route = cls.RuntimeRoute(
            id=int(payload.get("id") or 0),
            **{key: value for key, value in payload.items() if key in accepted},
        )
        statement = select(cls).where(
            cls.listen_address == route.listen_address,
            cls.incoming_port == route.incoming_port,
            cls.server_name == route.server_name,
        )
        if payload.get("id"):
            statement = statement.where(cls.id != int(payload["id"]))
        if (await _await(ctx["db"].execute(statement))).scalars().first() is not None:
            raise CollisionError(
                f"QUIC route already owns {route.server_name}:{route.incoming_port}/udp"
            )
        return {"valid": True}

    @classmethod
    def _runtime_projection(cls, row: Any) -> RuntimeRoute:
        return cls.RuntimeRoute(
            id=row.id,
            listen_address=row.listen_address,
            incoming_port=row.incoming_port,
            server_name=row.server_name,
            alpn=row.alpn,
            target_kind=row.target_kind,
            target=row.target,
            target_port=row.target_port,
            idle_timeout_seconds=row.idle_timeout_seconds,
            enabled=bool(row.enabled),
            meta=dict(extensions(row).get("meta") or {}),
        )

    @classmethod
    def _wire_projection(cls, row: Any) -> dict[str, Any]:
        return {
            "id": row.id,
            "listen_address": row.listen_address,
            "incoming_port": row.incoming_port,
            "server_name": row.server_name,
            "alpn": row.alpn,
            "target_kind": row.target_kind,
            "target": row.target,
            "target_port": row.target_port,
            "idle_timeout_seconds": row.idle_timeout_seconds,
            "enabled": bool(row.enabled),
            "owner_principal_id": row.owner_principal_id,
            "meta": dict(extensions(row).get("meta") or {}),
        }


__all__ = ["QuicPassthroughRouteStore", "canonical_server_name"]
