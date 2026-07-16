"""Reverse proxy, redirect, dead-host, stream, and revision tables."""

from __future__ import annotations

import hashlib
import inspect
import ipaddress
import re
from collections.abc import Iterable
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator
from sqlalchemy import CheckConstraint, delete, select
from tigrbl import op_ctx, schema_ctx
from tigrbl.types import (
    BaseModel,
    Boolean,
    Column,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from portwyrm.errors import CollisionError, DomainValidationError

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

_DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?=.{1,253}\.?$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.I,
)


class HostKind(StrEnum):
    PROXY = "proxy"
    REDIRECT = "redirect"
    DEAD = "dead"


class ForwardScheme(StrEnum):
    HTTP = "http"
    HTTPS = "https"


class RedirectScheme(StrEnum):
    AUTO = "auto"
    HTTP = "http"
    HTTPS = "https"


class TargetKind(StrEnum):
    IP = "ip"
    DNS = "dns"
    DOCKER = "docker"


class StreamProtocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    TCP_UDP = "tcp+udp"


def canonical_domains(values: Iterable[str]) -> tuple[str, ...]:
    domains: list[str] = []
    seen: set[str] = set()
    for raw in values:
        if not isinstance(raw, str):
            raise DomainValidationError("domain names must be strings")
        domain = raw.strip().rstrip(".").casefold()
        if not _DOMAIN_RE.fullmatch(domain):
            raise DomainValidationError(f"invalid domain name: {raw!r}")
        if domain in seen:
            raise DomainValidationError(f"duplicate domain name: {domain}")
        seen.add(domain)
        domains.append(domain)
    if not 1 <= len(domains) <= 100:
        raise DomainValidationError("resources require between 1 and 100 domain names")
    return tuple(domains)


def _port(value: int, name: str = "port") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise DomainValidationError(f"{name} must be between 1 and 65535")
    return value


def _target(value: str, kind: TargetKind, name: str = "target") -> str:
    target = value.strip()
    if not target:
        raise DomainValidationError(f"{name} is required")
    if kind == TargetKind.IP:
        try:
            return str(ipaddress.ip_address(target))
        except ValueError as exc:
            raise DomainValidationError(f"{name} must be an IPv4 or IPv6 address") from exc
    if kind == TargetKind.DNS:
        normalized = target.rstrip(".").casefold()
        labels = normalized.split(".")
        if (
            len(normalized) > 253
            or any(not label or len(label) > 63 for label in labels)
            or any(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) is None for label in labels
            )
        ):
            raise DomainValidationError(f"{name} must be a valid DNS hostname")
        return normalized
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", target) is None:
        raise DomainValidationError(f"{name} must be a valid Docker service/container name")
    return target


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class RoutingHostStore(ManagedPortwyrmTable):
    __tablename__ = "routing_hosts"
    __table_args__ = (
        CheckConstraint("kind IN ('proxy','redirect','dead')", name="ck_routing_host_kind"),
        CheckConstraint(
            "redirect_scheme IS NULL OR redirect_scheme IN ('auto','http','https')",
            name="ck_routing_host_redirect_scheme",
        ),
        CheckConstraint(
            "redirect_code IS NULL OR redirect_code IN (301,302,307,308)",
            name="ck_routing_host_redirect_code",
        ),
        CheckConstraint(
            "NOT force_ssl OR certificate_id IS NOT NULL",
            name="ck_routing_host_force_ssl_certificate",
        ),
        CheckConstraint(
            "NOT hsts_enabled OR force_ssl",
            name="ck_routing_host_hsts_force_ssl",
        ),
        CheckConstraint(
            "NOT hsts_subdomains OR hsts_enabled",
            name="ck_routing_host_hsts_subdomains",
        ),
    )

    class TLSSettings(BaseModel):
        model_config = ConfigDict(frozen=True, extra="forbid")

        certificate_id: int = 0
        forced: bool = False
        http2: bool = False
        hsts: bool = False
        hsts_subdomains: bool = False
        trust_forwarded_proto: bool = False

        def normalized(self) -> Self:
            certificate_id = int(self.certificate_id or 0)
            if certificate_id < 0:
                raise DomainValidationError("certificate_id cannot be negative")
            if certificate_id == 0:
                return type(self)()
            forced = bool(self.forced)
            hsts = forced and bool(self.hsts)
            return type(self)(
                certificate_id=certificate_id,
                forced=forced,
                http2=bool(self.http2),
                hsts=hsts,
                hsts_subdomains=hsts and bool(self.hsts_subdomains),
                trust_forwarded_proto=forced and bool(self.trust_forwarded_proto),
            )

    class RuntimeLocation(BaseModel):
        model_config = ConfigDict(frozen=True, extra="forbid")

        path: str
        forward_scheme: ForwardScheme = ForwardScheme.HTTP
        target_kind: TargetKind = TargetKind.DNS
        forward_host: str
        forward_port: int
        forward_path: str = ""
        advanced_config: str = ""

        @model_validator(mode="after")
        def validate_location(self) -> Self:
            if not self.path.startswith("/"):
                raise DomainValidationError("location path must start with /")
            if not self.forward_host.strip():
                raise DomainValidationError("location forward_host is required")
            object.__setattr__(
                self,
                "forward_host",
                _target(self.forward_host, self.target_kind, "location forward_host"),
            )
            _port(self.forward_port, "location forward_port")
            if self.forward_path and not self.forward_path.startswith("/"):
                raise DomainValidationError("location forward_path must start with /")
            return self

    @schema_ctx(alias="runtime_read", kind="out")
    class RuntimeHost(BaseModel):
        model_config = ConfigDict(frozen=True, extra="forbid", use_enum_values=True)

        id: int
        kind: HostKind
        domain_names: tuple[str, ...]
        forward_scheme: ForwardScheme | RedirectScheme = ForwardScheme.HTTP
        forward_host: str | None = None
        forward_port: int | None = None
        forward_domain_name: str | None = None
        forward_http_code: int = 301
        preserve_path: bool = False
        owner_user_id: int = 1
        access_list_id: int = 0
        access_list_ids: tuple[int, ...] = ()
        ssl: RoutingHostStore.TLSSettings = Field(
            default_factory=lambda: RoutingHostStore.TLSSettings()
        )
        caching_enabled: bool = False
        block_exploits: bool = False
        allow_websocket_upgrade: bool = False
        advanced_config: str = ""
        locations: tuple[RoutingHostStore.RuntimeLocation, ...] = ()
        enabled: bool = True
        meta: dict[str, Any] = Field(default_factory=dict)

        @field_validator("domain_names", mode="before")
        @classmethod
        def normalize_domains(cls, value: Any) -> tuple[str, ...]:
            return canonical_domains(value or [])

        @model_validator(mode="after")
        def validate_host(self) -> Self:
            if self.id <= 0 or self.owner_user_id <= 0:
                raise DomainValidationError("host and owner IDs must be positive")
            if any(value <= 0 for value in self.access_list_ids):
                raise DomainValidationError("access_list_ids must contain positive IDs")
            if len(self.access_list_ids) != len(set(self.access_list_ids)):
                raise DomainValidationError("access_list_ids must be unique")
            if self.kind == HostKind.PROXY:
                if not (self.forward_host or "").strip():
                    raise DomainValidationError("forward_host is required")
                _port(int(self.forward_port or 0), "forward_port")
            elif self.kind == HostKind.REDIRECT:
                target = (self.forward_domain_name or "").strip().rstrip(".").casefold()
                if not _DOMAIN_RE.fullmatch(target):
                    raise DomainValidationError("forward_domain_name must be a valid domain")
                if self.forward_http_code not in {301, 302, 307, 308}:
                    raise DomainValidationError(
                        "forward_http_code must be one of 301, 302, 307, or 308"
                    )
                object.__setattr__(self, "forward_domain_name", target)
            paths = [location.path for location in self.locations]
            if len(paths) != len(set(paths)):
                raise DomainValidationError("proxy location paths must be unique")
            object.__setattr__(self, "ssl", self.ssl.normalized())
            return self

    @schema_ctx(alias="runtime_list", kind="out")
    class RuntimeHostList(BaseModel):
        items: list[RoutingHostStore.RuntimeHost] = Field(default_factory=list)

    @schema_ctx(alias="preview", kind="out")
    class PreviewResult(BaseModel):
        path: str
        config: str
        digest: str
        warnings: list[str] = Field(default_factory=list)

    kind = Column(String(32), nullable=False, index=True)
    owner_principal_id = Column(Integer, ForeignKey("principals.id"), nullable=True, index=True)
    enabled = Column(Boolean, nullable=False, default=True)
    certificate_id = Column(Integer, ForeignKey("certificates.id"), nullable=True)
    force_ssl = Column(Boolean, nullable=False, default=False)
    hsts_enabled = Column(Boolean, nullable=False, default=False)
    hsts_subdomains = Column(Boolean, nullable=False, default=False)
    http2_enabled = Column(Boolean, nullable=False, default=False)
    trust_forwarded_proto = Column(Boolean, nullable=False, default=False)
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
        cls._validate_payload(payload)
        await cls._assert_source_collisions(ctx["db"], payload.get("domain_names") or [])
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
        cls._validate_payload(payload)
        await cls._assert_source_collisions(
            ctx["db"], payload.get("domain_names") or [], exclude_host_id=row.id
        )
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

    @op_ctx(alias="runtime_list", target="custom", arity="collection")
    async def runtime_list(cls, ctx: Any) -> dict[str, Any]:
        rows = list((await _await(ctx["db"].execute(select(cls).order_by(cls.id)))).scalars())
        return {
            "items": [
                cls.RuntimeHost.model_validate(
                    await cls._runtime_projection(ctx["db"], row)
                ).model_dump(mode="json")
                for row in rows
            ]
        }

    @op_ctx(alias="runtime_read", target="custom", arity="collection")
    async def runtime_read(cls, ctx: Any) -> dict[str, Any]:
        host_id = int((ctx.get("payload") or {})["id"])
        row = await _await(ctx["db"].get(cls, host_id))
        if row is None:
            raise ValueError("routing host not found")
        return cls.RuntimeHost.model_validate(
            await cls._runtime_projection(ctx["db"], row)
        ).model_dump(mode="json")

    @op_ctx(alias="validate", target="custom", arity="collection")
    async def validate(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        cls._validate_payload(payload)
        await cls._assert_source_collisions(
            ctx["db"], payload.get("domain_names") or [], exclude_host_id=payload.get("id")
        )
        return {"valid": True}

    @staticmethod
    def _validate_payload(payload: dict[str, Any]) -> None:
        kind = HostKind(str(payload.get("kind") or "proxy"))
        domains = canonical_domains(payload.get("domain_names") or [])
        payload["domain_names"] = list(domains)
        if kind == HostKind.PROXY:
            ForwardScheme(str(payload.get("forward_scheme") or "http"))
            target_kind = TargetKind(str(payload.get("target_kind") or "dns"))
            payload["forward_host"] = _target(
                str(payload.get("forward_host") or ""), target_kind, "forward_host"
            )
            _port(int(payload.get("forward_port") or 0), "forward_port")
        elif kind == HostKind.REDIRECT:
            RedirectScheme(str(payload.get("forward_scheme") or "auto"))
            target = str(payload.get("forward_domain_name") or "").strip().rstrip(".").casefold()
            if not _DOMAIN_RE.fullmatch(target):
                raise DomainValidationError("forward_domain_name must be a valid domain")
            payload["forward_domain_name"] = target
            code = int(payload.get("forward_http_code") or 301)
            if code not in {301, 302, 307, 308}:
                raise DomainValidationError(
                    "forward_http_code must be one of 301, 302, 307, or 308"
                )
        certificate_id = int(payload.get("certificate_id") or 0)
        force_ssl = bool(payload.get("ssl_forced", payload.get("force_ssl", False)))
        hsts_enabled = bool(payload.get("hsts_enabled", False))
        hsts_subdomains = bool(payload.get("hsts_subdomains", False))
        if force_ssl and not certificate_id:
            raise DomainValidationError("forced HTTPS requires a certificate")
        if hsts_enabled and (not force_ssl or not certificate_id):
            raise DomainValidationError("HSTS requires forced HTTPS and a certificate")
        if hsts_subdomains and not hsts_enabled:
            raise DomainValidationError("HSTS subdomains require HSTS")
        access_ids = payload.get("access_list_ids") or []
        if len(access_ids) != len({int(value) for value in access_ids}):
            raise DomainValidationError("access_list_ids must be unique")
        if any(int(value) <= 0 for value in access_ids):
            raise DomainValidationError("access_list_ids must contain positive IDs")
        paths = [str(item.get("path") or "/") for item in payload.get("locations") or []]
        if len(paths) != len(set(paths)):
            raise DomainValidationError("proxy location paths must be unique")

    @classmethod
    async def _assert_source_collisions(
        cls,
        db: Any,
        domains: Iterable[str],
        *,
        exclude_host_id: int | None = None,
    ) -> None:
        normalized = canonical_domains(domains)
        statement = select(RoutingSourceStore).where(RoutingSourceStore.domain_name.in_(normalized))
        if exclude_host_id is not None:
            statement = statement.where(RoutingSourceStore.routing_host_id != int(exclude_host_id))
        existing = (await _await(db.execute(statement))).scalars().first()
        if existing is not None:
            raise CollisionError(
                f"domain {existing.domain_name} is already used by routing host "
                f"{existing.routing_host_id}"
            )

    @staticmethod
    def _host_values(payload: dict[str, Any]) -> dict[str, Any]:
        kind = HostKind(str(payload.get("kind") or "proxy")).value
        certificate_id = int(payload.get("certificate_id") or 0) or None
        force_ssl = bool(payload.get("ssl_forced", payload.get("force_ssl", False))) and bool(
            certificate_id
        )
        hsts_enabled = force_ssl and bool(payload.get("hsts_enabled", False))
        return {
            "kind": kind,
            "owner_principal_id": payload.get("owner_principal_id"),
            "enabled": bool(payload.get("enabled", True)),
            "certificate_id": certificate_id,
            "force_ssl": force_ssl,
            "hsts_enabled": hsts_enabled,
            "hsts_subdomains": hsts_enabled and bool(payload.get("hsts_subdomains", False)),
            "http2_enabled": bool(payload.get("http2_support", False)),
            "trust_forwarded_proto": force_ssl
            and bool(payload.get("trust_forwarded_proto", False)),
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
        domains = payload.get("domain_names") or []
        if domains:
            for domain in canonical_domains(domains):
                db.add(RoutingSourceStore(routing_host_id=host_id, domain_name=domain))
        if payload.get("forward_host"):
            protocol = ForwardScheme(str(payload.get("forward_scheme") or "http")).value
            target_kind = TargetKind(str(payload.get("target_kind") or "dns")).value
            port = _port(int(payload.get("forward_port") or 80), "forward_port")
            db.add(
                RoutingUpstreamStore(
                    routing_host_id=host_id,
                    protocol=protocol,
                    target_kind=target_kind,
                    target=str(payload["forward_host"]),
                    port=port,
                    position=0,
                    weight=1,
                )
            )
        for position, location in enumerate(
            payload.get("locations", payload.get("custom_locations", [])) or []
        ):
            runtime_location = RoutingHostStore.RuntimeLocation.model_validate(
                {
                    "path": str(location.get("path") or "/"),
                    "forward_scheme": str(location.get("forward_scheme") or "http"),
                    "target_kind": str(location.get("target_kind") or "dns"),
                    "forward_host": str(location.get("forward_host") or ""),
                    "forward_port": int(location.get("forward_port") or 80),
                    "forward_path": str(location.get("forward_path") or ""),
                    "advanced_config": str(location.get("advanced_config") or ""),
                }
            )
            db.add(
                RoutingLocationStore(
                    routing_host_id=host_id,
                    path=runtime_location.path,
                    protocol=str(runtime_location.forward_scheme),
                    target_kind=str(runtime_location.target_kind),
                    target=runtime_location.forward_host,
                    port=runtime_location.forward_port,
                    forward_path=runtime_location.forward_path,
                    advanced_config=runtime_location.advanced_config,
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
                "http2_support": bool(row.http2_enabled),
                "trust_forwarded_proto": bool(row.trust_forwarded_proto),
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

    @classmethod
    async def _runtime_projection(cls, db: Any, row: Any) -> dict[str, Any]:
        projected = await cls._project(db, row)
        return {
            "id": projected["id"],
            "kind": projected["kind"],
            "domain_names": projected["domain_names"],
            "forward_scheme": projected.get("forward_scheme") or "http",
            "forward_host": projected.get("forward_host"),
            "forward_port": projected.get("forward_port"),
            "forward_domain_name": projected.get("forward_domain_name"),
            "forward_http_code": projected.get("forward_http_code") or 301,
            "preserve_path": bool(projected.get("preserve_path")),
            "owner_user_id": int(projected.get("owner_principal_id") or 1),
            "access_list_id": int(projected.get("access_list_id") or 0),
            "access_list_ids": projected.get("access_list_ids") or [],
            "ssl": {
                "certificate_id": int(projected.get("certificate_id") or 0),
                "forced": bool(projected.get("ssl_forced")),
                "http2": bool(projected.get("http2_support")),
                "hsts": bool(projected.get("hsts_enabled")),
                "hsts_subdomains": bool(projected.get("hsts_subdomains")),
                "trust_forwarded_proto": bool(projected.get("trust_forwarded_proto")),
            },
            "caching_enabled": bool(projected.get("caching_enabled")),
            "block_exploits": bool(projected.get("block_exploits")),
            "allow_websocket_upgrade": bool(projected.get("allow_websocket_upgrade")),
            "advanced_config": str(projected.get("advanced_config") or ""),
            "locations": projected.get("locations") or [],
            "enabled": bool(projected.get("enabled")),
            "meta": dict(row.metadata_json or {}),
        }

    @op_ctx(alias="preview", target="custom", arity="member")
    async def preview(cls, ctx: Any) -> dict[str, Any]:
        from portwyrm.runtime.nginx import NginxRenderer
        from portwyrm.runtime.nginx_primitives import merge_access_lists
        from portwyrm.tables.access import AccessListStore

        host_id = int((ctx.get("payload") or {})["id"])
        row = await _await(ctx["db"].get(cls, host_id))
        if row is None:
            raise ValueError("routing host not found")
        host = cls.RuntimeHost.model_validate(await cls._runtime_projection(ctx["db"], row))
        selected_ids = host.access_list_ids or (
            (host.access_list_id,) if host.access_list_id else ()
        )
        access_rows = []
        if selected_ids:
            access_rows = list(
                (
                    await _await(
                        ctx["db"].execute(
                            select(AccessListStore).where(AccessListStore.id.in_(selected_ids))
                        )
                    )
                ).scalars()
            )
        access_lists = [
            AccessListStore._runtime_projection(
                access_row,
                await AccessListStore._project(ctx["db"], access_row, include_hashes=True),
            )
            for access_row in access_rows
        ]
        effective_access = merge_access_lists(access_lists)
        password_file = f"proxy-host-{host.id}" if len(access_lists) > 1 else None
        renderer = NginxRenderer()
        if host.kind == HostKind.PROXY:
            path = f"http/proxy-{host.id}.conf"
            config = renderer.render_proxy(host, effective_access, password_file)
        elif host.kind == HostKind.REDIRECT:
            path = f"http/redirection-{host.id}.conf"
            config = renderer.render_redirection(host)
        else:
            path = f"http/dead-{host.id}.conf"
            config = renderer.render_dead(host)
        missing = sorted(set(selected_ids) - {access.id for access in access_lists})
        return {
            "path": path,
            "config": config,
            "digest": hashlib.sha256(config.encode()).hexdigest(),
            "warnings": [f"access list {item} was not found" for item in missing],
        }


class RoutingSourceStore(ManagedPortwyrmTable):
    __tablename__ = "routing_sources"
    __table_args__ = (
        UniqueConstraint("domain_name", name="uq_routing_source_domain"),
        CheckConstraint("domain_name = lower(domain_name)", name="ck_routing_source_lowercase"),
    )
    routing_host_id = Column(Integer, ForeignKey("routing_hosts.id"), nullable=False, index=True)
    domain_name = Column(String(253), nullable=False, index=True)


class RoutingUpstreamStore(ManagedPortwyrmTable):
    __tablename__ = "routing_upstreams"
    __table_args__ = (
        CheckConstraint("protocol IN ('http','https')", name="ck_routing_upstream_protocol"),
        CheckConstraint("target_kind IN ('ip','dns','docker')", name="ck_routing_upstream_target"),
        CheckConstraint("port BETWEEN 1 AND 65535", name="ck_routing_upstream_port"),
        CheckConstraint("weight > 0", name="ck_routing_upstream_weight"),
    )
    routing_host_id = Column(Integer, ForeignKey("routing_hosts.id"), nullable=False, index=True)
    protocol = Column(String(16), nullable=False, default="http")
    target_kind = Column(String(16), nullable=False)
    target = Column(String(1024), nullable=False)
    port = Column(Integer, nullable=False)
    position = Column(Integer, nullable=False, default=0)
    weight = Column(Integer, nullable=False, default=1)


class RoutingLocationStore(ManagedPortwyrmTable):
    __tablename__ = "routing_locations"
    __table_args__ = (
        UniqueConstraint("routing_host_id", "path", name="uq_routing_location_path"),
        CheckConstraint("protocol IN ('http','https')", name="ck_routing_location_protocol"),
        CheckConstraint("target_kind IN ('ip','dns','docker')", name="ck_routing_location_target"),
        CheckConstraint("port BETWEEN 1 AND 65535", name="ck_routing_location_port"),
    )
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
    __table_args__ = (
        UniqueConstraint("incoming_port", "protocol", name="uq_stream_port_protocol"),
        CheckConstraint("protocol IN ('tcp','udp','tcp+udp')", name="ck_stream_protocol"),
        CheckConstraint("target_kind IN ('ip','dns','docker')", name="ck_stream_target_kind"),
        CheckConstraint("incoming_port BETWEEN 1 AND 65535", name="ck_stream_incoming_port"),
        CheckConstraint("target_port BETWEEN 1 AND 65535", name="ck_stream_target_port"),
        CheckConstraint(
            "certificate_id IS NULL OR protocol IN ('tcp','tcp+udp')",
            name="ck_stream_tls_tcp",
        ),
    )
    owner_principal_id = Column(Integer, ForeignKey("principals.id"), nullable=True, index=True)
    protocol = Column(String(8), nullable=False)
    incoming_port = Column(Integer, nullable=False, index=True)
    target_kind = Column(String(16), nullable=False)
    target = Column(String(1024), nullable=False)
    target_port = Column(Integer, nullable=False)
    certificate_id = Column(Integer, ForeignKey("certificates.id"), nullable=True)
    enabled = Column(Boolean, nullable=False, default=True)

    @schema_ctx(alias="runtime_read", kind="out")
    class RuntimeStream(BaseModel):
        model_config = ConfigDict(frozen=True, extra="forbid", use_enum_values=True)

        id: int
        incoming_port: int
        forwarding_host: str
        forwarding_port: int
        protocol: StreamProtocol
        target_kind: TargetKind = TargetKind.DNS
        owner_user_id: int = 1
        certificate_id: int = 0
        enabled: bool = True
        meta: dict[str, Any] = Field(default_factory=dict)

        @model_validator(mode="after")
        def validate_stream(self) -> Self:
            _port(self.incoming_port, "incoming_port")
            _port(self.forwarding_port, "forwarding_port")
            if not self.forwarding_host.strip():
                raise DomainValidationError("forwarding_host is required")
            object.__setattr__(
                self,
                "forwarding_host",
                _target(self.forwarding_host, self.target_kind, "forwarding_host"),
            )
            if self.certificate_id < 0:
                raise DomainValidationError("certificate_id cannot be negative")
            if self.certificate_id and self.protocol == StreamProtocol.UDP:
                raise DomainValidationError("stream TLS is supported only for TCP")
            return self

        @property
        def tcp_forwarding(self) -> bool:
            return self.protocol in {StreamProtocol.TCP, StreamProtocol.TCP_UDP, "tcp", "tcp+udp"}

        @property
        def udp_forwarding(self) -> bool:
            return self.protocol in {StreamProtocol.UDP, StreamProtocol.TCP_UDP, "udp", "tcp+udp"}

    @schema_ctx(alias="runtime_list", kind="out")
    class RuntimeStreamList(BaseModel):
        items: list[StreamRouteStore.RuntimeStream] = Field(default_factory=list)

    @op_ctx(alias="runtime_list", target="custom", arity="collection")
    async def runtime_list(cls, ctx: Any) -> dict[str, Any]:
        rows = list((await _await(ctx["db"].execute(select(cls).order_by(cls.id)))).scalars())
        return {"items": [cls._runtime_projection(row).model_dump(mode="json") for row in rows]}

    @op_ctx(alias="runtime_read", target="custom", arity="collection")
    async def runtime_read(cls, ctx: Any) -> dict[str, Any]:
        row = await _await(ctx["db"].get(cls, int((ctx.get("payload") or {})["id"])))
        if row is None:
            raise ValueError("stream route not found")
        return cls._runtime_projection(row).model_dump(mode="json")

    @op_ctx(alias="validate", target="custom", arity="collection")
    async def validate(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        protocol = StreamProtocol(str(payload.get("protocol") or "tcp"))
        incoming_port = _port(int(payload["incoming_port"]), "incoming_port")
        _port(int(payload["target_port"]), "target_port")
        TargetKind(str(payload.get("target_kind") or "dns"))
        _target(
            str(payload.get("target") or ""),
            TargetKind(str(payload.get("target_kind") or "dns")),
            "target",
        )
        await cls._assert_port_available(
            ctx["db"], incoming_port, protocol, exclude_id=payload.get("id")
        )
        return {"valid": True}

    @classmethod
    async def _assert_port_available(
        cls,
        db: Any,
        incoming_port: int,
        protocol: StreamProtocol,
        *,
        exclude_id: int | None = None,
    ) -> None:
        conflicts = {
            StreamProtocol.TCP: ("tcp", "tcp+udp"),
            StreamProtocol.UDP: ("udp", "tcp+udp"),
            StreamProtocol.TCP_UDP: ("tcp", "udp", "tcp+udp"),
        }[protocol]
        statement = select(cls).where(
            cls.incoming_port == incoming_port,
            cls.__table__.c.protocol.in_(conflicts),
        )
        if exclude_id is not None:
            statement = statement.where(cls.id != int(exclude_id))
        if (await _await(db.execute(statement))).scalars().first() is not None:
            raise CollisionError(f"stream port {incoming_port}/{protocol.value} is already in use")

    @classmethod
    def _runtime_projection(cls, row: Any) -> RuntimeStream:
        return cls.RuntimeStream(
            id=row.id,
            incoming_port=row.incoming_port,
            forwarding_host=row.target,
            forwarding_port=row.target_port,
            protocol=row.protocol,
            target_kind=row.target_kind,
            owner_user_id=int(row.owner_principal_id or 1),
            certificate_id=int(row.certificate_id or 0),
            enabled=bool(row.enabled),
            meta=dict(row.metadata_json or {}),
        )


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


class ProxyHost(RoutingHostStore.RuntimeHost):
    kind: Literal[HostKind.PROXY] = HostKind.PROXY
    forward_scheme: ForwardScheme = ForwardScheme.HTTP
    forward_host: str
    forward_port: int


class RedirectionHost(RoutingHostStore.RuntimeHost):
    kind: Literal[HostKind.REDIRECT] = HostKind.REDIRECT
    forward_scheme: RedirectScheme = RedirectScheme.AUTO
    forward_domain_name: str


class DeadHost(RoutingHostStore.RuntimeHost):
    kind: Literal[HostKind.DEAD] = HostKind.DEAD


class HostInventory:
    """Compatibility preflight mirroring constraints enforced by routing operations."""

    def __init__(
        self,
        *,
        proxy_hosts: Iterable[ProxyHost] = (),
        redirection_hosts: Iterable[RedirectionHost] = (),
        dead_hosts: Iterable[DeadHost] = (),
        streams: Iterable[StreamRouteStore.RuntimeStream] = (),
    ) -> None:
        self.proxy_hosts = tuple(proxy_hosts)
        self.redirection_hosts = tuple(redirection_hosts)
        self.dead_hosts = tuple(dead_hosts)
        self.streams = tuple(streams)
        self.validate()

    def validate(self) -> None:
        claimed: dict[str, tuple[str, int]] = {}
        for family, resources in (
            ("proxy", self.proxy_hosts),
            ("redirection", self.redirection_hosts),
            ("dead", self.dead_hosts),
        ):
            for resource in resources:
                for domain in resource.domain_names:
                    previous = claimed.get(domain)
                    if previous is not None:
                        raise CollisionError(
                            f"domain {domain} is already used by {previous[0]} host {previous[1]}"
                        )
                    claimed[domain] = (family, resource.id)
        claims: set[tuple[int, str]] = set()
        for stream in self.streams:
            protocols = (
                ("tcp", "udp")
                if stream.protocol in {StreamProtocol.TCP_UDP, "tcp+udp"}
                else (str(stream.protocol),)
            )
            for protocol in protocols:
                claim = (stream.incoming_port, protocol)
                if claim in claims:
                    raise CollisionError(
                        f"stream port {stream.incoming_port}/{protocol} is already in use"
                    )
                claims.add(claim)


SSLSettings = RoutingHostStore.TLSSettings
ProxyLocation = RoutingHostStore.RuntimeLocation
Stream = StreamRouteStore.RuntimeStream


RoutingHost = RoutingHostStore
RoutingSource = RoutingSourceStore
RoutingUpstream = RoutingUpstreamStore
RoutingHostAccessList = RoutingHostAccessListStore
StreamRoute = StreamRouteStore
ConfigRevision = HostConfigRevisionStore

__all__ = [
    "ConfigRevision",
    "DeadHost",
    "ForwardScheme",
    "HostConfigRevisionStore",
    "HostInventory",
    "HostKind",
    "ProxyHost",
    "ProxyLocation",
    "RedirectScheme",
    "RedirectionHost",
    "RoutingHost",
    "RoutingHostAccessList",
    "RoutingHostAccessListStore",
    "RoutingHostStore",
    "RoutingLocationStore",
    "RoutingSource",
    "RoutingSourceStore",
    "RoutingUpstream",
    "RoutingUpstreamStore",
    "SSLSettings",
    "Stream",
    "StreamProtocol",
    "StreamRoute",
    "StreamRouteStore",
    "TargetKind",
    "canonical_domains",
]
