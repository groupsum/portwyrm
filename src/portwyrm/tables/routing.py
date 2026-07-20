"""Reverse proxy, redirect, dead-host, stream, and revision tables."""

from __future__ import annotations

import hashlib
import inspect
import ipaddress
import re
import time
from collections.abc import Callable, Iterable
from enum import StrEnum
from typing import Any, ClassVar, Literal, Self
from uuid import uuid4

from tigrbl import hook_ctx, op_alias, op_ctx, schema_ctx
from tigrbl.factories.column import IO, F, S
from tigrbl.types import (
    BaseModel,
    Boolean,
    CheckConstraint,
    Field,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from portwyrm.errors import CollisionError, DomainValidationError
from portwyrm.health import (
    AdministrativeState,
    DeploymentState,
    ReachabilityState,
    derive_host_summary,
)
from portwyrm.kernel_support import ConfigDict, delete, field_validator, model_validator, select

from .base import APPEND_ONLY_PROFILE, READ_ONLY_PROFILE, ManagedPortwyrmTable, PortwyrmTable, acol
from .compat import extension_metadata, extensions, iso
from .health import ProxyHostHealthObservationStore

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


@op_alias(alias="enable", target="update", arity="member", http_methods=("POST",))
@op_alias(alias="disable", target="update", arity="member", http_methods=("POST",))
class RoutingHostStore(ManagedPortwyrmTable):
    __tablename__ = "routing_hosts"
    _health_prober: ClassVar[Any | None] = None
    _health_freshness_seconds: ClassVar[int] = 60
    _health_runtime_provider: ClassVar[Callable[[], Any] | None] = None
    _health_app_provider: ClassVar[Callable[[], Any] | None] = None
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

    @schema_ctx(alias="probe", kind="out")
    @schema_ctx(alias="health_read", kind="out")
    class HealthStatus(BaseModel):
        id: int
        owner_principal_id: int | None = None
        administrative_state: str
        deployment_state: str
        reachability_state: str
        summary_status: str
        checked_at: int | None = None
        expires_at: int | None = None
        latency_ms: int | None = None
        http_status: int | None = None
        phase: str | None = None
        error_code: str | None = None
        error_detail: str | None = None

    @schema_ctx(alias="health_list", kind="out")
    class HealthStatusList(BaseModel):
        items: list[RoutingHostStore.HealthStatus] = Field(default_factory=list)

    @classmethod
    def configure_health_runtime(
        cls,
        prober: Any | None,
        *,
        freshness_seconds: int = 60,
        runtime_provider: Callable[[], Any] | None = None,
        app_provider: Callable[[], Any] | None = None,
    ) -> None:
        cls._health_prober = prober
        cls._health_freshness_seconds = max(1, freshness_seconds)
        cls._health_runtime_provider = runtime_provider
        cls._health_app_provider = app_provider

    kind = acol(String(32), nullable=False, index=True)
    owner_principal_id = acol(Integer, ForeignKey("principals.id"), nullable=True, index=True)
    enabled = acol(
        storage=S(type_=Boolean, nullable=False, default=True),
        field=F(py_type=bool),
        io=IO(
            in_verbs=("create", "update", "replace", "enable", "disable"),
            out_verbs=("read", "list", "create", "update", "replace", "enable", "disable"),
        ),
    )
    certificate_id = acol(Integer, ForeignKey("certificates.id"), nullable=True)
    force_ssl = acol(Boolean, nullable=False, default=False)
    hsts_enabled = acol(Boolean, nullable=False, default=False)
    hsts_subdomains = acol(Boolean, nullable=False, default=False)
    http2_enabled = acol(Boolean, nullable=False, default=False)
    trust_forwarded_proto = acol(Boolean, nullable=False, default=False)
    websocket_enabled = acol(Boolean, nullable=False, default=False)
    cache_enabled = acol(Boolean, nullable=False, default=False)
    block_exploits = acol(Boolean, nullable=False, default=False)
    redirect_target = acol(String(1024), nullable=True)
    redirect_scheme = acol(String(16), nullable=True)
    redirect_code = acol(Integer, nullable=True)
    preserve_path = acol(Boolean, nullable=False, default=False)
    advanced_config = acol(Text, nullable=False, default="")

    @hook_ctx(ops="enable", phase="PRE_HANDLER")
    def enable_payload(cls, ctx: dict[str, Any]) -> None:
        ctx.setdefault("payload", {})["enabled"] = True

    @hook_ctx(ops="disable", phase="PRE_HANDLER")
    def disable_payload(cls, ctx: dict[str, Any]) -> None:
        ctx.setdefault("payload", {})["enabled"] = False

    @classmethod
    async def _latest_observation(cls, db: Any, host_id: int) -> Any | None:
        result = await _await(
            db.execute(
                select(ProxyHostHealthObservationStore)
                .where(ProxyHostHealthObservationStore.routing_host_id == host_id)
                .order_by(
                    ProxyHostHealthObservationStore.checked_at.desc(),
                    ProxyHostHealthObservationStore.id.desc(),
                )
                .limit(1)
            )
        )
        return result.scalar_one_or_none()

    @classmethod
    async def _deployment_state(cls, db: Any, host_id: int) -> DeploymentState:
        runtime = cls._health_runtime_provider() if cls._health_runtime_provider else None
        if runtime is not None and runtime.is_host_applying(host_id):
            return DeploymentState.APPLYING
        result = await _await(
            db.execute(
                select(HostConfigRevisionStore)
                .where(HostConfigRevisionStore.routing_host_id == host_id)
                .order_by(HostConfigRevisionStore.id.desc())
                .limit(1)
            )
        )
        revision = result.scalar_one_or_none()
        if revision is None:
            return DeploymentState.PENDING
        active_generation = runtime.active_generation if runtime is not None else None
        if not revision.applied:
            return DeploymentState.ROLLED_BACK if active_generation else DeploymentState.FAILED
        if active_generation and revision.generation != active_generation:
            return DeploymentState.PENDING
        if runtime is not None and runtime.host_revision_drifted(revision):
            return DeploymentState.DRIFTED
        return DeploymentState.APPLIED

    @classmethod
    async def _health_status(cls, db: Any, row: Any) -> dict[str, Any]:
        observation = await cls._latest_observation(db, int(row.id))
        administrative = (
            AdministrativeState.ENABLED if row.enabled else AdministrativeState.DISABLED
        )
        deployment = await cls._deployment_state(db, int(row.id))
        reachability = ReachabilityState.UNKNOWN
        if observation is not None:
            reachability = ReachabilityState(str(observation.status))
            if observation.expires_at <= int(time.time()):
                reachability = ReachabilityState.STALE
        return {
            "id": int(row.id),
            "owner_principal_id": row.owner_principal_id,
            "administrative_state": administrative.value,
            "deployment_state": deployment.value,
            "reachability_state": reachability.value,
            "summary_status": derive_host_summary(administrative, deployment, reachability),
            "checked_at": observation.checked_at if observation is not None else None,
            "expires_at": observation.expires_at if observation is not None else None,
            "latency_ms": observation.latency_ms if observation is not None else None,
            "http_status": observation.http_status if observation is not None else None,
            "phase": observation.phase if observation is not None else None,
            "error_code": observation.error_code if observation is not None else None,
            "error_detail": observation.error_detail if observation is not None else None,
        }

    @op_ctx(alias="health_read", target="custom", arity="member", persist="skip")
    async def health_read(cls, ctx: Any) -> dict[str, Any]:
        host_id = int((ctx.get("payload") or {})["id"])
        row = await _await(ctx["db"].get(cls, host_id))
        if row is None or row.kind != HostKind.PROXY.value:
            raise LookupError("proxy host not found")
        return await cls._health_status(ctx["db"], row)

    @op_ctx(alias="health_list", target="custom", arity="collection", persist="skip")
    async def health_list(cls, ctx: Any) -> dict[str, Any]:
        rows = list(
            (
                await _await(
                    ctx["db"].execute(
                        select(cls).where(cls.kind == HostKind.PROXY.value).order_by(cls.id)
                    )
                )
            ).scalars()
        )
        return {"items": [await cls._health_status(ctx["db"], row) for row in rows]}

    @op_ctx(alias="probe", target="custom", arity="member")
    async def probe(cls, ctx: Any) -> dict[str, Any]:
        if cls._health_prober is None:
            raise RuntimeError("proxy-host health probing is not configured")
        host_id = int((ctx.get("payload") or {})["id"])
        row = await _await(ctx["db"].get(cls, host_id))
        if row is None or row.kind != HostKind.PROXY.value:
            raise LookupError("proxy host not found")
        if not row.enabled:
            raise ValueError("disabled proxy hosts are not probed")
        projected = await cls._project(ctx["db"], row)
        app = cls._health_app_provider() if cls._health_app_provider else None
        holder = uuid4().hex
        lease_name = f"proxy-host-probe:{host_id}"
        if app is not None:
            lease = await app.core.LeaseStore.acquire(
                {"name": lease_name, "holder": holder, "ttl_seconds": 30}
            )
            if not lease["acquired"]:
                raise ValueError("proxy host probe is already in progress")
        try:
            from portwyrm.runtime.upstream_health import ProbeTarget

            result = await cls._health_prober.probe(
                ProbeTarget(
                    host=str(projected["forward_host"]),
                    port=int(projected["forward_port"]),
                    scheme=str(projected.get("forward_scheme") or "http"),
                )
            )
        finally:
            if app is not None:
                await app.core.LeaseStore.release({"name": lease_name, "holder": holder})
        expires_at = result.checked_at + cls._health_freshness_seconds
        deployment = await cls._deployment_state(ctx["db"], host_id)
        ctx["db"].add(
            ProxyHostHealthObservationStore(
                routing_host_id=host_id,
                status=result.status.value,
                phase=result.phase.value,
                checked_at=result.checked_at,
                expires_at=expires_at,
                latency_ms=result.latency_ms,
                http_status=result.http_status,
                error_code=result.error_code,
                error_detail=result.error_detail,
            )
        )
        return {
            "id": host_id,
            "owner_principal_id": row.owner_principal_id,
            "administrative_state": AdministrativeState.ENABLED.value,
            "deployment_state": deployment.value,
            "reachability_state": result.status.value,
            "summary_status": derive_host_summary(
                AdministrativeState.ENABLED, deployment, result.status
            ),
            "checked_at": result.checked_at,
            "expires_at": expires_at,
            "latency_ms": result.latency_ms,
            "http_status": result.http_status,
            "phase": result.phase.value,
            "error_code": result.error_code,
            "error_detail": result.error_detail,
        }

    @hook_ctx(ops=("create", "update", "replace"), phase="PRE_HANDLER")
    async def prepare_aggregate(cls, ctx: dict[str, Any]) -> None:
        payload = dict(ctx.get("payload") or {})
        op = ctx.get("op") or ctx.get("alias") or ""
        alias = str(getattr(op, "alias", op)).casefold()
        if alias == "update":
            row = await _await(ctx["db"].get(cls, int(payload["id"])))
            if row is not None:
                payload = {**(await cls._project(ctx["db"], row)), **payload}
        cls._validate_payload(payload)
        await cls._assert_source_collisions(
            ctx["db"],
            payload.get("domain_names") or [],
            exclude_host_id=payload.get("id"),
        )
        ctx.setdefault("temp", {})["routing_aggregate"] = payload
        root = cls._host_values(payload)
        if payload.get("id") is not None:
            root["id"] = int(payload["id"])
        ctx["payload"] = root

    @hook_ctx(ops=("create", "update", "replace"), phase="POST_HANDLER")
    async def persist_aggregate(cls, ctx: dict[str, Any]) -> None:
        row = ctx["result"]
        payload = ctx.get("temp", {}).get("routing_aggregate", {})
        await cls._replace_children(ctx["db"], row.id, payload)
        ctx["result"] = await cls._project(ctx["db"], row)

    @hook_ctx(ops=("read", "list"), phase="POST_HANDLER")
    async def project_aggregate(cls, ctx: dict[str, Any]) -> None:
        result = ctx["result"]
        if isinstance(result, list):
            kind = (ctx.get("payload") or {}).get("kind")
            rows = [row for row in result if kind is None or row.kind == str(kind)]
            ctx["result"] = [await cls._project(ctx["db"], row) for row in rows]
        else:
            ctx["result"] = await cls._project(ctx["db"], result)

    @hook_ctx(ops="delete", phase="PRE_HANDLER")
    async def delete_aggregate_children(cls, ctx: dict[str, Any]) -> None:
        host_id = int(ctx["payload"]["id"])
        db = ctx["db"]
        await cls._replace_children(db, host_id, {})
        # These tables intentionally do not use database-level cascades: the
        # routing aggregate owns their lifecycle, while audit rows and global
        # generation records must remain durable. Remove host-specific runtime
        # state before the root row so SQLite and PostgreSQL enforce the same
        # referentially complete delete semantics.
        for table in (ProxyHostHealthObservationStore, HostConfigRevisionStore):
            await _await(db.execute(delete(table).where(table.routing_host_id == host_id)))

    HOOKS = (
        enable_payload,
        disable_payload,
        prepare_aggregate,
        persist_aggregate,
        project_aggregate,
        delete_aggregate_children,
    )

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
            "websocket_enabled": bool(payload.get("allow_websocket_upgrade", False)),
            "cache_enabled": bool(payload.get("caching_enabled", False)),
            "block_exploits": bool(payload.get("block_exploits", False)),
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


class RoutingSourceStore(PortwyrmTable):
    __tablename__ = "routing_sources"
    TABLE_PROFILE = READ_ONLY_PROFILE
    __table_args__ = (
        UniqueConstraint("domain_name", name="uq_routing_source_domain"),
        CheckConstraint("domain_name = lower(domain_name)", name="ck_routing_source_lowercase"),
    )
    routing_host_id = acol(Integer, ForeignKey("routing_hosts.id"), nullable=False, index=True)
    domain_name = acol(String(253), nullable=False, index=True)


class RoutingUpstreamStore(PortwyrmTable):
    __tablename__ = "routing_upstreams"
    TABLE_PROFILE = READ_ONLY_PROFILE
    __table_args__ = (
        CheckConstraint("protocol IN ('http','https')", name="ck_routing_upstream_protocol"),
        CheckConstraint("target_kind IN ('ip','dns','docker')", name="ck_routing_upstream_target"),
        CheckConstraint("port BETWEEN 1 AND 65535", name="ck_routing_upstream_port"),
        CheckConstraint("weight > 0", name="ck_routing_upstream_weight"),
    )
    routing_host_id = acol(Integer, ForeignKey("routing_hosts.id"), nullable=False, index=True)
    protocol = acol(String(16), nullable=False, default="http")
    target_kind = acol(String(16), nullable=False)
    target = acol(String(1024), nullable=False)
    port = acol(Integer, nullable=False)
    position = acol(Integer, nullable=False, default=0)
    weight = acol(Integer, nullable=False, default=1)


class RoutingLocationStore(PortwyrmTable):
    __tablename__ = "routing_locations"
    TABLE_PROFILE = READ_ONLY_PROFILE
    __table_args__ = (
        UniqueConstraint("routing_host_id", "path", name="uq_routing_location_path"),
        CheckConstraint("protocol IN ('http','https')", name="ck_routing_location_protocol"),
        CheckConstraint("target_kind IN ('ip','dns','docker')", name="ck_routing_location_target"),
        CheckConstraint("port BETWEEN 1 AND 65535", name="ck_routing_location_port"),
    )
    routing_host_id = acol(Integer, ForeignKey("routing_hosts.id"), nullable=False, index=True)
    path = acol(String(1024), nullable=False)
    protocol = acol(String(16), nullable=False, default="http")
    target_kind = acol(String(16), nullable=False)
    target = acol(String(1024), nullable=False)
    port = acol(Integer, nullable=False)
    forward_path = acol(String(1024), nullable=False, default="")
    advanced_config = acol(Text, nullable=False, default="")


class RoutingHostAccessListStore(PortwyrmTable):
    __tablename__ = "routing_host_access_lists"
    TABLE_PROFILE = READ_ONLY_PROFILE
    __table_args__ = (
        UniqueConstraint("routing_host_id", "access_list_id", name="uq_routing_host_access_list"),
    )
    routing_host_id = acol(Integer, ForeignKey("routing_hosts.id"), nullable=False, index=True)
    access_list_id = acol(Integer, ForeignKey("access_lists.id"), nullable=False, index=True)


@op_alias(alias="enable", target="update", arity="member", http_methods=("POST",))
@op_alias(alias="disable", target="update", arity="member", http_methods=("POST",))
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
    owner_principal_id = acol(Integer, ForeignKey("principals.id"), nullable=True, index=True)
    protocol = acol(String(8), nullable=False)
    incoming_port = acol(Integer, nullable=False, index=True)
    target_kind = acol(String(16), nullable=False)
    target = acol(String(1024), nullable=False)
    target_port = acol(Integer, nullable=False)
    certificate_id = acol(Integer, ForeignKey("certificates.id"), nullable=True)
    enabled = acol(
        storage=S(type_=Boolean, nullable=False, default=True),
        field=F(py_type=bool),
        io=IO(
            in_verbs=("create", "update", "replace", "enable", "disable"),
            out_verbs=("read", "list", "create", "update", "replace", "enable", "disable"),
        ),
    )

    @hook_ctx(ops="enable", phase="PRE_HANDLER")
    def enable_payload(cls, ctx: dict[str, Any]) -> None:
        ctx.setdefault("payload", {})["enabled"] = True

    @hook_ctx(ops="disable", phase="PRE_HANDLER")
    def disable_payload(cls, ctx: dict[str, Any]) -> None:
        ctx.setdefault("payload", {})["enabled"] = False

    HOOKS = (enable_payload, disable_payload)

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


class HostConfigRevisionStore(PortwyrmTable):
    __tablename__ = "config_revisions"
    TABLE_PROFILE = APPEND_ONLY_PROFILE
    __table_args__ = (UniqueConstraint("routing_host_id", "generation", name="uq_host_generation"),)
    routing_host_id = acol(Integer, ForeignKey("routing_hosts.id"), nullable=False, index=True)
    generation = acol(String(64), nullable=False)
    config_text = acol(Text, nullable=False)
    config_digest = acol(String(64), nullable=False)
    applied = acol(Boolean, nullable=False, default=False)
    applied_at = acol(Integer, nullable=True)

    @op_ctx(alias="record", target="custom", arity="collection")
    async def record(cls, ctx: Any) -> Any:
        payload = dict(ctx.get("payload") or {})
        result = await _await(
            ctx["db"].execute(
                select(cls).where(
                    cls.routing_host_id == int(payload["routing_host_id"]),
                    cls.generation == str(payload["generation"]),
                )
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            row = cls(
                routing_host_id=int(payload["routing_host_id"]),
                generation=str(payload["generation"]),
                config_text=str(payload["config_text"]),
                config_digest=str(payload["config_digest"]),
                applied=bool(payload.get("applied")),
                applied_at=payload.get("applied_at"),
            )
            ctx["db"].add(row)
        return row

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
