"""Canonical routing entities and cross-resource invariants."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .errors import CollisionError, DomainValidationError
from .ownership import Ownership

_DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?=.{1,253}\.?$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.I,
)


class ForwardScheme(StrEnum):
    HTTP = "http"
    HTTPS = "https"


class RedirectScheme(StrEnum):
    AUTO = "auto"
    HTTP = "http"
    HTTPS = "https"


class AccessDirective(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


def _positive_id(value: int, name: str = "id") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise DomainValidationError(f"{name} must be a positive integer")
    return value


def _port(value: int, name: str = "port") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise DomainValidationError(f"{name} must be between 1 and 65535")
    return value


def canonical_domains(values: Iterable[str]) -> tuple[str, ...]:
    domains: list[str] = []
    seen: set[str] = set()
    for raw in values:
        if not isinstance(raw, str):
            raise DomainValidationError("domain names must be strings")
        domain = raw.strip().rstrip(".").lower()
        if not _DOMAIN_RE.fullmatch(domain):
            raise DomainValidationError(f"invalid domain name: {raw!r}")
        if domain in seen:
            raise DomainValidationError(f"duplicate domain name: {domain}")
        seen.add(domain)
        domains.append(domain)
    if not 1 <= len(domains) <= 100:
        raise DomainValidationError("resources require between 1 and 100 domain names")
    return tuple(domains)


@dataclass(frozen=True, slots=True)
class SSLSettings:
    certificate_id: int = 0
    forced: bool = False
    http2: bool = False
    hsts: bool = False
    hsts_subdomains: bool = False
    trust_forwarded_proto: bool = False

    def normalized(self) -> SSLSettings:
        certificate_id = int(self.certificate_id or 0)
        if certificate_id < 0:
            raise DomainValidationError("certificate_id cannot be negative")
        if certificate_id == 0:
            return SSLSettings()
        forced = bool(self.forced)
        hsts = forced and bool(self.hsts)
        return SSLSettings(
            certificate_id=certificate_id,
            forced=forced,
            http2=bool(self.http2),
            hsts=hsts,
            hsts_subdomains=hsts and bool(self.hsts_subdomains),
            trust_forwarded_proto=forced and bool(self.trust_forwarded_proto),
        )


@dataclass(frozen=True, slots=True)
class ProxyLocation:
    path: str
    forward_scheme: ForwardScheme | str
    forward_host: str
    forward_port: int
    forward_path: str = ""
    advanced_config: str = ""

    def __post_init__(self) -> None:
        if not self.path.startswith("/"):
            raise DomainValidationError("location path must start with /")
        object.__setattr__(self, "forward_scheme", ForwardScheme(self.forward_scheme))
        if not self.forward_host.strip():
            raise DomainValidationError("location forward_host is required")
        _port(self.forward_port, "location forward_port")
        if self.forward_path and not self.forward_path.startswith("/"):
            raise DomainValidationError("location forward_path must start with /")


@dataclass(frozen=True, slots=True)
class ProxyHost:
    id: int
    domain_names: tuple[str, ...] | list[str]
    forward_scheme: ForwardScheme | str
    forward_host: str
    forward_port: int
    owner_user_id: int = 1
    access_list_id: int = 0
    ssl: SSLSettings = field(default_factory=SSLSettings)
    caching_enabled: bool = False
    block_exploits: bool = False
    allow_websocket_upgrade: bool = False
    advanced_config: str = ""
    locations: tuple[ProxyLocation, ...] | list[ProxyLocation] = ()
    enabled: bool = True
    meta: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _positive_id(self.id)
        _positive_id(self.owner_user_id, "owner_user_id")
        object.__setattr__(self, "domain_names", canonical_domains(self.domain_names))
        object.__setattr__(self, "forward_scheme", ForwardScheme(self.forward_scheme))
        if not self.forward_host.strip():
            raise DomainValidationError("forward_host is required")
        _port(self.forward_port, "forward_port")
        if self.access_list_id < 0:
            raise DomainValidationError("access_list_id cannot be negative")
        object.__setattr__(self, "ssl", self.ssl.normalized())
        object.__setattr__(self, "locations", tuple(self.locations))
        paths = [location.path for location in self.locations]
        if len(paths) != len(set(paths)):
            raise DomainValidationError("proxy location paths must be unique")
        object.__setattr__(self, "meta", dict(self.meta))

    @property
    def ownership(self) -> Ownership | None:
        return Ownership.from_meta(self.meta)


@dataclass(frozen=True, slots=True)
class RedirectionHost:
    id: int
    domain_names: tuple[str, ...] | list[str]
    forward_domain_name: str
    forward_scheme: RedirectScheme | str = RedirectScheme.AUTO
    forward_http_code: int = 301
    preserve_path: bool = False
    owner_user_id: int = 1
    ssl: SSLSettings = field(default_factory=SSLSettings)
    block_exploits: bool = False
    advanced_config: str = ""
    enabled: bool = True
    meta: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _positive_id(self.id)
        _positive_id(self.owner_user_id, "owner_user_id")
        object.__setattr__(self, "domain_names", canonical_domains(self.domain_names))
        object.__setattr__(self, "forward_scheme", RedirectScheme(self.forward_scheme))
        target = self.forward_domain_name.strip().rstrip(".").lower()
        if not _DOMAIN_RE.fullmatch(target):
            raise DomainValidationError("forward_domain_name must be a valid domain")
        object.__setattr__(self, "forward_domain_name", target)
        if not 300 <= self.forward_http_code <= 308:
            raise DomainValidationError("forward_http_code must be between 300 and 308")
        object.__setattr__(self, "ssl", self.ssl.normalized())
        object.__setattr__(self, "meta", dict(self.meta))

    @property
    def ownership(self) -> Ownership | None:
        return Ownership.from_meta(self.meta)


@dataclass(frozen=True, slots=True)
class DeadHost:
    id: int
    domain_names: tuple[str, ...] | list[str]
    owner_user_id: int = 1
    ssl: SSLSettings = field(default_factory=SSLSettings)
    block_exploits: bool = False
    advanced_config: str = ""
    enabled: bool = True
    meta: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _positive_id(self.id)
        _positive_id(self.owner_user_id, "owner_user_id")
        object.__setattr__(self, "domain_names", canonical_domains(self.domain_names))
        object.__setattr__(self, "ssl", self.ssl.normalized())
        object.__setattr__(self, "meta", dict(self.meta))

    @property
    def ownership(self) -> Ownership | None:
        return Ownership.from_meta(self.meta)


@dataclass(frozen=True, slots=True)
class Stream:
    id: int
    incoming_port: int
    forwarding_host: str
    forwarding_port: int
    tcp_forwarding: bool
    udp_forwarding: bool
    owner_user_id: int = 1
    certificate_id: int = 0
    enabled: bool = True
    meta: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _positive_id(self.id)
        _positive_id(self.owner_user_id, "owner_user_id")
        _port(self.incoming_port, "incoming_port")
        _port(self.forwarding_port, "forwarding_port")
        if not self.forwarding_host.strip():
            raise DomainValidationError("forwarding_host is required")
        if not self.tcp_forwarding and not self.udp_forwarding:
            raise DomainValidationError("a stream must enable TCP, UDP, or both")
        if self.certificate_id < 0:
            raise DomainValidationError("certificate_id cannot be negative")
        if self.certificate_id and not self.tcp_forwarding:
            raise DomainValidationError("stream TLS is supported only for TCP")
        object.__setattr__(self, "meta", dict(self.meta))

    @property
    def ownership(self) -> Ownership | None:
        return Ownership.from_meta(self.meta)


@dataclass(frozen=True, slots=True)
class AccessListCredential:
    username: str
    password: str

    def __post_init__(self) -> None:
        if not self.username or ":" in self.username or "\n" in self.username:
            raise DomainValidationError("invalid basic-auth username")
        if not self.password or "\n" in self.password:
            raise DomainValidationError("invalid basic-auth password/hash")


@dataclass(frozen=True, slots=True)
class AccessClient:
    address: str
    directive: AccessDirective | str

    def __post_init__(self) -> None:
        object.__setattr__(self, "directive", AccessDirective(self.directive))
        address = self.address.strip()
        if address != "all":
            try:
                ipaddress.ip_network(address, strict=False)
            except ValueError as exc:
                raise DomainValidationError(f"invalid access-list address: {address}") from exc
        object.__setattr__(self, "address", address)


@dataclass(frozen=True, slots=True)
class AccessList:
    id: int
    name: str
    credentials: tuple[AccessListCredential, ...] | list[AccessListCredential] = ()
    clients: tuple[AccessClient, ...] | list[AccessClient] = ()
    satisfy_any: bool = False
    pass_auth: bool = False
    owner_user_id: int = 1
    meta: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _positive_id(self.id)
        _positive_id(self.owner_user_id, "owner_user_id")
        if not self.name.strip():
            raise DomainValidationError("access-list name is required")
        object.__setattr__(self, "credentials", tuple(self.credentials))
        object.__setattr__(self, "clients", tuple(self.clients))
        object.__setattr__(self, "meta", dict(self.meta))

    @property
    def ownership(self) -> Ownership | None:
        return Ownership.from_meta(self.meta)


Host = ProxyHost | RedirectionHost | DeadHost


class HostInventory:
    """Checks invariants that span multiple routing resource families."""

    def __init__(
        self,
        *,
        proxy_hosts: Iterable[ProxyHost] = (),
        redirection_hosts: Iterable[RedirectionHost] = (),
        dead_hosts: Iterable[DeadHost] = (),
        streams: Iterable[Stream] = (),
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

        stream_claims: set[tuple[int, str]] = set()
        for stream in self.streams:
            protocols = []
            if stream.tcp_forwarding:
                protocols.append("tcp")
            if stream.udp_forwarding:
                protocols.append("udp")
            for protocol in protocols:
                claim = (stream.incoming_port, protocol)
                if claim in stream_claims:
                    raise CollisionError(
                        f"stream port {stream.incoming_port}/{protocol} is already in use"
                    )
                stream_claims.add(claim)
