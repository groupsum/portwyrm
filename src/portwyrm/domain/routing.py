"""Legacy constructor adapters for table-owned routing schemas.

Runtime and API code must import the schemas from :mod:`portwyrm.tables`.
"""

from typing import Any

from pydantic import ValidationError

from portwyrm.errors import DomainValidationError
from portwyrm.tables.access import (
    AccessClient as _AccessClient,
)
from portwyrm.tables.access import (
    AccessDirective,
)
from portwyrm.tables.access import (
    RuntimeAccessCredential as _AccessListCredential,
)
from portwyrm.tables.access import (
    RuntimeAccessList as _AccessList,
)
from portwyrm.tables.routing import (
    DeadHost as _DeadHost,
)
from portwyrm.tables.routing import (
    ForwardScheme,
    HostInventory,
    RedirectScheme,
    SSLSettings,
    StreamProtocol,
    TargetKind,
    canonical_domains,
)
from portwyrm.tables.routing import (
    ProxyHost as _ProxyHost,
)
from portwyrm.tables.routing import (
    ProxyLocation as _ProxyLocation,
)
from portwyrm.tables.routing import (
    RedirectionHost as _RedirectionHost,
)
from portwyrm.tables.routing import (
    Stream as _Stream,
)


def _legacy(
    values: tuple[Any, ...], names: tuple[str, ...], data: dict[str, Any]
) -> dict[str, Any]:
    if len(values) > len(names):
        raise TypeError(f"expected at most {len(names)} positional arguments")
    return {**dict(zip(names, values, strict=False)), **data}


class _DomainAdapter:
    def __init__(self, **data: Any) -> None:
        try:
            super().__init__(**data)
        except ValidationError as exc:
            errors = exc.errors()
            cause = errors[0].get("ctx", {}).get("error") if errors else None
            if isinstance(cause, DomainValidationError):
                raise cause from exc
            raise


class ProxyLocation(_DomainAdapter, _ProxyLocation):
    def __init__(self, *values: Any, **data: Any) -> None:
        super().__init__(
            **_legacy(
                values,
                (
                    "path",
                    "forward_scheme",
                    "forward_host",
                    "forward_port",
                    "forward_path",
                    "advanced_config",
                ),
                data,
            )
        )


class ProxyHost(_DomainAdapter, _ProxyHost):
    def __init__(self, *values: Any, **data: Any) -> None:
        super().__init__(
            **_legacy(
                values,
                ("id", "domain_names", "forward_scheme", "forward_host", "forward_port"),
                data,
            )
        )


class RedirectionHost(_DomainAdapter, _RedirectionHost):
    def __init__(self, *values: Any, **data: Any) -> None:
        super().__init__(
            **_legacy(
                values,
                (
                    "id",
                    "domain_names",
                    "forward_domain_name",
                    "forward_scheme",
                    "forward_http_code",
                    "preserve_path",
                    "owner_user_id",
                    "ssl",
                    "block_exploits",
                    "advanced_config",
                    "enabled",
                    "meta",
                ),
                data,
            )
        )


class DeadHost(_DomainAdapter, _DeadHost):
    def __init__(self, *values: Any, **data: Any) -> None:
        super().__init__(
            **_legacy(
                values,
                (
                    "id",
                    "domain_names",
                    "owner_user_id",
                    "ssl",
                    "block_exploits",
                    "advanced_config",
                    "enabled",
                    "meta",
                ),
                data,
            )
        )


class Stream(_DomainAdapter, _Stream):
    def __init__(self, *values: Any, **data: Any) -> None:
        payload = _legacy(
            values,
            (
                "id",
                "incoming_port",
                "forwarding_host",
                "forwarding_port",
                "tcp_forwarding",
                "udp_forwarding",
            ),
            data,
        )
        tcp = bool(payload.pop("tcp_forwarding", True))
        udp = bool(payload.pop("udp_forwarding", False))
        if not tcp and not udp:
            raise ValueError("a stream must enable TCP, UDP, or both")
        payload["protocol"] = "tcp+udp" if tcp and udp else ("tcp" if tcp else "udp")
        super().__init__(**payload)


class AccessListCredential(_DomainAdapter, _AccessListCredential):
    def __init__(self, *values: Any, **data: Any) -> None:
        payload = _legacy(values, ("username", "password_hash"), data)
        if "password" in payload and "password_hash" not in payload:
            payload["password_hash"] = payload.pop("password")
        super().__init__(**payload)


class AccessClient(_DomainAdapter, _AccessClient):
    def __init__(self, *values: Any, **data: Any) -> None:
        super().__init__(**_legacy(values, ("address", "directive"), data))


class AccessList(_DomainAdapter, _AccessList):
    def __init__(self, *values: Any, **data: Any) -> None:
        payload = _legacy(
            values,
            ("id", "name", "credentials", "clients", "satisfy_any", "pass_auth"),
            data,
        )
        payload.pop("owner_user_id", None)
        super().__init__(**payload)


Host = ProxyHost | RedirectionHost | DeadHost

__all__ = [
    "AccessClient",
    "AccessDirective",
    "AccessList",
    "AccessListCredential",
    "DeadHost",
    "ForwardScheme",
    "Host",
    "HostInventory",
    "ProxyHost",
    "ProxyLocation",
    "RedirectScheme",
    "RedirectionHost",
    "SSLSettings",
    "Stream",
    "StreamProtocol",
    "TargetKind",
    "canonical_domains",
]
