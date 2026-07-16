"""Immutable inputs and outputs for deterministic Nginx compilation."""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class PlatformConfig:
    ipv6: bool = True
    resolver_enabled: bool = True
    resolver_addresses: tuple[str, ...] = ("127.0.0.11",)
    trusted_proxy_ranges: tuple[str, ...] = ()
    default_site: str = "congratulations"
    default_redirect: str = ""
    default_html: str = ""
    custom_includes: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.default_site not in {"congratulations", "404", "444", "redirect", "html"}:
            raise ValueError("unsupported default-site mode")
        if self.default_site == "redirect" and not self.default_redirect:
            raise ValueError("default redirect mode requires a destination")
        if self.default_site == "html" and not self.default_html:
            raise ValueError("default html mode requires HTML")
        for address in self.trusted_proxy_ranges:
            ipaddress.ip_network(address, strict=False)


@dataclass(frozen=True, slots=True)
class RenderedConfiguration:
    files: Mapping[str, str]

    @property
    def digest(self) -> str:
        digest = hashlib.sha256()
        for name, contents in sorted(self.files.items()):
            digest.update(name.encode())
            digest.update(b"\0")
            digest.update(contents.encode())
            digest.update(b"\0")
        return digest.hexdigest()


__all__ = ["PlatformConfig", "RenderedConfiguration"]
