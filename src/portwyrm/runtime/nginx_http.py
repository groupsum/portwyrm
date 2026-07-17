"""HTTP proxy, redirect, and dead-host rendering."""

from __future__ import annotations

from portwyrm.tables.access import RuntimeAccessList as AccessList
from portwyrm.tables.routing import DeadHost, ProxyHost, ProxyLocation, RedirectionHost

from .nginx_models import PlatformConfig
from .nginx_primitives import (
    access_lines,
    acme_challenge_location,
    asset_cache_lines,
    block_exploits,
    force_ssl_lines,
    has_root_location,
    indented,
    listen,
    ssl_lines,
)


def _render_default_proxy_location(
    host: ProxyHost,
    access_list: AccessList | None,
    password_file: str | None = None,
) -> list[str]:
    lines = ["  location / {"]
    lines.extend(f"    {line}" for line in access_lines(access_list, password_file))
    if host.allow_websocket_upgrade:
        lines.extend(
            [
                "    proxy_set_header Upgrade $http_upgrade;",
                "    proxy_set_header Connection $http_connection;",
                "    proxy_http_version 1.1;",
            ]
        )
    lines.extend(["    include conf.d/include/proxy.conf;", "  }"])
    return lines


def _render_location(
    location: ProxyLocation,
    host: ProxyHost,
    access_list: AccessList | None,
    password_file: str | None = None,
) -> list[str]:
    lines = [f"  location {location.path} {{"]
    if location.advanced_config:
        lines.append(indented(location.advanced_config.rstrip(), 4))
    lines.extend(
        [
            "    proxy_set_header Host $host;",
            "    proxy_set_header X-Forwarded-Scheme $scheme;",
            "    proxy_set_header X-Forwarded-Proto $scheme;",
            "    proxy_set_header X-Forwarded-For $remote_addr;",
            "    proxy_set_header X-Real-IP $remote_addr;",
            f"    proxy_pass {location.forward_scheme}://{location.forward_host}:"
            f"{location.forward_port}{location.forward_path};",
        ]
    )
    lines.extend(f"    {line}" for line in access_lines(access_list, password_file))
    if host.allow_websocket_upgrade:
        lines.extend(
            [
                "    proxy_set_header Upgrade $http_upgrade;",
                "    proxy_set_header Connection $http_connection;",
                "    proxy_http_version 1.1;",
            ]
        )
    lines.append("  }")
    return lines


def _render_disabled_host(platform: PlatformConfig, host: ProxyHost, family: str) -> str:
    ssl = host.ssl.normalized()
    lines = ["server {", *listen(host.domain_names, ssl, platform.ipv6)]
    lines.extend(ssl_lines(ssl))
    lines.extend(
        [
            f"  access_log /data/logs/{family}-{host.id}_access.log proxy;",
            f"  error_log /data/logs/{family}-{host.id}_error.log warn;",
            "  return 503;",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


def render_proxy(
    platform: PlatformConfig,
    host: ProxyHost,
    access_list: AccessList | None = None,
    password_file: str | None = None,
) -> str:
    if not host.enabled:
        return _render_disabled_host(platform, host, "proxy-host")
    ssl = host.ssl.normalized()
    lines = ["server {", *listen(host.domain_names, ssl, platform.ipv6)]
    lines.extend(ssl_lines(ssl))
    lines.extend(force_ssl_lines(ssl))
    lines.extend(acme_challenge_location())
    lines.extend(
        [
            f"  set $forward_scheme {host.forward_scheme};",
            f'  set $server "{host.forward_host}";',
            f"  set $port {host.forward_port};",
            f"  access_log /data/logs/proxy-host-{host.id}_access.log proxy;",
            f"  error_log /data/logs/proxy-host-{host.id}_error.log warn;",
        ]
    )
    if host.block_exploits:
        lines.append(block_exploits().rstrip())
    if host.advanced_config:
        lines.append(indented(host.advanced_config.rstrip()))
    if host.caching_enabled:
        lines.extend(indented(line) for line in asset_cache_lines())
    for location in sorted(host.locations, key=lambda item: item.path):
        lines.extend(_render_location(location, host, access_list, password_file))
    has_location_root = any(location.path == "/" for location in host.locations)
    if not has_location_root and not has_root_location(host.advanced_config):
        lines.extend(_render_default_proxy_location(host, access_list, password_file))
    lines.extend(["  include custom/server_proxy.conf;", "}"])
    return "\n".join(lines) + "\n"


def render_redirection(platform: PlatformConfig, host: RedirectionHost) -> str:
    if not host.enabled:
        return _render_disabled_host(platform, host, "redirection-host")
    ssl = host.ssl.normalized()
    scheme = "$scheme" if host.forward_scheme == "auto" else str(host.forward_scheme)
    suffix = "$request_uri" if host.preserve_path else ""
    lines = ["server {", *listen(host.domain_names, ssl, platform.ipv6)]
    lines.extend(ssl_lines(ssl))
    lines.extend(force_ssl_lines(ssl))
    lines.extend(acme_challenge_location())
    if host.block_exploits:
        lines.append(block_exploits().rstrip())
    if host.advanced_config:
        lines.append(indented(host.advanced_config.rstrip()))
    if not has_root_location(host.advanced_config):
        lines.extend(
            [
                "  location / {",
                f"    return {host.forward_http_code} {scheme}://"
                f"{host.forward_domain_name}{suffix};",
                "  }",
            ]
        )
    lines.extend(["  include custom/server_redirect.conf;", "}"])
    return "\n".join(lines) + "\n"


def render_dead(platform: PlatformConfig, host: DeadHost) -> str:
    if not host.enabled:
        return _render_disabled_host(platform, host, "dead-host")
    ssl = host.ssl.normalized()
    lines = ["server {", *listen(host.domain_names, ssl, platform.ipv6)]
    lines.extend(ssl_lines(ssl))
    lines.extend(force_ssl_lines(ssl))
    lines.extend(acme_challenge_location())
    if host.block_exploits:
        lines.append(block_exploits().rstrip())
    if host.advanced_config:
        lines.append(indented(host.advanced_config.rstrip()))
    if not has_root_location(host.advanced_config):
        lines.append("  location / { return 404; }")
    lines.extend(["  include custom/server_dead.conf;", "}"])
    return "\n".join(lines) + "\n"


__all__ = ["render_dead", "render_proxy", "render_redirection"]
