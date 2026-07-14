"""Deterministic Nginx configuration rendering.

The renderer accepts canonical domain objects and emits a complete generation as a mapping
of safe relative file names to UTF-8 text. Generated files are derived state.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from portwyrm.domain.routing import (
    AccessList,
    DeadHost,
    ProxyHost,
    ProxyLocation,
    RedirectionHost,
    SSLSettings,
    Stream,
)


def _indented(value: str, spaces: int = 2) -> str:
    prefix = " " * spaces
    return "\n".join(f"{prefix}{line}" if line else "" for line in value.splitlines())


def _block_exploits() -> str:
    return "  include conf.d/include/block-exploits.conf;\n"


def _listen(domain_names: tuple[str, ...], ssl: SSLSettings, ipv6: bool) -> list[str]:
    lines = ["  listen 80;"]
    if ipv6:
        lines.append("  listen [::]:80;")
    if ssl.certificate_id:
        http2 = " http2" if ssl.http2 else ""
        lines.append(f"  listen 443 ssl{http2};")
        if ipv6:
            lines.append(f"  listen [::]:443 ssl{http2};")
    lines.append(f"  server_name {' '.join(domain_names)};")
    return lines


def _ssl_lines(ssl: SSLSettings, *, stream: bool = False) -> list[str]:
    if not ssl.certificate_id:
        return []
    cert_dir = f"/etc/letsencrypt/live/npm-{ssl.certificate_id}"
    lines = [
        f"  ssl_certificate {cert_dir}/fullchain.pem;",
        f"  ssl_certificate_key {cert_dir}/privkey.pem;",
        "  ssl_session_cache shared:SSL_stream:50m;"
        if stream
        else "  ssl_session_cache shared:SSL:50m;",
    ]
    if not stream and ssl.hsts:
        subdomains = "; includeSubDomains" if ssl.hsts_subdomains else ""
        lines.append(
            f'  add_header Strict-Transport-Security "max-age=63072000{subdomains}" always;'
        )
    if not stream and ssl.client_certificate_id:
        ca_dir = f"/etc/letsencrypt/live/npm-{ssl.client_certificate_id}"
        lines.extend(
            [
                f"  ssl_client_certificate {ca_dir}/fullchain.pem;",
                "  ssl_verify_client on;",
                f"  ssl_verify_depth {ssl.client_verify_depth};",
            ]
        )
    return lines


def _force_ssl_lines(ssl: SSLSettings) -> list[str]:
    if not ssl.certificate_id or not ssl.forced:
        return []
    condition = (
        "$http_x_forwarded_proto != https" if ssl.trust_forwarded_proto else "$scheme != https"
    )
    return [f"  if ({condition}) {{", "    return 301 https://$host$request_uri;", "  }"]


def _access_lines(access_list: AccessList | None) -> list[str]:
    if access_list is None:
        return []
    lines: list[str] = []
    if access_list.credentials:
        lines.extend(
            [
                'auth_basic "Authorization required";',
                f"auth_basic_user_file /data/access/{access_list.id};",
            ]
        )
        if not access_list.pass_auth:
            lines.append('proxy_set_header Authorization "";')
    if access_list.clients:
        lines.extend(
            f"{client.directive.value} {client.address};" for client in access_list.clients
        )
        lines.append("deny all;")
    if access_list.credentials or access_list.clients:
        lines.append("satisfy any;" if access_list.satisfy_any else "satisfy all;")
    return lines


def _asset_cache_lines() -> list[str]:
    return [
        "location ~* ^.*\\.(css|js|jpe?g|gif|png|webp|woff|woff2|eot|ttf|svg|ico|"
        "css\\.map|js\\.map)$ {",
        "  if_modified_since off;",
        "  proxy_cache public-cache;",
        "  proxy_cache_key $host$request_uri;",
        "  proxy_ignore_headers Set-Cookie Cache-Control Expires X-Accel-Expires;",
        "  proxy_cache_valid any 30m;",
        "  proxy_cache_valid 404 1m;",
        "  proxy_hide_header Last-Modified;",
        "  proxy_hide_header Cache-Control;",
        "  proxy_hide_header Vary;",
        "  proxy_cache_bypass 0;",
        "  proxy_no_cache 0;",
        "  proxy_cache_use_stale error timeout updating http_500 http_502 http_503 "
        "http_504 http_404;",
        "  proxy_connect_timeout 5s;",
        "  proxy_read_timeout 45s;",
        "  expires 30m;",
        "  access_log off;",
        "  include conf.d/include/proxy.conf;",
        "}",
    ]


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


class NginxRenderer:
    """Render complete deterministic generations for NPM-compatible resources."""

    def __init__(self, platform: PlatformConfig | None = None) -> None:
        self.platform = platform or PlatformConfig()

    def render(
        self,
        *,
        proxy_hosts: Iterable[ProxyHost] = (),
        redirection_hosts: Iterable[RedirectionHost] = (),
        dead_hosts: Iterable[DeadHost] = (),
        streams: Iterable[Stream] = (),
        access_lists: Iterable[AccessList] = (),
    ) -> RenderedConfiguration:
        access_by_id = {item.id: item for item in access_lists}
        custom_names = (
            "root_top",
            "root",
            "http_top",
            "http",
            "events",
            "stream",
            "server_proxy",
            "server_redirect",
            "server_stream",
            "server_stream_tcp",
            "server_stream_udp",
            "server_dead",
        )
        files: dict[str, str] = {
            "nginx.conf": self.render_main(),
            "http/default.conf": self.render_default_site(),
            "include/trusted-proxies.conf": self.render_trusted_proxies(),
            "conf.d/include/proxy.conf": self.render_proxy_include(),
            "conf.d/include/block-exploits.conf": self.render_block_exploits(),
            **{f"custom/{name}.conf": "" for name in custom_names},
        }
        if self.platform.default_site == "html":
            files["default_www/index.html"] = self.platform.default_html
        for access_list in sorted(access_lists, key=lambda item: item.id):
            files[f"access/{access_list.id}"] = self.render_htpasswd(access_list)
        for host in sorted(proxy_hosts, key=lambda item: item.id):
            files[f"http/proxy-{host.id}.conf"] = self.render_proxy(
                host, access_by_id.get(host.access_list_id)
            )
        for host in sorted(redirection_hosts, key=lambda item: item.id):
            files[f"http/redirection-{host.id}.conf"] = self.render_redirection(host)
        for host in sorted(dead_hosts, key=lambda item: item.id):
            files[f"http/dead-{host.id}.conf"] = self.render_dead(host)
        for stream in sorted(streams, key=lambda item: item.id):
            files[f"stream/stream-{stream.id}.conf"] = self.render_stream(stream)
        for name, contents in sorted(self.platform.custom_includes.items()):
            if name not in custom_names:
                raise ValueError(f"unsupported custom include point: {name}")
            files[f"custom/{name}.conf"] = contents.rstrip() + "\n"
        return RenderedConfiguration(files)

    def render_main(self) -> str:
        resolver = ""
        if self.platform.resolver_enabled:
            resolver = f"  resolver {' '.join(self.platform.resolver_addresses)} valid=30s;\n"
        return (
            "# Generated by Portwyrm\n"
            "load_module /usr/lib/nginx/modules/ngx_stream_module.so;\n"
            "worker_processes auto;\n"
            "pid /tmp/nginx.pid;\n"
            "error_log /dev/stderr info;\n"
            "include custom/root_top.conf;\n"
            "events { worker_connections 1024; include custom/events.conf; }\n"
            "http {\n"
            "  include /etc/nginx/mime.types;\n"
            "  default_type application/octet-stream;\n"
            "  log_format proxy '$remote_addr - $host [$time_local] $request $status "
            "$body_bytes_sent';\n"
            "  include custom/http_top.conf;\n"
            "  proxy_cache_path /var/lib/nginx/cache/public levels=1:2 "
            "keys_zone=public-cache:30m max_size=192m;\n"
            f"{resolver}"
            "  include include/trusted-proxies.conf;\n"
            "  include http/*.conf;\n"
            "  include custom/http.conf;\n"
            "}\n"
            "stream { log_format stream '$remote_addr [$time_local] $protocol $status'; "
            "include stream/*.conf; include custom/stream.conf; }\n"
            "include custom/root.conf;\n"
        )

    @staticmethod
    def render_proxy_include() -> str:
        return (
            "proxy_set_header Host $host;\n"
            "proxy_set_header X-Real-IP $remote_addr;\n"
            "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
            "proxy_set_header X-Forwarded-Proto $scheme;\n"
            "proxy_pass $forward_scheme://$server:$port;\n"
        )

    @staticmethod
    def render_block_exploits() -> str:
        return "location ~* /(?:\\.git|\\.env|wp-config\\.php) { deny all; }\n"

    def render_trusted_proxies(self) -> str:
        lines = ["# Trusted reverse-proxy ranges"]
        for address in sorted(self.platform.trusted_proxy_ranges):
            lines.append(f"set_real_ip_from {address};")
        if self.platform.trusted_proxy_ranges:
            lines.extend(["real_ip_header X-Forwarded-For;", "real_ip_recursive on;"])
        return "\n".join(lines) + "\n"

    def render_default_site(self) -> str:
        mode = self.platform.default_site
        if mode == "congratulations":
            body = 'return 200 "Congratulations! Portwyrm is running.\\n";'
        elif mode in {"404", "444"}:
            body = f"return {mode};"
        elif mode == "redirect":
            body = f"return 301 {self.platform.default_redirect};"
        else:
            body = "root /data/nginx/default_www;\n    try_files $uri /index.html;"
        ipv6 = "  listen [::]:80 default_server;\n" if self.platform.ipv6 else ""
        return (
            "server {\n"
            "  listen 80 default_server;\n"
            f"{ipv6}"
            "  server_name _;\n"
            "  location ^~ /.well-known/acme-challenge/ {\n"
            "    root /data/acme-challenge;\n"
            "    try_files $uri =404;\n"
            "  }\n"
            "  location / {\n"
            f"    {body}\n"
            "  }\n"
            "}\n"
        )

    @staticmethod
    def render_htpasswd(access_list: AccessList) -> str:
        return "".join(f"{item.username}:{item.password}\n" for item in access_list.credentials)

    def render_proxy(self, host: ProxyHost, access_list: AccessList | None = None) -> str:
        if not host.enabled:
            return f"# proxy host {host.id} disabled\n"
        ssl = host.ssl.normalized()
        lines = ["server {", *_listen(host.domain_names, ssl, self.platform.ipv6)]
        lines.extend(_ssl_lines(ssl))
        lines.extend(_force_ssl_lines(ssl))
        lines.extend(self._acme_challenge_location())
        lines.extend(
            [
                f"  set $forward_scheme {host.forward_scheme.value};",
                f'  set $server "{host.forward_host}";',
                f"  set $port {host.forward_port};",
                f"  access_log /data/logs/proxy-host-{host.id}_access.log proxy;",
                f"  error_log /data/logs/proxy-host-{host.id}_error.log warn;",
            ]
        )
        if host.block_exploits:
            lines.append(_block_exploits().rstrip())
        if host.advanced_config:
            lines.append(_indented(host.advanced_config.rstrip()))
        if host.caching_enabled:
            lines.extend(_indented(line) for line in _asset_cache_lines())
        for location in sorted(host.locations, key=lambda item: item.path):
            lines.extend(self._render_location(location, host, access_list))
        has_location_root = any(location.path == "/" for location in host.locations)
        if not has_location_root and not self._has_root_location(host.advanced_config):
            lines.extend(self._render_default_proxy_location(host, access_list))
        lines.extend(["  include custom/server_proxy.conf;", "}"])
        return "\n".join(lines) + "\n"

    @staticmethod
    def _has_root_location(config: str) -> bool:
        compact = " ".join(config.replace("\n", " ").split())
        return "location / {" in compact

    def _render_default_proxy_location(
        self, host: ProxyHost, access_list: AccessList | None
    ) -> list[str]:
        lines = ["  location / {"]
        lines.extend(f"    {line}" for line in _access_lines(access_list))
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
        self,
        location: ProxyLocation,
        host: ProxyHost,
        access_list: AccessList | None,
    ) -> list[str]:
        lines = [f"  location {location.path} {{"]
        if location.advanced_config:
            lines.append(_indented(location.advanced_config.rstrip(), 4))
        lines.extend(
            [
                "    proxy_set_header Host $host;",
                "    proxy_set_header X-Forwarded-Scheme $scheme;",
                "    proxy_set_header X-Forwarded-Proto $scheme;",
                "    proxy_set_header X-Forwarded-For $remote_addr;",
                "    proxy_set_header X-Real-IP $remote_addr;",
                f"    proxy_pass {location.forward_scheme.value}://{location.forward_host}:{location.forward_port}{location.forward_path};",
            ]
        )
        lines.extend(f"    {line}" for line in _access_lines(access_list))
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

    def render_redirection(self, host: RedirectionHost) -> str:
        if not host.enabled:
            return f"# redirection host {host.id} disabled\n"
        ssl = host.ssl.normalized()
        scheme = "$scheme" if host.forward_scheme.value == "auto" else host.forward_scheme.value
        suffix = "$request_uri" if host.preserve_path else ""
        lines = ["server {", *_listen(host.domain_names, ssl, self.platform.ipv6)]
        lines.extend(_ssl_lines(ssl))
        lines.extend(_force_ssl_lines(ssl))
        lines.extend(self._acme_challenge_location())
        if host.block_exploits:
            lines.append(_block_exploits().rstrip())
        if host.advanced_config:
            lines.append(_indented(host.advanced_config.rstrip()))
        if not self._has_root_location(host.advanced_config):
            lines.extend(
                [
                    "  location / {",
                    f"    return {host.forward_http_code} {scheme}://{host.forward_domain_name}{suffix};",
                    "  }",
                ]
            )
        lines.extend(["  include custom/server_redirect.conf;", "}"])
        return "\n".join(lines) + "\n"

    def render_dead(self, host: DeadHost) -> str:
        if not host.enabled:
            return f"# dead host {host.id} disabled\n"
        ssl = host.ssl.normalized()
        lines = ["server {", *_listen(host.domain_names, ssl, self.platform.ipv6)]
        lines.extend(_ssl_lines(ssl))
        lines.extend(_force_ssl_lines(ssl))
        lines.extend(self._acme_challenge_location())
        if host.block_exploits:
            lines.append(_block_exploits().rstrip())
        if host.advanced_config:
            lines.append(_indented(host.advanced_config.rstrip()))
        if not self._has_root_location(host.advanced_config):
            lines.extend(
                ["  location / { return 404; }", "  include custom/server_dead.conf;", "}"]
            )
        else:
            lines.extend(["  include custom/server_dead.conf;", "}"])
        return "\n".join(lines) + "\n"

    @staticmethod
    def _acme_challenge_location() -> list[str]:
        return [
            "  location ^~ /.well-known/acme-challenge/ {",
            "    root /data/acme-challenge;",
            "    try_files $uri =404;",
            "  }",
        ]

    def render_stream(self, stream: Stream) -> str:
        if not stream.enabled:
            return f"# stream {stream.id} disabled\n"
        blocks: list[str] = []
        if stream.tcp_forwarding:
            ssl_suffix = " ssl" if stream.certificate_id else ""
            lines = ["server {", f"  listen {stream.incoming_port}{ssl_suffix};"]
            if self.platform.ipv6:
                lines.append(f"  listen [::]:{stream.incoming_port}{ssl_suffix};")
            if stream.certificate_id:
                stream_ssl = SSLSettings(certificate_id=stream.certificate_id)
                lines.extend(_ssl_lines(stream_ssl, stream=True))
            lines.extend(
                [
                    f"  proxy_pass {stream.forwarding_host}:{stream.forwarding_port};",
                    f"  access_log /data/logs/stream-{stream.id}_access.log stream;",
                    f"  error_log /data/logs/stream-{stream.id}_error.log warn;",
                    "  include custom/server_stream.conf;",
                    "  include custom/server_stream_tcp.conf;",
                    "}",
                ]
            )
            blocks.append("\n".join(lines))
        if stream.udp_forwarding:
            lines = ["server {", f"  listen {stream.incoming_port} udp;"]
            if self.platform.ipv6:
                lines.append(f"  listen [::]:{stream.incoming_port} udp;")
            lines.extend(
                [
                    f"  proxy_pass {stream.forwarding_host}:{stream.forwarding_port};",
                    f"  access_log /data/logs/stream-{stream.id}_access.log stream;",
                    f"  error_log /data/logs/stream-{stream.id}_error.log warn;",
                    "  include custom/server_stream.conf;",
                    "  include custom/server_stream_udp.conf;",
                    "}",
                ]
            )
            blocks.append("\n".join(lines))
        return "\n\n".join(blocks) + "\n"
