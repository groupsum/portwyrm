"""Shared Nginx fragment primitives."""

from __future__ import annotations

from portwyrm.tables.access import AccessClient
from portwyrm.tables.access import RuntimeAccessCredential as AccessListCredential
from portwyrm.tables.access import RuntimeAccessList as AccessList
from portwyrm.tables.routing import SSLSettings


def indented(value: str, spaces: int = 2) -> str:
    prefix = " " * spaces
    return "\n".join(f"{prefix}{line}" if line else "" for line in value.splitlines())


def block_exploits() -> str:
    return "  include conf.d/include/block-exploits.conf;\n"


def listen(domain_names: tuple[str, ...], ssl: SSLSettings, ipv6: bool) -> list[str]:
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


def ssl_lines(ssl: SSLSettings, *, stream: bool = False) -> list[str]:
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
    return lines


def force_ssl_lines(ssl: SSLSettings) -> list[str]:
    if not ssl.certificate_id or not ssl.forced:
        return []
    condition = (
        "$http_x_forwarded_proto != https" if ssl.trust_forwarded_proto else "$scheme != https"
    )
    return [f"  if ({condition}) {{", "    return 301 https://$host$request_uri;", "  }"]


def access_lines(access_list: AccessList | None, password_file: str | None = None) -> list[str]:
    if access_list is None:
        return []
    lines: list[str] = []
    if access_list.credentials:
        lines.extend(
            [
                'auth_basic "Authorization required";',
                f"auth_basic_user_file /data/access/{password_file or access_list.id};",
            ]
        )
        if not access_list.pass_auth:
            lines.append('proxy_set_header Authorization "";')
    if access_list.clients:
        lines.extend(f"{client.directive} {client.address};" for client in access_list.clients)
        lines.append("deny all;")
    if access_list.credentials or access_list.clients:
        lines.append("satisfy any;" if access_list.satisfy_any else "satisfy all;")
    return lines


def asset_cache_lines() -> list[str]:
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


def acme_challenge_location() -> list[str]:
    return [
        "  location ^~ /.well-known/acme-challenge/ {",
        "    root /data/acme-challenge;",
        "    try_files $uri =404;",
        "  }",
    ]


def has_root_location(config: str) -> bool:
    compact = " ".join(config.replace("\n", " ").split())
    return "location / {" in compact


def render_htpasswd(access_list: AccessList) -> str:
    return "".join(f"{item.username}:{item.password_hash}\n" for item in access_list.credentials)


def merge_access_lists(access_lists: list[AccessList]) -> AccessList | None:
    """Combine selected lists into one deterministic, conservative Nginx policy."""
    if not access_lists:
        return None
    ordered = sorted(access_lists, key=lambda item: item.id)
    credentials: dict[str, AccessListCredential] = {}
    clients: dict[tuple[str, str], AccessClient] = {}
    for access_list in ordered:
        for credential in access_list.credentials:
            existing = credentials.get(credential.username)
            if existing is not None and existing.password_hash != credential.password_hash:
                raise ValueError(
                    f"conflicting credentials for {credential.username!r} in selected access lists"
                )
            credentials[credential.username] = credential
        for client in access_list.clients:
            clients[(str(client.directive), client.address)] = client
    first = ordered[0]
    return AccessList(
        id=first.id,
        name=" + ".join(item.name for item in ordered),
        credentials=[credentials[key] for key in sorted(credentials)],
        clients=[clients[key] for key in sorted(clients)],
        satisfy_any=all(item.satisfy_any for item in ordered),
        pass_auth=all(item.pass_auth for item in ordered),
    )


__all__ = [
    "access_lines",
    "acme_challenge_location",
    "asset_cache_lines",
    "block_exploits",
    "force_ssl_lines",
    "has_root_location",
    "indented",
    "listen",
    "merge_access_lists",
    "render_htpasswd",
    "ssl_lines",
]
