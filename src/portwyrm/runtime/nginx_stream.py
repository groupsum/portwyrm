"""TCP and UDP stream rendering."""

from __future__ import annotations

from portwyrm.tables.routing import SSLSettings, Stream

from .nginx_models import PlatformConfig
from .nginx_primitives import ssl_lines


def render_stream(platform: PlatformConfig, stream: Stream) -> str:
    if not stream.enabled:
        return f"# stream {stream.id} disabled\n"
    blocks: list[str] = []
    if stream.tcp_forwarding:
        ssl_suffix = " ssl" if stream.certificate_id else ""
        lines = ["server {", f"  listen {stream.incoming_port}{ssl_suffix};"]
        if platform.ipv6:
            lines.append(f"  listen [::]:{stream.incoming_port}{ssl_suffix};")
        if stream.certificate_id:
            lines.extend(ssl_lines(SSLSettings(certificate_id=stream.certificate_id), stream=True))
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
        if platform.ipv6:
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


__all__ = ["render_stream"]
