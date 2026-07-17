"""Bounded DNS, TCP, TLS, and HTTP reachability probing."""

from __future__ import annotations

import asyncio
import contextlib
import socket
import ssl
import time
from dataclasses import dataclass

from portwyrm.health import ProbePhase, ReachabilityState


@dataclass(frozen=True, slots=True)
class ProbeTarget:
    host: str
    port: int
    scheme: str = "http"


@dataclass(frozen=True, slots=True)
class ProbeResult:
    status: ReachabilityState
    phase: ProbePhase
    checked_at: int
    latency_ms: int | None = None
    http_status: int | None = None
    error_code: str | None = None
    error_detail: str | None = None


class UpstreamProber:
    def __init__(
        self,
        *,
        dns_timeout: float = 3.0,
        connect_timeout: float = 3.0,
        tls_timeout: float = 5.0,
        http_timeout: float = 5.0,
    ) -> None:
        self.dns_timeout = dns_timeout
        self.connect_timeout = connect_timeout
        self.tls_timeout = tls_timeout
        self.http_timeout = http_timeout

    async def probe(self, target: ProbeTarget) -> ProbeResult:
        started = time.perf_counter()
        checked_at = int(time.time())
        phase = ProbePhase.DNS
        writer: asyncio.StreamWriter | None = None
        raw_socket: socket.socket | None = None
        try:
            loop = asyncio.get_running_loop()
            addresses = await asyncio.wait_for(
                loop.getaddrinfo(
                    target.host,
                    target.port,
                    type=socket.SOCK_STREAM,
                    proto=socket.IPPROTO_TCP,
                ),
                timeout=self.dns_timeout,
            )
            if not addresses:
                raise OSError("DNS returned no addresses")

            phase = ProbePhase.CONNECT
            family, socktype, proto, _canonical, sockaddr = addresses[0]
            raw_socket = socket.socket(family, socktype, proto)
            raw_socket.setblocking(False)
            await asyncio.wait_for(
                loop.sock_connect(raw_socket, sockaddr),
                timeout=self.connect_timeout,
            )

            if target.scheme.casefold() == "https":
                phase = ProbePhase.TLS
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        sock=raw_socket,
                        ssl=context,
                        server_hostname=target.host,
                        ssl_handshake_timeout=self.tls_timeout,
                    ),
                    timeout=self.tls_timeout,
                )
            else:
                reader, writer = await asyncio.open_connection(sock=raw_socket)
            raw_socket = None

            phase = ProbePhase.HTTP
            request = (
                f"HEAD / HTTP/1.1\r\nHost: {target.host}\r\n"
                "User-Agent: portwyrm-health/1\r\nConnection: close\r\n\r\n"
            )
            writer.write(request.encode("ascii", errors="strict"))
            await asyncio.wait_for(writer.drain(), timeout=self.http_timeout)
            status_line = await asyncio.wait_for(reader.readline(), timeout=self.http_timeout)
            parts = status_line.decode("ascii", errors="replace").strip().split()
            if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
                raise ValueError("upstream did not return a valid HTTP status line")
            return ProbeResult(
                status=ReachabilityState.ONLINE,
                phase=ProbePhase.HTTP,
                checked_at=checked_at,
                latency_ms=max(0, round((time.perf_counter() - started) * 1000)),
                http_status=int(parts[1]),
            )
        except Exception as exc:
            detail = " ".join(str(exc).split())[:500] or type(exc).__name__
            return ProbeResult(
                status=ReachabilityState.OFFLINE,
                phase=phase,
                checked_at=checked_at,
                latency_ms=max(0, round((time.perf_counter() - started) * 1000)),
                error_code=type(exc).__name__,
                error_detail=detail,
            )
        finally:
            if writer is not None:
                writer.close()
                with contextlib.suppress(OSError, ssl.SSLError):
                    await writer.wait_closed()
            if raw_socket is not None:
                raw_socket.close()


__all__ = ["ProbeResult", "ProbeTarget", "UpstreamProber"]
