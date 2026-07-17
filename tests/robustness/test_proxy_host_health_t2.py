"""T2 robustness coverage for proxy-host operational health."""

from __future__ import annotations

import asyncio
import socket

from portwyrm.health import ProbePhase, ReachabilityState
from portwyrm.runtime import ProbeTarget, UpstreamProber
from portwyrm.runtime.health_scheduler import ProxyHostHealthScheduler


def test_real_http_probe_classifies_reachable_and_unreachable_upstreams() -> None:
    async def exercise() -> None:
        async def respond(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(respond, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        prober = UpstreamProber(dns_timeout=1, connect_timeout=1, http_timeout=1)
        try:
            online = await prober.probe(ProbeTarget("127.0.0.1", port))
        finally:
            server.close()
            await server.wait_closed()
        assert online.status == ReachabilityState.ONLINE
        assert online.phase == ProbePhase.HTTP
        assert online.http_status == 204

        reserved = socket.socket()
        reserved.bind(("127.0.0.1", 0))
        closed_port = reserved.getsockname()[1]
        reserved.close()
        offline = await prober.probe(ProbeTarget("127.0.0.1", closed_port))
        assert offline.status == ReachabilityState.OFFLINE
        assert offline.phase == ProbePhase.CONNECT
        assert offline.error_code

    asyncio.run(exercise())


def test_scheduler_invokes_the_same_probe_operation_for_enabled_hosts_only() -> None:
    class Operations:
        def __init__(self) -> None:
            self.probed: list[int] = []

        async def health_list(self, payload: dict[str, object]) -> dict[str, object]:
            return {
                "items": [
                    {"id": 1, "administrative_state": "enabled"},
                    {"id": 2, "administrative_state": "disabled"},
                    {"id": 3, "administrative_state": "enabled"},
                ]
            }

        async def probe(self, payload: dict[str, int]) -> None:
            self.probed.append(payload["id"])

    class Core:
        RoutingHostStore = Operations()

    class App:
        core = Core()

    scheduler = ProxyHostHealthScheduler(App(), concurrency=1)
    asyncio.run(scheduler.sweep())
    assert Core.RoutingHostStore.probed == [1, 3]
