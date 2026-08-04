"""Deterministic configuration for Portwyrm's opaque QUIC data plane."""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any


def render_quic_routes(routes: Iterable[Any]) -> str:
    enabled = [route for route in routes if route.enabled]
    document = {
        "version": 1,
        "listeners": [
            {
                "listen_address": address,
                "incoming_port": port,
                "routes": [
                    {
                        "server_name": route.server_name,
                        "alpn": route.alpn,
                        "target": route.target,
                        "target_port": route.target_port,
                        "idle_timeout_seconds": route.idle_timeout_seconds,
                    }
                    for route in sorted(group, key=lambda item: item.server_name)
                ],
            }
            for (address, port), group in _groups(enabled)
        ],
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"


def _groups(routes: list[Any]) -> list[tuple[tuple[str, int], list[Any]]]:
    grouped: dict[tuple[str, int], list[Any]] = {}
    for route in routes:
        grouped.setdefault((route.listen_address, route.incoming_port), []).append(route)
    return sorted(grouped.items())


__all__ = ["render_quic_routes"]
