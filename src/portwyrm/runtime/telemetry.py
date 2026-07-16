"""Private Nginx stub-status telemetry."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any
from urllib.request import Request, urlopen

_ACTIVE = re.compile(r"Active connections:\s*(\d+)")
_COUNTERS = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s*$", re.MULTILINE)
_STATES = re.compile(r"Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)")


def parse_stub_status(payload: str) -> dict[str, Any]:
    active, counters, states = (
        _ACTIVE.search(payload),
        _COUNTERS.search(payload),
        _STATES.search(payload),
    )
    if active is None or counters is None or states is None:
        raise ValueError("invalid Nginx stub_status response")
    return {
        "active": int(active.group(1)),
        "accepts": int(counters.group(1)),
        "handled": int(counters.group(2)),
        "requests": int(counters.group(3)),
        "reading": int(states.group(1)),
        "writing": int(states.group(2)),
        "waiting": int(states.group(3)),
    }


class NginxStatusClient:
    def __init__(
        self,
        url: str = "http://127.0.0.1:8081/nginx-status",
        *,
        timeout: float = 1.0,
        opener: Callable[..., Any] = urlopen,
    ) -> None:
        self.url, self.timeout, self.opener = url, timeout, opener

    def collect(self) -> dict[str, Any]:
        request = Request(self.url, headers={"User-Agent": "portwyrm-status/1"})
        with self.opener(request, timeout=self.timeout) as response:
            return parse_stub_status(response.read().decode("utf-8", errors="strict"))


__all__ = ["NginxStatusClient", "parse_stub_status"]
