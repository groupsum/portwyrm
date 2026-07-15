"""Private Nginx stub-status collection for authenticated system diagnostics."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any
from urllib.request import Request, urlopen

_ACTIVE = re.compile(r"Active connections:\s*(\d+)")
_COUNTERS = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s*$", re.MULTILINE)
_STATES = re.compile(r"Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)")


def parse_stub_status(payload: str) -> dict[str, Any]:
    """Parse the stable text format emitted by ngx_http_stub_status_module."""

    active = _ACTIVE.search(payload)
    counters = _COUNTERS.search(payload)
    states = _STATES.search(payload)
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
    """Read the loopback-only Nginx status endpoint with a bounded timeout."""

    def __init__(
        self,
        url: str = "http://127.0.0.1:8081/nginx-status",
        *,
        timeout: float = 1.0,
        opener: Callable[..., Any] = urlopen,
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.opener = opener

    def collect(self) -> dict[str, Any]:
        request = Request(self.url, headers={"User-Agent": "portwyrm-status/1"})
        with self.opener(request, timeout=self.timeout) as response:
            payload = response.read().decode("utf-8", errors="strict")
        return parse_stub_status(payload)
