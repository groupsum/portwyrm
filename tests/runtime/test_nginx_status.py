from __future__ import annotations

from io import BytesIO

import pytest

from portwyrm.runtime.telemetry import NginxStatusClient, parse_stub_status

STATUS = """Active connections: 12
server accepts handled requests
 1042 1042 9281
Reading: 1 Writing: 3 Waiting: 8
"""


class _Response(BytesIO):
    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def test_parse_stub_status_exposes_connection_states_and_counters() -> None:
    assert parse_stub_status(STATUS) == {
        "active": 12,
        "accepts": 1042,
        "handled": 1042,
        "requests": 9281,
        "reading": 1,
        "writing": 3,
        "waiting": 8,
    }


def test_parse_stub_status_rejects_incomplete_payloads() -> None:
    with pytest.raises(ValueError, match="invalid Nginx stub_status response"):
        parse_stub_status("Active connections: 2\n")


def test_status_client_uses_bounded_loopback_request() -> None:
    observed: dict[str, object] = {}

    def opener(request: object, *, timeout: float) -> _Response:
        observed["url"] = request.full_url  # type: ignore[attr-defined]
        observed["timeout"] = timeout
        return _Response(STATUS.encode())

    result = NginxStatusClient(timeout=0.75, opener=opener).collect()
    assert result["active"] == 12
    assert observed == {"url": "http://127.0.0.1:8081/nginx-status", "timeout": 0.75}
