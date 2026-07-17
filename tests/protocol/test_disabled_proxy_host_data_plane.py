"""T2 protocol coverage for disabled proxy-host isolation."""

from __future__ import annotations

import os
import sys
import time
import uuid
from contextlib import ExitStack
from http.server import ThreadingHTTPServer

import pytest

from tests.integration.test_s1_container_protocols import (
    _docker,
    _http,
    _HTTPHandler,
    _json_request,
    _published_port,
    _server,
    _wait_http,
    _wait_ready,
)

pytestmark = pytest.mark.skipif(
    os.getenv("PORTWYRM_RUN_DOCKER_TESTS") != "1",
    reason="set PORTWYRM_RUN_DOCKER_TESTS=1 to run real container protocols",
)


def test_disabled_proxy_host_data_plane_contract() -> None:
    image = os.getenv("PORTWYRM_TEST_IMAGE", "portwyrm:s1-test")
    suffix = uuid.uuid4().hex[:10]
    network = f"portwyrm-disabled-{suffix}"
    container = f"portwyrm-disabled-{suffix}"
    http_server = ThreadingHTTPServer(("0.0.0.0", 0), _HTTPHandler)
    _HTTPHandler.requests = {}

    with ExitStack() as stack:
        stack.enter_context(_server(http_server))
        linux_host_network = sys.platform.startswith("linux")
        if not linux_host_network:
            _docker("network", "create", network)
            stack.callback(lambda: _docker("network", "rm", network, check=False))
        network_args = (
            ["--network", "host"]
            if linux_host_network
            else [
                "--network",
                network,
                "--add-host",
                "host.docker.internal:host-gateway",
                "-p",
                "127.0.0.1::80",
                "-p",
                "127.0.0.1::81",
            ]
        )
        _docker(
            "run",
            "-d",
            "--name",
            container,
            *network_args,
            "-e",
            "INITIAL_ADMIN_EMAIL=admin@example.test",
            "-e",
            "INITIAL_ADMIN_PASSWORD=correct-password",
            "-e",
            "PORTWYRM_INITIAL_ADMIN_REQUIRE_PASSWORD_CHANGE=0",
            image,
        )
        stack.callback(lambda: _docker("rm", "-f", container, check=False))

        data_port = 80 if linux_host_network else _published_port(container, "80/tcp")
        api_port = 81 if linux_host_network else _published_port(container, "81/tcp")
        upstream_host = "127.0.0.1" if linux_host_network else "host.docker.internal"
        _wait_ready(api_port, container)
        token = _json_request(
            f"http://127.0.0.1:{api_port}/api/tokens",
            method="POST",
            payload={
                "identity": "admin@example.test",
                "secret": "correct-password",
                "scope": "user",
            },
        )["result"]["token"]
        host = _json_request(
            f"http://127.0.0.1:{api_port}/api/nginx/proxy-hosts",
            method="POST",
            token=token,
            payload={
                "domain_names": ["disabled.example.test"],
                "forward_scheme": "http",
                "forward_host": upstream_host,
                "forward_port": http_server.server_port,
                "enabled": 1,
            },
        )
        _wait_http(
            data_port,
            "disabled.example.test",
            "/proof",
            lambda response: response[0] == 200 and response[2] == b"portwyrm-upstream:/proof",
        )
        deadline = time.monotonic() + 2
        while not _HTTPHandler.requests and time.monotonic() < deadline:
            time.sleep(0.01)
        assert _HTTPHandler.requests.get("/proof") == 1
        _json_request(
            f"http://127.0.0.1:{api_port}/api/nginx/proxy-hosts/{host['id']}/disable",
            method="POST",
            token=token,
        )
        response = _wait_http(
            data_port,
            "disabled.example.test",
            "/proof",
            lambda candidate: candidate[0] == 503,
        )
        assert response[0] == 503
        assert b"Portwyrm is running" not in response[2]
        disabled_baseline = sum(_HTTPHandler.requests.values())
        time.sleep(0.1)
        assert _http(data_port, "disabled.example.test", "/proof")[0] == 503
        assert sum(_HTTPHandler.requests.values()) == disabled_baseline
