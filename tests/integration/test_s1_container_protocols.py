from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import secrets
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, ClassVar

import pytest
from websockets.sync.server import serve

pytestmark = pytest.mark.skipif(
    os.getenv("PORTWYRM_RUN_DOCKER_TESTS") != "1",
    reason="set PORTWYRM_RUN_DOCKER_TESTS=1 to run real container protocols",
)


class _HTTPHandler(BaseHTTPRequestHandler):
    requests: ClassVar[dict[str, int]] = {}

    def do_GET(self) -> None:
        self.requests[self.path] = self.requests.get(self.path, 0) + 1
        body = f"portwyrm-upstream:{self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class _TCPEcho(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.sendall(self.request.recv(4096))


class _UDPEcho(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        sock.sendto(data, self.client_address)


@contextmanager
def _server(server: Any) -> Iterator[Any]:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextmanager
def _websocket_server() -> Iterator[int]:
    def echo(connection: Any) -> None:
        for message in connection:
            connection.send(message)

    server = serve(echo, "0.0.0.0", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.socket.getsockname()[1])
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args],
        check=check,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _published_port(container: str, target: str) -> int:
    output = _docker("port", container, target).stdout.strip()
    return int(output.rsplit(":", 1)[1])


def _json_request(
    url: str,
    *,
    method: str = "GET",
    token: str | None = None,
    payload: dict[str, Any] | None = None,
) -> Any:
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read())


def _wait_ready(api_port: int, container: str) -> None:
    for _attempt in range(60):
        try:
            result = _json_request(f"http://127.0.0.1:{api_port}/health/ready")
            if result["status"] == "ok":
                return
        except (OSError, urllib.error.URLError):
            time.sleep(0.25)
    logs = _docker("logs", container, check=False).stdout
    raise AssertionError(f"Portwyrm did not become ready:\n{logs}")


def _http(port: int, host: str, path: str = "/") -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request("GET", path, headers={"Host": host})
    response = connection.getresponse()
    body = response.read()
    headers = {key.lower(): value for key, value in response.getheaders()}
    connection.close()
    return response.status, headers, body


def _websocket_echo(port: int, host: str, message: bytes) -> bytes:
    key = base64.b64encode(secrets.token_bytes(16)).decode()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        connection.sendall(
            (
                "GET /socket HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n"
            ).encode()
        )
        handshake = b""
        while b"\r\n\r\n" not in handshake:
            handshake += connection.recv(4096)
        assert handshake.startswith(b"HTTP/1.1 101")
        expected_accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        )
        assert expected_accept in handshake

        mask = secrets.token_bytes(4)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(message))
        connection.sendall(bytes((0x81, 0x80 | len(message))) + mask + masked)
        header = connection.recv(2)
        assert header[0] & 0x0F == 1
        length = header[1] & 0x7F
        return connection.recv(length)


def _wait_websocket_echo(port: int, host: str, message: bytes) -> bytes:
    deadline = time.monotonic() + 10
    while True:
        try:
            return _websocket_echo(port, host, message)
        except AssertionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)


def _wait_http(
    port: int, host: str, path: str, predicate: Callable[[tuple[int, dict[str, str], bytes]], bool]
) -> tuple[int, dict[str, str], bytes]:
    deadline = time.monotonic() + 10
    while True:
        try:
            result = _http(port, host, path)
            if predicate(result):
                return result
        except OSError:
            pass
        if time.monotonic() >= deadline:
            raise AssertionError(f"Nginx route for {host}{path} did not converge")
        time.sleep(0.2)


def _wait_tcp_echo(port: int, message: bytes) -> None:
    deadline = time.monotonic() + 10
    while True:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1) as client:
                client.sendall(message)
                if client.recv(64) == message:
                    return
        except OSError:
            pass
        if time.monotonic() >= deadline:
            raise AssertionError("TCP stream did not converge")
        time.sleep(0.2)


def _wait_udp_echo(port: int, message: bytes) -> None:
    deadline = time.monotonic() + 10
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(1)
                client.sendto(message, ("127.0.0.1", port))
                if client.recv(64) == message:
                    return
        except OSError:
            pass
        if time.monotonic() >= deadline:
            raise AssertionError("UDP stream did not converge")
        time.sleep(0.2)


def test_s1_real_http_websocket_cache_redirect_dead_tcp_and_udp() -> None:
    image = os.getenv("PORTWYRM_TEST_IMAGE", "portwyrm:s1-test")
    suffix = uuid.uuid4().hex[:10]
    network = f"portwyrm-s1-{suffix}"
    container = f"portwyrm-s1-{suffix}"
    http_server = ThreadingHTTPServer(("0.0.0.0", 0), _HTTPHandler)
    tcp_server = socketserver.ThreadingTCPServer(("0.0.0.0", 0), _TCPEcho)
    udp_server = socketserver.ThreadingUDPServer(("0.0.0.0", 0), _UDPEcho)
    _HTTPHandler.requests = {}

    with ExitStack() as stack:
        stack.enter_context(_server(http_server))
        stack.enter_context(_server(tcp_server))
        stack.enter_context(_server(udp_server))
        websocket_port = stack.enter_context(_websocket_server())
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
                "-p",
                "127.0.0.1::19091/tcp",
                "-p",
                "127.0.0.1::19092/udp",
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

        http_port = 80 if linux_host_network else _published_port(container, "80/tcp")
        api_port = 81 if linux_host_network else _published_port(container, "81/tcp")
        tcp_port = 19091 if linux_host_network else _published_port(container, "19091/tcp")
        udp_port = 19092 if linux_host_network else _published_port(container, "19092/udp")
        upstream_host = "127.0.0.1" if linux_host_network else "host.docker.internal"
        _wait_ready(api_port, container)
        control_ui = _http(api_port, "127.0.0.1", "/ui/")
        assert control_ui[0] == 200
        assert b"Portwyrm Control Plane" in control_ui[2]
        data_plane_ui = _wait_http(
            http_port,
            "127.0.0.1",
            "/ui/",
            lambda result: result[0] in {200, 301, 302, 307, 308, 404},
        )
        assert b"Portwyrm Control Plane" not in data_plane_ui[2]
        login = _json_request(
            f"http://127.0.0.1:{api_port}/api/tokens",
            method="POST",
            payload={
                "identity": "admin@example.test",
                "secret": "correct-password",
                "scope": "user",
            },
        )
        token = login["result"]["token"]

        def create(path: str, payload: dict[str, Any]) -> None:
            _json_request(
                f"http://127.0.0.1:{api_port}{path}",
                method="POST",
                token=token,
                payload=payload,
            )

        create(
            "/api/nginx/proxy-hosts",
            {
                "domain_names": ["app.example.test"],
                "forward_scheme": "http",
                "forward_host": upstream_host,
                "forward_port": http_server.server_port,
                "caching_enabled": 1,
                "enabled": 1,
            },
        )
        assert (
            _wait_http(
                http_port,
                "app.example.test",
                "/",
                lambda result: result[2] == b"portwyrm-upstream:/",
            )[2]
            == b"portwyrm-upstream:/"
        )
        create(
            "/api/nginx/proxy-hosts",
            {
                "domain_names": ["socket.example.test"],
                "forward_scheme": "http",
                "forward_host": upstream_host,
                "forward_port": websocket_port,
                "allow_websocket_upgrade": 1,
                "enabled": 1,
            },
        )
        assert _wait_websocket_echo(http_port, "socket.example.test", b"hello") == b"hello"
        create(
            "/api/nginx/redirection-hosts",
            {
                "domain_names": ["old.example.test"],
                "forward_domain_name": "new.example.test",
                "forward_scheme": "http",
                "forward_http_code": 308,
                "preserve_path": 1,
                "enabled": 1,
            },
        )
        redirect = _wait_http(
            http_port,
            "old.example.test",
            "/path?value=1",
            lambda result: result[0] == 308,
        )
        assert redirect[1]["location"] == "http://new.example.test/path?value=1"
        create(
            "/api/nginx/dead-hosts",
            {"domain_names": ["gone.example.test"], "enabled": 1},
        )
        assert (
            _wait_http(http_port, "gone.example.test", "/", lambda result: result[0] == 404)[0]
            == 404
        )
        create(
            "/api/nginx/streams",
            {
                "incoming_port": 19091,
                "forwarding_host": upstream_host,
                "forwarding_port": tcp_server.server_address[1],
                "tcp_forwarding": 1,
                "udp_forwarding": 0,
                "enabled": 1,
            },
        )
        _wait_tcp_echo(tcp_port, b"tcp-echo")
        create(
            "/api/nginx/streams",
            {
                "incoming_port": 19092,
                "forwarding_host": upstream_host,
                "forwarding_port": udp_server.server_address[1],
                "tcp_forwarding": 0,
                "udp_forwarding": 1,
                "enabled": 1,
            },
        )
        _wait_udp_echo(udp_port, b"udp-echo")

        assert _http(http_port, "app.example.test", "/asset.css")[2].endswith(b"/asset.css")
        assert _http(http_port, "app.example.test", "/asset.css")[2].endswith(b"/asset.css")
        assert _HTTPHandler.requests["/asset.css"] == 1
