"""Signal-forwarding supervisor for the control plane and Nginx."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from portwyrm.api import create_app
from portwyrm.application import ControlPlane
from portwyrm.operations import LogRotator
from portwyrm.runtime.coordinator import RuntimeCoordinator


def seed_demo_proxy_host(control_plane: ControlPlane) -> None:
    """Create or repair the opt-in, DNS-free local Docker demonstration route."""
    domain = os.getenv("PORTWYRM_DEMO_HOST", "").strip().lower()
    if not domain:
        return
    payload = {
        "domain_names": [domain],
        "forward_scheme": "http",
        "forward_host": "127.0.0.1",
        "forward_port": 81,
        "enabled": 1,
        "certificate_id": 0,
        "access_list_id": 0,
        "allow_websocket_upgrade": 1,
        "caching_enabled": 0,
        "block_exploits": 0,
        "http2_support": 0,
        "ssl_forced": 0,
        "hsts_enabled": 0,
        "meta": {
            "managed_by": "portwyrm-demo",
            "purpose": "local reverse-proxy demonstration",
        },
    }
    existing = next(
        (
            row
            for row in control_plane.list("proxy-hosts")
            if row.get("meta", {}).get("managed_by") == "portwyrm-demo"
        ),
        None,
    )
    if existing is None:
        control_plane.create("proxy-hosts", payload)
    else:
        control_plane.update("proxy-hosts", existing["id"], payload)


def main() -> int:
    for directory in (
        Path("/data"),
        Path("/data/logs"),
        Path("/data/nginx"),
        Path("/etc/letsencrypt"),
    ):
        directory.mkdir(parents=True, exist_ok=True)

    app = create_app()
    control_plane = app.state.control_plane
    seed_demo_proxy_host(control_plane)
    runtime = app.state.runtime or RuntimeCoordinator(
        control_plane, "/data/nginx", validate=True, reload=False
    )
    runtime.reconcile()

    children = [
        subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "portwyrm.api:create_app",
                "--factory",
                "--host",
                "0.0.0.0",
                "--port",
                "81",
            ]
        ),
        subprocess.Popen(
            [
                "nginx",
                "-c",
                "/data/nginx/current/nginx.conf",
                "-p",
                "/data/nginx/current/",
                "-g",
                "daemon off;",
            ]
        ),
    ]
    stopping = False
    rotation_interval = max(60, int(os.getenv("PORTWYRM_LOG_ROTATION_INTERVAL", "172800")))
    next_rotation = time.monotonic() + rotation_interval

    def stop(signum: int, _frame: object) -> None:
        nonlocal stopping
        if stopping:
            return
        stopping = True
        for child in children:
            if child.poll() is None:
                child.send_signal(signum)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while True:
        if time.monotonic() >= next_rotation:
            rotation_results = [
                LogRotator(
                    path, max_bytes=int(os.getenv("PORTWYRM_LOG_MAX_BYTES", "10000000"))
                ).rotate_if_needed()
                for path in Path("/data/logs").glob("*.log")
            ]
            rotated = any(rotation_results)
            if rotated:
                subprocess.run(
                    [
                        "nginx",
                        "-s",
                        "reopen",
                        "-c",
                        "/data/nginx/current/nginx.conf",
                        "-p",
                        "/data/nginx/current/",
                    ],
                    check=False,
                )
            next_rotation = time.monotonic() + rotation_interval
        for child in children:
            code = child.poll()
            if code is not None:
                stop(signal.SIGTERM, None)
                deadline = time.monotonic() + 10
                for peer in children:
                    if peer.poll() is None:
                        try:
                            peer.wait(timeout=max(0, deadline - time.monotonic()))
                        except subprocess.TimeoutExpired:
                            peer.kill()
                return code
        time.sleep(0.2)


if __name__ == "__main__":
    raise SystemExit(main())
