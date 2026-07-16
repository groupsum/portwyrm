"""Signal-forwarding supervisor for the control plane and Nginx."""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

from portwyrm.api import create_app
from portwyrm.config import PortwyrmSettings
from portwyrm.runtime.bootstrap import seed_demo_proxy_host
from portwyrm.runtime.logs import LogRotator


async def prepare_runtime() -> None:
    """Create the initial immutable generation before Nginx starts."""

    settings = PortwyrmSettings.from_environment()
    app = create_app(settings=replace(settings, nginx_reload=False))
    resources = app.state.control_plane
    await seed_demo_proxy_host(resources)
    if app.state.runtime is not None:
        await app.state.runtime.reconcile()


def main() -> int:
    for directory in (
        Path("/data"),
        Path("/data/logs"),
        Path("/data/nginx"),
        Path("/etc/letsencrypt"),
    ):
        directory.mkdir(parents=True, exist_ok=True)

    asyncio.run(prepare_runtime())

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
