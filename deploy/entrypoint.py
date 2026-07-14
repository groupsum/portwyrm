"""Signal-forwarding supervisor for the control plane and Nginx."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from portwyrm.application import PersistentControlPlane
from portwyrm.operations import LogRotator, UpgradeManager, default_upgrades
from portwyrm.operations.runtime import repository_config_from_environment
from portwyrm.persistence import create_repository
from portwyrm.runtime.coordinator import RuntimeCoordinator


def main() -> int:
    for directory in (
        Path("/data"),
        Path("/data/logs"),
        Path("/data/nginx"),
        Path("/etc/letsencrypt"),
    ):
        directory.mkdir(parents=True, exist_ok=True)

    repository = create_repository(repository_config_from_environment())
    UpgradeManager(repository, default_upgrades()).run()
    control_plane = PersistentControlPlane(repository)
    RuntimeCoordinator(control_plane, "/data/nginx", validate=True, reload=False).reconcile()

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
