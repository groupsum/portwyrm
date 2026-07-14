"""Signal-forwarding supervisor for the control plane and Nginx."""

from __future__ import annotations

import signal
import subprocess
import sys
import time
from pathlib import Path

from portwyrm.operations.runtime import repository_config_from_environment
from portwyrm.persistence import create_repository
from portwyrm.persistent import PersistentControlPlane
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
