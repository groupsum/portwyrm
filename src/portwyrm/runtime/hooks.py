"""Production command hooks for Nginx validation and reload."""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

Runner = Callable[..., subprocess.CompletedProcess[str]]


class NginxCommandHooks:
    def __init__(
        self,
        nginx_binary: str = "nginx",
        *,
        runner: Runner = subprocess.run,
    ) -> None:
        self.nginx_binary = nginx_binary
        self.runner = runner

    def _run(self, args: Sequence[str]) -> None:
        result = self.runner(
            list(args),
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            detail = (result.stderr or result.stdout or "command failed").strip()
            raise RuntimeError(detail)

    def validate(self, generation: Path) -> None:
        self._run(
            [
                self.nginx_binary,
                "-t",
                "-c",
                str(generation / "nginx.conf"),
                "-p",
                f"{generation}{Path('/')}",
            ]
        )

    def reload(self, generation: Path) -> None:
        self._run(
            [
                self.nginx_binary,
                "-c",
                str(generation / "nginx.conf"),
                "-p",
                f"{generation}{Path('/')}",
                "-s",
                "reload",
            ]
        )
