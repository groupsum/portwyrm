"""Minimal operational HTTP runtime used by the container supervisor."""

from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from portwyrm import __version__
from portwyrm.persistence import create_repository

from .health import HealthService


def repository_config_from_environment() -> dict[str, Any]:
    backend = os.getenv("PORTWYRM_DB_BACKEND", "sqlite")
    data_root = Path(os.getenv("PORTWYRM_DATA_ROOT", str(Path.cwd() / ".portwyrm")))
    config: dict[str, Any] = {
        "backend": backend,
        "data_root": data_root,
        "sqlite_path": Path(os.getenv("PORTWYRM_SQLITE_PATH", str(data_root / "portwyrm.sqlite"))),
        "filesystem_root": Path(
            os.getenv("PORTWYRM_FILESYSTEM_ROOT", str(data_root / "repository"))
        ),
        "blob_root": Path(os.getenv("PORTWYRM_BLOB_ROOT", str(data_root / "blobs"))),
    }
    prefix = "PORTWYRM_POSTGRES_" if backend == "postgresql" else "PORTWYRM_MYSQL_"
    if backend in {"postgresql", "mysql"}:
        database_config = {
            "host": os.getenv(f"{prefix}HOST", "localhost"),
            "port": int(os.getenv(f"{prefix}PORT", "5432" if backend == "postgresql" else "3306")),
            "user": os.getenv(f"{prefix}USER", "portwyrm"),
            "password": os.getenv(f"{prefix}PASSWORD", ""),
            "dbname" if backend == "postgresql" else "database": os.getenv(
                f"{prefix}DATABASE", "portwyrm"
            ),
        }
        config[backend] = database_config
    return config


def serve() -> None:
    repository = create_repository(repository_config_from_environment())
    health = HealthService(repository)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/health/live":
                self._json(HTTPStatus.OK, health.live())
            elif self.path == "/health/ready":
                payload = health.ready()
                status = (
                    HTTPStatus.OK if payload["status"] == "ok" else HTTPStatus.SERVICE_UNAVAILABLE
                )
                self._json(status, payload)
            elif self.path == "/version":
                self._json(HTTPStatus.OK, {"version": __version__})
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def log_message(self, format: str, *args: object) -> None:
            return

        def _json(self, status: HTTPStatus, payload: object) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    address = os.getenv("PORTWYRM_ADMIN_HOST", "0.0.0.0")
    port = int(os.getenv("PORTWYRM_ADMIN_PORT", "81"))
    ThreadingHTTPServer((address, port), Handler).serve_forever()


if __name__ == "__main__":
    serve()
