"""Minimal operational HTTP runtime used by the container supervisor."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def repository_config_from_environment() -> dict[str, Any]:
    backend = os.getenv("PORTWYRM_DB_BACKEND", "sqlite").lower()
    backend = {"postgres": "postgresql", "mariadb": "mysql"}.get(backend, backend)
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
    """Run the composed Tigrbl application with its native engine configuration."""
    import uvicorn

    uvicorn.run(
        "portwyrm.api:create_app",
        factory=True,
        host=os.getenv("PORTWYRM_ADMIN_HOST", "0.0.0.0"),
        port=int(os.getenv("PORTWYRM_ADMIN_PORT", "81")),
    )


if __name__ == "__main__":
    serve()
