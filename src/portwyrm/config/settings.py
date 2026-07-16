"""Environment-derived application settings without persistence behavior."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class PortwyrmSettings:
    backend: str = "sqlite"
    data_root: Path = Path("/data")
    sqlite_path: Path = Path("/data/portwyrm.sqlite")
    database_dsn: str | None = None
    database_host: str = "localhost"
    database_port: int | None = None
    database_name: str = "portwyrm"
    database_user: str = "portwyrm"
    database_password: str = ""
    database_async: bool = False
    nginx_runtime: bool = False
    nginx_root: Path = Path("/data/nginx")
    nginx_validate: bool = True
    nginx_reload: bool = False

    @classmethod
    def from_environment(cls) -> PortwyrmSettings:
        root = Path(os.getenv("PORTWYRM_DATA_ROOT", "/data"))
        backend = (
            os.getenv("PORTWYRM_PERSISTENCE", os.getenv("PORTWYRM_DB_BACKEND", "sqlite"))
            .strip()
            .lower()
        )
        default_port = (
            3306 if backend == "mysql" else 5432 if backend in {"postgres", "postgresql"} else None
        )
        raw_port = os.getenv("PORTWYRM_DATABASE_PORT")
        return cls(
            backend=backend,
            data_root=root,
            sqlite_path=Path(os.getenv("PORTWYRM_SQLITE_PATH", str(root / "portwyrm.sqlite"))),
            database_dsn=os.getenv("PORTWYRM_DATABASE_DSN") or None,
            database_host=os.getenv("PORTWYRM_DATABASE_HOST", "localhost"),
            database_port=int(raw_port) if raw_port else default_port,
            database_name=os.getenv("PORTWYRM_DATABASE_NAME", "portwyrm"),
            database_user=os.getenv("PORTWYRM_DATABASE_USER", "portwyrm"),
            database_password=os.getenv("PORTWYRM_DATABASE_PASSWORD", ""),
            database_async=_flag("PORTWYRM_DATABASE_ASYNC"),
            nginx_runtime=_flag("PORTWYRM_NGINX_RUNTIME"),
            nginx_root=Path(os.getenv("PORTWYRM_NGINX_ROOT", str(root / "nginx"))),
            nginx_validate=_flag("PORTWYRM_NGINX_VALIDATE", True),
            nginx_reload=_flag("PORTWYRM_NGINX_RELOAD"),
        )
