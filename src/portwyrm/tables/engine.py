"""Tigrbl EngineSpec selection for Portwyrm persistence profiles.

Engine construction and session ownership belong to installed
``tigrbl_engine_*`` packages. This module only translates Portwyrm deployment
configuration into public Tigrbl factory values.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tigrbl.factories.engine import pg, sqlitef

from portwyrm.persistence import (
    FilesystemRepository,
    HybridRepository,
    MemoryRepository,
    MySQLRepository,
    PostgreSQLRepository,
    Repository,
    SQLiteRepository,
)


def engine_for_repository(repository: Repository) -> Any:
    """Translate import-source configuration into a native Tigrbl EngineSpec value."""
    if isinstance(repository, MemoryRepository):
        return {
            "kind": "sqlite",
            "async": False,
            "mode": "memory",
            "instance": id(repository),
        }
    if isinstance(repository, SQLiteRepository):
        return sqlitef(str(repository.path), async_=False)
    if isinstance(repository, FilesystemRepository):
        return sqlitef(str(repository.root / "portwyrm.tables.sqlite"), async_=False)
    if isinstance(repository, HybridRepository):
        return engine_for_repository(repository.metadata)
    if isinstance(repository, PostgreSQLRepository):
        config = dict(repository.config)
        return pg(
            async_=False,
            user=str(config.get("user", "app")),
            pwd=str(config.get("password", config.get("pwd", "secret"))),
            host=str(config.get("host", "localhost")),
            port=int(config.get("port", 5432)),
            name=str(config.get("dbname", config.get("name", "portwyrm"))),
        )
    if isinstance(repository, MySQLRepository):
        config = dict(repository.config)
        return {
            "kind": "mysql",
            "async": False,
            "user": str(config.get("user", "portwyrm")),
            "pwd": str(config.get("password", config.get("pwd", ""))),
            "host": str(config.get("host", "localhost")),
            "port": int(config.get("port", 3306)),
            "db": str(config.get("database", config.get("name", "portwyrm"))),
            "pool_size": int(config.get("pool_size", 10)),
            "max": int(config.get("max", 20)),
        }
    raise TypeError(f"Tigrbl engine is not available for {repository.backend_name!r}")


def sqlite_table_path(repository: Repository) -> Path | None:
    if isinstance(repository, SQLiteRepository):
        return repository.path
    if isinstance(repository, FilesystemRepository):
        return repository.root / "portwyrm.tables.sqlite"
    if isinstance(repository, HybridRepository):
        return sqlite_table_path(repository.metadata)
    return None
