"""Tigrbl EngineSpec selection for Portwyrm persistence profiles.

Engine construction and session ownership belong to installed
``tigrbl_engine_*`` packages. This module only translates Portwyrm deployment
configuration into public Tigrbl factory values.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any
from uuid import uuid4

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
        namespace = getattr(repository, "_tigrbl_namespace", None)
        if namespace is None:
            namespace = uuid4().hex
            repository._tigrbl_namespace = namespace
        return {
            "kind": "sqlite",
            "async": False,
            "mode": "memory",
            "instance": namespace,
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


def engine_for_config(config: Mapping[str, Any]) -> Any:
    """Translate deployment configuration without constructing a legacy repository."""
    backend = str(config.get("backend", "sqlite")).lower()
    backend = {"postgres": "postgresql", "mariadb": "mysql"}.get(backend, backend)
    if backend == "memory":
        return {
            "kind": "sqlite",
            "async": False,
            "mode": "memory",
            "instance": uuid4().hex,
        }
    if backend == "sqlite":
        return sqlitef(str(config["sqlite_path"]), async_=False)
    if backend == "filesystem":
        path = Path(config["filesystem_root"]) / "portwyrm.tables.sqlite"
        return sqlitef(str(path), async_=False)
    if backend == "hybrid":
        metadata = config.get("metadata")
        if not isinstance(metadata, Mapping):
            metadata = {**config, "backend": str(config.get("metadata_backend", "sqlite"))}
        return engine_for_config(metadata)
    if backend == "postgresql":
        database = config.get("postgresql", {})
        if not isinstance(database, Mapping):
            raise TypeError("postgresql configuration must be a mapping")
        return pg(
            async_=False,
            user=str(database.get("user", "portwyrm")),
            pwd=str(database.get("password", database.get("pwd", ""))),
            host=str(database.get("host", "localhost")),
            port=int(database.get("port", 5432)),
            name=str(database.get("dbname", database.get("name", "portwyrm"))),
        )
    if backend == "mysql":
        database = config.get("mysql", {})
        if not isinstance(database, Mapping):
            raise TypeError("mysql configuration must be a mapping")
        return {
            "kind": "mysql",
            "async": False,
            "user": str(database.get("user", "portwyrm")),
            "pwd": str(database.get("password", database.get("pwd", ""))),
            "host": str(database.get("host", "localhost")),
            "port": int(database.get("port", 3306)),
            "db": str(database.get("database", database.get("name", "portwyrm"))),
            "pool_size": int(database.get("pool_size", 10)),
            "max": int(database.get("max", 20)),
        }
    raise TypeError(f"Tigrbl engine is not available for {backend!r}")


def sqlite_table_path(repository: Repository) -> Path | None:
    if isinstance(repository, SQLiteRepository):
        return repository.path
    if isinstance(repository, FilesystemRepository):
        return repository.root / "portwyrm.tables.sqlite"
    if isinstance(repository, HybridRepository):
        return sqlite_table_path(repository.metadata)
    return None
