"""Tigrbl engine selection aligned with Portwyrm persistence profiles."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from tigrbl.engine import register_engine
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


class _MySQLEngineRegistration:
    """Synchronous SQLAlchemy provider for Tigrbl's MySQL/MariaDB profile."""

    def build(self, *, mapping: dict[str, object], spec: Any, dsn: str | None) -> Any:
        config = dict(mapping)
        url = dsn or URL.create(
            "mysql+pymysql",
            username=str(config.get("user", "portwyrm")),
            password=str(config.get("password", config.get("pwd", ""))),
            host=str(config.get("host", "localhost")),
            port=int(config.get("port", 3306)),
            database=str(config.get("database", config.get("name", "portwyrm"))),
        )
        engine = create_engine(
            url,
            pool_size=int(config.get("pool_size", 10)),
            max_overflow=int(config.get("max", 20)),
            pool_pre_ping=True,
        )
        return engine, sessionmaker(bind=engine, autoflush=True, expire_on_commit=False)

    def capabilities(
        self,
        *,
        spec: Any,
        mapping: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        return {
            "transactional": True,
            "async_native": False,
            "isolation_levels": {
                "READ UNCOMMITTED",
                "READ COMMITTED",
                "REPEATABLE READ",
                "SERIALIZABLE",
            },
            "read_only_enforced": False,
            "engine": "mysql",
        }


register_engine("mysql", _MySQLEngineRegistration())


class _IsolatedMemoryEngineRegistration:
    """One process-local database per Portwyrm memory repository instance."""

    def build(self, *, mapping: dict[str, object], spec: Any, dsn: str | None) -> Any:
        del mapping, spec, dsn
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        return engine, sessionmaker(bind=engine, autoflush=True, expire_on_commit=False)

    def capabilities(
        self,
        *,
        spec: Any,
        mapping: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        return {
            "transactional": True,
            "async_native": False,
            "isolation_levels": {"SERIALIZABLE"},
            "read_only_enforced": False,
            "engine": "portwyrm-memory",
        }


register_engine("portwyrm-memory", _IsolatedMemoryEngineRegistration())


def engine_for_repository(repository: Repository) -> Any:
    """Return a synchronous Tigrbl engine co-located with repository metadata."""
    if isinstance(repository, MemoryRepository):
        return {"kind": "portwyrm-memory", "async": False, "instance": id(repository)}
    if isinstance(repository, SQLiteRepository):
        return sqlitef(str(repository.path), async_=False)
    if isinstance(repository, FilesystemRepository):
        return sqlitef(str(repository.root / "portwyrm.tables.sqlite"), async_=False)
    if isinstance(repository, HybridRepository):
        return engine_for_repository(repository.metadata)
    if isinstance(repository, PostgreSQLRepository):
        config = dict(getattr(repository, "config", {}))
        return pg(
            async_=False,
            user=str(config.get("user", "app")),
            pwd=str(config.get("password", config.get("pwd", "secret"))),
            host=str(config.get("host", "localhost")),
            port=int(config.get("port", 5432)),
            name=str(config.get("dbname", config.get("name", "portwyrm"))),
        )
    if isinstance(repository, MySQLRepository):
        config = dict(getattr(repository, "config", {}))
        return {
            "kind": "mysql",
            "async": False,
            "user": str(config.get("user", "portwyrm")),
            "password": str(config.get("password", config.get("pwd", ""))),
            "host": str(config.get("host", "localhost")),
            "port": int(config.get("port", 3306)),
            "database": str(config.get("database", config.get("name", "portwyrm"))),
            "pool_size": int(config.get("pool_size", 10)),
            "max": int(config.get("max", 20)),
        }
    raise TypeError(f"Tigrbl engine is not available for {repository.backend_name!r}")


def sqlite_table_path(repository: Repository) -> Path | None:
    """Expose the canonical table file location for diagnostics and backups."""
    if isinstance(repository, SQLiteRepository):
        return repository.path
    if isinstance(repository, FilesystemRepository):
        return repository.root / "portwyrm.tables.sqlite"
    if isinstance(repository, HybridRepository):
        return sqlite_table_path(repository.metadata)
    return None
