"""Public Tigrbl engine configuration for Portwyrm deployment profiles."""

from __future__ import annotations

from typing import Any

from tigrbl.factories.engine import engine, mem, pga, pgs, sqlitef

from .settings import PortwyrmSettings


def engine_from_environment() -> Any:
    return engine_from_settings(PortwyrmSettings.from_environment())


def engine_from_settings(settings: PortwyrmSettings) -> Any:
    backend = settings.backend
    if settings.database_dsn:
        return settings.database_dsn
    if backend in {"memory", "in-memory", "in_memory"}:
        return mem(async_=settings.database_async)
    if backend == "sqlite":
        return sqlitef(str(settings.sqlite_path), async_=settings.database_async)
    if backend in {"postgres", "postgresql"}:
        factory = pga if settings.database_async else pgs
        return factory(
            host=settings.database_host,
            port=settings.database_port or 5432,
            name=settings.database_name,
            user=settings.database_user,
            pwd=settings.database_password,
        )
    if backend == "mysql":
        if settings.database_async:
            raise ValueError("the installed MySQL engine currently supports synchronous sessions")
        return engine(
            {
                "kind": "mysql",
                "host": settings.database_host,
                "port": settings.database_port or 3306,
                "name": settings.database_name,
                "user": settings.database_user,
                "pwd": settings.database_password,
            }
        )
    raise ValueError(f"unsupported Portwyrm engine backend: {backend!r}")
