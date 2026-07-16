"""Configurable MySQL/MariaDB and PostgreSQL DB-API adapters."""

from __future__ import annotations

import importlib
import json
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from .base import ConfigurationError, Resource, canonical_json, clone, resource_key

ConnectFactory = Callable[[], Any]


class LegacyDBAPITransaction:
    def __init__(self, connection: Any, vendor: str) -> None:
        self.connection = connection
        self.vendor = vendor

    def _execute(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        cursor = self.connection.cursor()
        cursor.execute(sql, params)
        return cursor

    def collections(self) -> tuple[str, ...]:
        cursor = self._execute(
            "SELECT DISTINCT collection FROM portwyrm_records ORDER BY collection"
        )
        return tuple(row[0] for row in cursor.fetchall())

    def list(self, collection: str) -> list[Resource]:
        cursor = self._execute(
            "SELECT payload FROM portwyrm_records WHERE collection = %s ORDER BY resource_id",
            (collection,),
        )
        return [
            json.loads(row[0]) if isinstance(row[0], str) else row[0] for row in cursor.fetchall()
        ]

    def get(self, collection: str, resource_id: str | int) -> Resource | None:
        cursor = self._execute(
            "SELECT payload FROM portwyrm_records WHERE collection = %s AND resource_id = %s",
            (collection, str(resource_id)),
        )
        row = cursor.fetchone()
        return (json.loads(row[0]) if isinstance(row[0], str) else row[0]) if row else None

    def upsert(self, collection: str, resource: Mapping[str, Any]) -> Resource:
        value = clone(dict(resource))
        if self.vendor == "postgresql":
            sql = (
                "INSERT INTO portwyrm_records(collection, resource_id, payload) "
                "VALUES (%s, %s, %s) ON CONFLICT(collection, resource_id) "
                "DO UPDATE SET payload = EXCLUDED.payload"
            )
        else:
            sql = """INSERT INTO portwyrm_records(collection, resource_id, payload)
                     VALUES (%s, %s, %s)
                     ON DUPLICATE KEY UPDATE payload = VALUES(payload)"""
        self._execute(sql, (collection, resource_key(value), canonical_json(value)))
        return value

    def delete(self, collection: str, resource_id: str | int) -> bool:
        cursor = self._execute(
            "DELETE FROM portwyrm_records WHERE collection = %s AND resource_id = %s",
            (collection, str(resource_id)),
        )
        return cursor.rowcount > 0


class DBAPIRepository:
    def __init__(self, vendor: str, connect_factory: ConnectFactory) -> None:
        self.backend_name = vendor
        self.vendor = vendor
        self.connect_factory = connect_factory
        self._initialize()

    def _initialize(self) -> None:
        connection = self.connect_factory()
        try:
            cursor = connection.cursor()
            payload_type = "TEXT" if self.vendor == "postgresql" else "LONGTEXT"
            cursor.execute(
                f"""CREATE TABLE IF NOT EXISTS portwyrm_records (
                    collection VARCHAR(128) NOT NULL,
                    resource_id VARCHAR(255) NOT NULL,
                    payload {payload_type} NOT NULL,
                    PRIMARY KEY (collection, resource_id)
                )"""
            )
            connection.commit()
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[LegacyDBAPITransaction]:
        connection = self.connect_factory()
        try:
            yield LegacyDBAPITransaction(connection, self.vendor)
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()


def _driver_factory(module_name: str, config: Mapping[str, Any]) -> ConnectFactory:
    frozen = dict(config)

    def connect() -> Any:
        try:
            module = importlib.import_module(module_name)
        except ImportError as error:
            raise ConfigurationError(
                f"optional database driver {module_name!r} is required for this backend"
            ) from error
        return module.connect(**frozen)

    return connect


class MySQLRepository(DBAPIRepository):
    def __init__(
        self,
        config: Mapping[str, Any] | None = None,
        *,
        connect_factory: ConnectFactory | None = None,
    ) -> None:
        self.config = dict(config or {})
        super().__init__("mysql", connect_factory or _driver_factory("pymysql", self.config))


class PostgreSQLRepository(DBAPIRepository):
    def __init__(
        self,
        config: Mapping[str, Any] | None = None,
        *,
        connect_factory: ConnectFactory | None = None,
    ) -> None:
        self.config = dict(config or {})
        super().__init__(
            "postgresql", connect_factory or _driver_factory("psycopg", self.config)
        )
