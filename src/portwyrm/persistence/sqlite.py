"""SQLite adapter with explicit transactions and stable JSON payloads."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .base import Resource, canonical_json, clone, resource_key, validate_collection_name


class SQLiteTransaction:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def collections(self) -> tuple[str, ...]:
        rows = self.connection.execute(
            "SELECT DISTINCT collection FROM records ORDER BY collection"
        )
        return tuple(row[0] for row in rows)

    def list(self, collection: str) -> list[Resource]:
        validate_collection_name(collection)
        rows = self.connection.execute(
            "SELECT payload FROM records WHERE collection = ? ORDER BY resource_id", (collection,)
        )
        return [json.loads(row[0]) for row in rows]

    def get(self, collection: str, resource_id: str | int) -> Resource | None:
        validate_collection_name(collection)
        row = self.connection.execute(
            "SELECT payload FROM records WHERE collection = ? AND resource_id = ?",
            (collection, str(resource_id)),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def upsert(self, collection: str, resource: Mapping[str, Any]) -> Resource:
        validate_collection_name(collection)
        value = clone(dict(resource))
        self.connection.execute(
            """INSERT INTO records(collection, resource_id, payload)
               VALUES (?, ?, ?)
               ON CONFLICT(collection, resource_id) DO UPDATE SET payload = excluded.payload""",
            (collection, resource_key(value), canonical_json(value)),
        )
        return value

    def delete(self, collection: str, resource_id: str | int) -> bool:
        validate_collection_name(collection)
        cursor = self.connection.execute(
            "DELETE FROM records WHERE collection = ? AND resource_id = ?",
            (collection, str(resource_id)),
        )
        return cursor.rowcount > 0


class SQLiteRepository:
    backend_name = "sqlite"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS records (
                    collection TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    PRIMARY KEY (collection, resource_id)
                )"""
            )

    @contextmanager
    def transaction(self) -> Iterator[SQLiteTransaction]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield SQLiteTransaction(connection)
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
