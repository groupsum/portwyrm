from __future__ import annotations

import asyncio
import inspect
import sqlite3
from pathlib import Path

import bcrypt
from tigrbl import TigrblApp
from tigrbl.factories.engine import sqlitef

from portwyrm.migration import preflight_npm, preflight_npm_sqlite
from portwyrm.tables import PORTWYRM_TABLES, SchemaMigrationStore


def test_npm_preflight_preserves_ids_metadata_and_quarantines_invalid_references() -> None:
    source = {
        "user": [{"id": 1, "email": "admin@example.test"}],
        "certificate": [{"id": 161, "domain_names": '["example.test"]'}],
        "proxy_host": [
            {
                "id": 7,
                "certificate_id": 161,
                "domain_names": '["app.example.test"]',
                "meta": '{"managed_by":"npmctl","owner":"edge","resource_id":"proxy.app"}',
            },
            {"id": 8, "certificate_id": 999, "domain_names": '["broken.example.test"]'},
            {"id": 9, "is_deleted": 1, "domain_names": '["deleted.example.test"]'},
        ],
    }
    report = preflight_npm(source)

    assert report.importable == 3
    assert [item.source_id for item in report.quarantine] == ["9", "8"]
    proxy = report.records["proxy_hosts"][0]
    assert proxy["id"] == 7
    assert proxy["meta"]["managed_by"] == "npmctl"


def test_read_only_sqlite_preflight(tmp_path: Path) -> None:
    path = tmp_path / "npm.sqlite"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE user (id INTEGER PRIMARY KEY, email TEXT, is_deleted INTEGER)")
    connection.execute("INSERT INTO user VALUES (1, 'admin@example.test', 0)")
    connection.commit()
    connection.close()

    report = preflight_npm_sqlite(path)
    assert report.source_kind == "sqlite"
    assert report.records["users"] == [{"id": 1, "email": "admin@example.test", "is_deleted": 0}]


def test_npm_related_identity_and_access_list_tables_are_assembled() -> None:
    password_hash = bcrypt.hashpw(b"migrated-password", bcrypt.gensalt()).decode()
    report = preflight_npm(
        {
            "user": [{"id": 5, "email": "operator@example.test"}],
            "auth": [{"id": 10, "user_id": 5, "type": "password", "secret": password_hash}],
            "user_permission": [{"user_id": 5, "visibility": "all", "proxy_hosts": "manage"}],
            "access_list": [{"id": 7, "name": "private"}],
            "access_list_auth": [
                {"id": 8, "access_list_id": 7, "username": "alice", "password": "hash"}
            ],
            "access_list_client": [
                {"id": 9, "access_list_id": 7, "address": "10.0.0.0/8", "directive": "allow"}
            ],
        }
    )

    assert report.records["_credentials"] == [
        {"id": "operator@example.test", "password_hash": password_hash}
    ]
    assert report.records["users"][0]["permissions"]["proxy_hosts"] == "manage"
    assert report.records["access_lists"][0]["items"][0]["username"] == "alice"
    assert report.records["access_lists"][0]["clients"][0]["directive"] == "allow"


def test_schema_migration_surface_only_reports_the_current_contract(tmp_path: Path) -> None:
    async def run() -> None:
        app = TigrblApp(
            engine=sqlitef(str(tmp_path / "current.sqlite"), async_=False),
            mount_system=False,
        )
        app.include_tables(PORTWYRM_TABLES)
        initialized = app.initialize(tables=PORTWYRM_TABLES)
        if inspect.isawaitable(initialized):
            await initialized

        assert set(SchemaMigrationStore.ops.by_alias) == {
            "read",
            "list",
            "plan",
            "apply",
            "record_failure",
        }
        assert await app.core.SchemaMigrationStore.plan({}) == {
            "name": "tigrbl-current-schema",
            "required": False,
            "records": 0,
            "checksum": "current",
        }
        result = await app.core.SchemaMigrationStore.apply({})
        assert result["required"] is False
        assert result["applied"] is False

    asyncio.run(run())
