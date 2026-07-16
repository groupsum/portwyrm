from __future__ import annotations

import asyncio
import inspect
import json
import sqlite3
from pathlib import Path

import bcrypt
from tigrbl import TigrblApp
from tigrbl.factories.engine import sqlitef

from portwyrm.api.compat.resources import TableResources
from portwyrm.migration import preflight_npm, preflight_npm_sqlite
from portwyrm.tables import PORTWYRM_TABLES
from portwyrm.tables.migrations import ROUTING_CONTRACT_MIGRATION


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


def test_legacy_sqlite_records_upgrade_is_idempotent_and_preserves_ids(tmp_path: Path) -> None:
    path = tmp_path / "legacy.sqlite"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE records (collection TEXT, resource_id TEXT, payload TEXT, "
        "PRIMARY KEY (collection, resource_id))"
    )
    records = [
        (
            "access_lists",
            "7",
            {
                "id": 7,
                "name": "private",
                "clients": [{"address": "10.0.0.0/8", "directive": "allow"}],
            },
        ),
        (
            "certificates",
            "9",
            {
                "id": 9,
                "nice_name": "edge",
                "provider": "custom",
                "domain_names": ["edge.example.test"],
            },
        ),
        (
            "proxy_hosts",
            "12",
            {
                "id": 12,
                "domain_names": ["app.example.test"],
                "forward_scheme": "http",
                "forward_host": "app",
                "forward_port": 8080,
                "access_list_id": 7,
                "certificate_id": 9,
            },
        ),
    ]
    connection.executemany(
        "INSERT INTO records(collection, resource_id, payload) VALUES (?, ?, ?)",
        [
            (collection, resource_id, json.dumps(payload))
            for collection, resource_id, payload in records
        ],
    )
    connection.commit()
    connection.close()

    async def run() -> None:
        app = TigrblApp(engine=sqlitef(str(path), async_=False), mount_system=False)
        app.include_tables(PORTWYRM_TABLES)
        initialized = app.initialize(tables=PORTWYRM_TABLES)
        if inspect.isawaitable(initialized):
            await initialized
        first = await app.core.SchemaMigrationStore.apply({})
        second = await app.core.SchemaMigrationStore.apply({})
        assert first["applied"] is True
        assert second["applied"] is False
        assert second["required"] is False
        resources = TableResources(app)
        host = await resources.get_resource("proxy_hosts", 12)
        assert host is not None
        assert host["domain_names"] == ["app.example.test"]
        assert host["forward_host"] == "app"
        assert host["access_list_ids"] == [7]
        certificate = await resources.get_resource("certificates", 9)
        assert certificate is not None
        assert certificate["domain_names"] == ["edge.example.test"]

    asyncio.run(run())


def test_existing_normalized_sqlite_gets_routing_columns_and_migration_record(
    tmp_path: Path,
) -> None:
    path = tmp_path / "normalized-v1.sqlite"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE routing_hosts ("
        "id INTEGER PRIMARY KEY, kind TEXT NOT NULL, redirect_code INTEGER, "
        "hsts_enabled BOOLEAN NOT NULL DEFAULT 0, force_ssl BOOLEAN NOT NULL DEFAULT 0, "
        "certificate_id INTEGER, hsts_subdomains BOOLEAN NOT NULL DEFAULT 0)"
    )
    connection.execute(
        "CREATE TABLE stream_routes ("
        "id INTEGER PRIMARY KEY, protocol TEXT NOT NULL, incoming_port INTEGER NOT NULL, "
        "target_kind TEXT NOT NULL, target_port INTEGER NOT NULL)"
    )
    connection.commit()
    connection.close()

    async def run() -> None:
        app = TigrblApp(engine=sqlitef(str(path), async_=False), mount_system=False)
        app.include_tables(PORTWYRM_TABLES)
        initialized = app.initialize(tables=PORTWYRM_TABLES)
        if inspect.isawaitable(initialized):
            await initialized
        first = await app.core.SchemaMigrationStore.apply({})
        second = await app.core.SchemaMigrationStore.apply({})
        assert first["applied"] is False
        assert second["applied"] is False

    asyncio.run(run())
    connection = sqlite3.connect(path)
    host_columns = {row[1] for row in connection.execute("PRAGMA table_info(routing_hosts)")}
    stream_columns = {row[1] for row in connection.execute("PRAGMA table_info(stream_routes)")}
    migration_count = connection.execute(
        "SELECT COUNT(*) FROM system_migrations WHERE name = ? AND status = 'applied'",
        (ROUTING_CONTRACT_MIGRATION,),
    ).fetchone()[0]
    connection.close()
    assert {"http2_enabled", "trust_forwarded_proto"} <= host_columns
    assert "certificate_id" in stream_columns
    assert migration_count == 1


def test_partial_legacy_upgrade_skips_already_normalized_resource_ids(tmp_path: Path) -> None:
    path = tmp_path / "partial.sqlite"

    async def seed_normalized() -> None:
        app = TigrblApp(engine=sqlitef(str(path), async_=False), mount_system=False)
        app.include_tables(PORTWYRM_TABLES)
        initialized = app.initialize(tables=PORTWYRM_TABLES)
        if inspect.isawaitable(initialized):
            await initialized
        resources = TableResources(app)
        host = await resources.create_resource(
            "proxy_hosts",
            {
                "domain_names": ["demo.portwyrm.localhost"],
                "forward_scheme": "http",
                "forward_host": "127.0.0.1",
                "forward_port": 81,
            },
        )
        assert host["id"] == 1

    asyncio.run(seed_normalized())
    payload = {
        "id": 1,
        "domain_names": ["demo.portwyrm.localhost"],
        "forward_scheme": "http",
        "forward_host": "127.0.0.1",
        "forward_port": 81,
    }
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE records (collection TEXT, resource_id TEXT, payload TEXT, "
        "PRIMARY KEY (collection, resource_id))"
    )
    connection.execute(
        "INSERT INTO records(collection, resource_id, payload) VALUES (?, ?, ?)",
        ("proxy_hosts", "1", json.dumps(payload)),
    )
    connection.commit()
    connection.close()

    async def upgrade() -> None:
        app = TigrblApp(engine=sqlitef(str(path), async_=False), mount_system=False)
        app.include_tables(PORTWYRM_TABLES)
        initialized = app.initialize(tables=PORTWYRM_TABLES)
        if inspect.isawaitable(initialized):
            await initialized
        applied = await app.core.SchemaMigrationStore.apply({})
        assert applied["applied"] is True
        resources = TableResources(app)
        assert len(await resources.list_resources("proxy_hosts")) == 1

    asyncio.run(upgrade())
