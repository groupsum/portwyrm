from __future__ import annotations

import asyncio
import inspect
import sqlite3
from pathlib import Path

import bcrypt
from tigrbl import TigrblApp
from tigrbl.factories.engine import sqlitef

from portwyrm.api import create_app
from portwyrm.config import PortwyrmSettings
from portwyrm.migration import preflight_npm, preflight_npm_sqlite
from portwyrm.tables import PORTWYRM_TABLES, SchemaMigrationStore
from tests.support import TestClient


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
            "name": "certificate-owner-principal-v1",
            "required": False,
            "records": 0,
            "checksum": "sha256:certificate-owner-principal-v1",
        }
        result = await app.core.SchemaMigrationStore.apply({})
        assert result["required"] is False
        assert result["applied"] is False

    asyncio.run(run())


def test_schema_migration_adds_certificate_owner_to_existing_sqlite_database(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy.sqlite"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE certificates ("
            "id INTEGER PRIMARY KEY, metadata_json JSON NOT NULL, "
            "nice_name VARCHAR(255) NOT NULL, provider VARCHAR(64) NOT NULL, "
            "challenge_type VARCHAR(32), key_type VARCHAR(32) NOT NULL, "
            "material_ref VARCHAR(1024), expires_at INTEGER, status VARCHAR(32) NOT NULL, "
            "created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL)"
        )

    async def run() -> None:
        app = TigrblApp(engine=sqlitef(str(path), async_=False), mount_system=False)
        app.include_tables(PORTWYRM_TABLES)
        initialized = app.initialize(tables=PORTWYRM_TABLES)
        if inspect.isawaitable(initialized):
            await initialized
        assert (await app.core.SchemaMigrationStore.plan({}))["required"] is True
        assert (await app.core.SchemaMigrationStore.apply({}))["applied"] is True
        assert (await app.core.SchemaMigrationStore.plan({}))["required"] is False

    asyncio.run(run())
    with sqlite3.connect(path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(certificates)")}
    assert "owner_principal_id" in columns


def _npm_import_client(tmp_path: Path) -> tuple[TestClient, dict[str, str]]:
    client = TestClient(
        create_app(
            settings=PortwyrmSettings(
                backend="sqlite", data_root=tmp_path, sqlite_path=tmp_path / "npm-import.sqlite"
            ),
        )
    )
    credentials = {"email": "admin@example.test", "password": "test strong password"}
    setup = client.post("/api/setup", json=credentials)
    assert setup.status_code == 201, setup.text
    login = client.post(
        "/api/tokens",
        json={"identity": credentials["email"], "secret": credentials["password"]},
    )
    assert login.status_code == 200, login.text
    return client, {"Authorization": f"Bearer {login.json()['result']['token']}"}


_NPM_HOST = {
    "id": 7,
    "domain_names": '["app.example.test"]',
    "forward_scheme": "http",
    "forward_host": "upstream.example.test",
    "forward_port": 8080,
    "enabled": 1,
}


def test_npm_routing_import_preserves_id_and_replays_as_unchanged(tmp_path: Path) -> None:
    client, headers = _npm_import_client(tmp_path)
    url = "/api/v2/migration/npm/import"
    source = {"source": {"proxy_host": [_NPM_HOST]}}
    preview = client.post(url, json=source, headers=headers)
    assert preview.status_code == 200, preview.text
    assert preview.json()["created"] == 1
    assert client.get("/api/nginx/proxy-hosts", headers=headers).json() == []

    applied = client.post(f"{url}?dry_run=false", json=source, headers=headers)
    assert applied.status_code == 200, applied.text
    assert applied.json()["created"] == 1
    hosts = client.get("/api/nginx/proxy-hosts", headers=headers).json()
    assert [host["id"] for host in hosts] == [7]

    for suffix in ("", "?dry_run=false"):
        replay = client.post(f"{url}{suffix}", json=source, headers=headers)
        assert replay.status_code == 200, replay.text
        assert replay.json()["created"] == 0
        assert replay.json()["unchanged"] == 1
        assert replay.json()["quarantined"] == 0
    assert client.get("/api/nginx/proxy-hosts", headers=headers).json() == hosts


def test_npm_routing_import_preview_and_apply_report_hostname_conflict(tmp_path: Path) -> None:
    client, headers = _npm_import_client(tmp_path)
    existing = client.post(
        "/api/nginx/dead-hosts",
        headers=headers,
        json={"domain_names": ["app.example.test"]},
    )
    assert existing.status_code == 201, existing.text
    url = "/api/v2/migration/npm/import"
    source = {"source": {"proxy_host": [_NPM_HOST]}}
    for suffix in ("?replace=true", "?replace=true&dry_run=false"):
        response = client.post(f"{url}{suffix}", json=source, headers=headers)
        assert response.status_code == 200, response.text
        assert response.json()["created"] == 0
        assert response.json()["quarantined"] == 1
        assert (
            "domain app.example.test is already used" in response.json()["conflicts"][0]["reason"]
        )
    assert client.get("/api/nginx/proxy-hosts", headers=headers).json() == []
    assert (
        client.get("/api/nginx/dead-hosts", headers=headers).json()[0]["id"]
        == existing.json()["id"]
    )


def test_npm_routing_import_quarantines_same_batch_collisions(tmp_path: Path) -> None:
    client, headers = _npm_import_client(tmp_path)
    meta = {"managed_by": "npmctl", "owner": "edge", "resource_id": "proxy.app"}
    source = {
        "source": {
            "proxy_host": [{**_NPM_HOST, "meta": meta}],
            "dead_host": [
                {"id": 7, "domain_names": ["different.example.test"]},
                {"id": 8, "domain_names": ["APP.EXAMPLE.TEST."]},
            ],
        }
    }
    url = "/api/v2/migration/npm/import"
    preview = client.post(url, json=source, headers=headers)
    assert preview.status_code == 200, preview.text
    assert client.get("/api/nginx/proxy-hosts", headers=headers).json() == []
    applied = client.post(f"{url}?dry_run=false", json=source, headers=headers)
    assert applied.status_code == 200, applied.text
    assert applied.json() == {**preview.json(), "dry_run": False}
    assert applied.json()["created"] == 1
    assert applied.json()["quarantined"] == 2
    assert [conflict["source_id"] for conflict in applied.json()["conflicts"]] == ["7", "8"]
    hosts = client.get("/api/nginx/proxy-hosts", headers=headers).json()
    assert [(host["id"], host["meta"]) for host in hosts] == [(7, meta)]
    assert client.get("/api/nginx/dead-hosts", headers=headers).json() == []

    replacement = {"source": {"proxy_host": [{**_NPM_HOST, "forward_port": 9000}]}}
    applied = client.post(f"{url}?dry_run=false&replace=true", json=replacement, headers=headers)
    assert applied.status_code == 200, applied.text
    assert applied.json()["quarantined"] == 1
    assert client.get("/api/nginx/proxy-hosts", headers=headers).json() == hosts
