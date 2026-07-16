"""Native Tigrbl schema, operation, hook, and legacy-projection contracts."""

from __future__ import annotations

import sqlite3

import pytest
from tigrbl import TigrblApp
from tigrbl.engine import resolver
from tigrbl.factories.engine import mem

from portwyrm.api.app import create_app
from portwyrm.persistence import (
    FilesystemRepository,
    MemoryRepository,
    MySQLRepository,
    PostgreSQLRepository,
    SQLiteRepository,
)
from portwyrm.tables import PORTWYRM_TABLES
from portwyrm.tables.engine import engine_for_repository
from portwyrm.tables.models import (
    BrowserSession,
    PersonalAccessToken,
    PortwyrmTable,
    Principal,
    RoutingHost,
    RoutingSource,
    RoutingUpstream,
)
from tests.support import TestClient


class HookProbe(PortwyrmTable):
    __tablename__ = "hook_probe_test"


@pytest.fixture(autouse=True)
def isolated_mfa_key(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("PORTWYRM_MFA_KEY_PATH", str(tmp_path / "mfa.key"))


def _setup(client: TestClient) -> dict[str, str]:
    created = client.post(
        "/api/setup",
        json={"email": "owner@example.com", "password": "correct horse battery staple"},
    )
    assert created.status_code == 201
    authenticated = client.post(
        "/api/tokens",
        json={
            "identity": "owner@example.com",
            "secret": "correct horse battery staple",
            "scope": "user",
        },
    )
    assert authenticated.status_code == 200
    return {"Authorization": f"Bearer {authenticated.json()['result']['token']}"}


def test_canonical_tables_bind_builtin_custom_ops_and_post_commit_hooks() -> None:
    app = create_app(MemoryRepository())

    assert len(PORTWYRM_TABLES) == 25
    principal_ops = {spec.alias for spec in app.bind(Principal)}
    routing_ops = {spec.alias for spec in app.bind(RoutingHost)}
    assert {"create", "read", "update", "replace", "delete", "list"} <= principal_ops
    assert "preview" in routing_ops
    assert len(RoutingHost.hooks.create.POST_COMMIT) == 1


def test_native_tigrbl_create_executes_post_commit_hook() -> None:
    app = TigrblApp(engine=mem(async_=False), mount_system=False)
    app.include_table(HookProbe)
    app.initialize()
    changes: list[str] = []
    app.state.tigrbl_after_commit = changes.append

    created = TestClient(app).post("/hookprobe", json={})

    assert created.status_code == 201
    assert changes == ["hook_probe_test"]


def test_compatibility_writes_project_multiple_sources_and_typed_upstream() -> None:
    app = create_app(MemoryRepository())
    client = TestClient(app)
    headers = _setup(client)

    created = client.post(
        "/api/nginx/proxy-hosts",
        headers=headers,
        json={
            "domain_names": ["one.example.com", "two.example.com"],
            "forward_scheme": "http",
            "forward_host": "backend",
            "forward_port": 8080,
            "target_kind": "docker",
        },
    )
    assert created.status_code == 201

    session, release = resolver.acquire(router=app, model=RoutingHost, require_ready=True)
    try:
        host = session.query(RoutingHost).one()
        sources = session.query(RoutingSource).order_by(RoutingSource.domain_name).all()
        upstream = session.query(RoutingUpstream).one()
        assert host.kind == "proxy"
        assert [source.domain_name for source in sources] == [
            "one.example.com",
            "two.example.com",
        ]
        assert (upstream.target_kind, upstream.target, upstream.port) == (
            "docker",
            "backend",
            8080,
        )
    finally:
        release()


def test_pat_projection_contains_only_prefix_and_argon_digest() -> None:
    app = create_app(MemoryRepository())
    client = TestClient(app)
    headers = _setup(client)
    issued = client.post(
        "/api/v2/tokens",
        headers=headers,
        json={"name": "automation", "scopes": ["user"]},
    )
    assert issued.status_code == 201
    plaintext = issued.json()["token"]

    session, release = resolver.acquire(
        router=app,
        model=PersonalAccessToken,
        require_ready=True,
    )
    try:
        stored = session.query(PersonalAccessToken).one()
        assert stored.token_prefix in plaintext
        assert stored.token_digest.startswith("$argon2id$")
        assert plaintext not in stored.token_digest
    finally:
        release()


def test_tigrbl_tables_are_authoritative_after_one_time_sqlite_import(tmp_path) -> None:
    path = tmp_path / "authority.sqlite"
    legacy = SQLiteRepository(path)
    app = create_app(legacy)
    client = TestClient(app)
    headers = _setup(client)
    created = client.post(
        "/api/nginx/proxy-hosts",
        headers=headers,
        json={
            "domain_names": ["authoritative.example.com"],
            "forward_scheme": "http",
            "forward_host": "backend",
            "forward_port": 8080,
        },
    )
    assert created.status_code == 201

    with legacy.transaction() as transaction:
        assert transaction.list("users") == []
        transaction.upsert(
            "proxy_hosts",
            {
                "id": 999,
                "domain_names": ["stale-legacy.example.com"],
                "forward_host": "stale",
                "forward_port": 80,
            },
        )

    restarted = TestClient(create_app(SQLiteRepository(path)))
    restarted_headers = {
        "Authorization": (
            "Bearer "
            + restarted.post(
                "/api/tokens",
                json={
                    "identity": "owner@example.com",
                    "secret": "correct horse battery staple",
                    "scope": "user",
                },
            ).json()["result"]["token"]
        )
    }
    rows = restarted.get("/api/nginx/proxy-hosts", headers=restarted_headers).json()
    assert [row["domain_names"] for row in rows] == [["authoritative.example.com"]]


def test_browser_sessions_are_hash_only_tigrbl_rows() -> None:
    app = create_app(MemoryRepository())
    client = TestClient(app)
    created = client.post(
        "/api/setup",
        json={"email": "owner@example.com", "password": "correct horse battery staple"},
    )
    assert created.status_code == 201
    login = client.post(
        "/api/v2/browser/login",
        json={"identity": "owner@example.com", "secret": "correct horse battery staple"},
    )
    assert login.status_code == 200

    session, release = resolver.acquire(router=app, model=BrowserSession, require_ready=True)
    try:
        stored = session.query(BrowserSession).one()
        assert stored.token_digest.startswith("$argon2id$")
        assert "portwyrm_session" not in stored.token_digest
    finally:
        release()


def test_sqlite_profile_creates_normalized_tables_beside_legacy_projection(
    tmp_path,
) -> None:
    path = tmp_path / "portwyrm.sqlite"
    create_app(SQLiteRepository(path))

    with sqlite3.connect(path) as connection:
        names = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
    assert {"records", "principals", "routing_hosts", "config_revisions"} <= names


def test_filesystem_profile_uses_durable_sqlite_table_sidecar(tmp_path) -> None:
    repository = FilesystemRepository(tmp_path / "repository")
    create_app(repository)

    table_path = repository.root / "portwyrm.tables.sqlite"
    assert table_path.is_file()
    with sqlite3.connect(table_path) as connection:
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'principals'"
        ).fetchone() == (1,)


def test_postgres_repository_configuration_maps_to_tigrbl_engine() -> None:
    repository = object.__new__(PostgreSQLRepository)
    repository.backend_name = "postgresql"
    repository.config = {
        "host": "db.internal",
        "port": 6543,
        "dbname": "portwyrm",
        "user": "operator",
        "pwd": "secret",
    }

    config = engine_for_repository(repository)

    assert config == {
        "kind": "postgres",
        "async": False,
        "user": "operator",
        "pwd": "secret",
        "host": "db.internal",
        "port": 6543,
        "db": "portwyrm",
        "pool_size": 10,
        "max": 20,
    }


def test_mysql_repository_configuration_maps_to_registered_tigrbl_engine() -> None:
    repository = object.__new__(MySQLRepository)
    repository.backend_name = "mysql"
    repository.config = {
        "host": "mysql.internal",
        "port": 3307,
        "db": "portwyrm",
        "user": "operator",
        "pwd": "secret",
    }

    config = engine_for_repository(repository)

    assert config == {
        "kind": "mysql",
        "async": False,
        "user": "operator",
        "pwd": "secret",
        "host": "mysql.internal",
        "port": 3307,
        "db": "portwyrm",
        "pool_size": 10,
        "max": 20,
    }
