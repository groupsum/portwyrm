from __future__ import annotations

import argparse
from pathlib import Path

import bcrypt
from fastapi.testclient import TestClient

from portwyrm import __main__ as cli
from portwyrm.api import create_app
from portwyrm.api.dependencies import create_default_repository
from portwyrm.application import PersistentControlPlane
from portwyrm.cli.commands import remote
from portwyrm.persistence import SQLiteRepository
from portwyrm.runtime.coordinator import RuntimeCoordinator
from portwyrm.security import totp_code


def _login(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/tokens",
        json={"identity": "admin@example.test", "secret": "correct-password", "scope": "user"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['result']['token']}"}


def test_api_setup_crud_and_credentials_survive_restart(tmp_path: Path) -> None:
    path = tmp_path / "portwyrm.sqlite"
    first = TestClient(create_app(SQLiteRepository(path)))
    setup = first.post(
        "/api/setup",
        json={"email": "admin@example.test", "password": "correct-password"},
    )
    assert setup.status_code == 201
    created = first.post(
        "/api/nginx/proxy-hosts",
        headers=_login(first),
        json={
            "domain_names": ["app.example.test"],
            "forward_scheme": "http",
            "forward_host": "application",
            "forward_port": 8080,
            "allow_websocket_upgrade": 1,
            "caching_enabled": 1,
        },
    )
    assert created.status_code == 201

    restarted = TestClient(create_app(SQLiteRepository(path)))
    listed = restarted.get("/api/nginx/proxy-hosts", headers=_login(restarted))
    assert listed.status_code == 200
    assert listed.json()[0]["domain_names"] == ["app.example.test"]
    assert restarted.get("/health/ready").json()["components"]["database"]["status"] == "ok"
    report = restarted.get("/api/reports/hosts", headers=_login(restarted))
    assert report.json()["proxy_hosts"]["total"] == 1
    metrics = restarted.get("/metrics")
    assert 'portwyrm_resources{collection="proxy-hosts"} 1' in metrics.text
    api_response = restarted.get("/api/", headers=_login(restarted))
    assert api_response.headers["cache-control"] == "no-store"
    assert api_response.headers["x-content-type-options"] == "nosniff"


def test_user_credentials_profile_logout_and_pat_lifecycle_survive_restart(tmp_path: Path) -> None:
    path = tmp_path / "identity.sqlite"
    first = TestClient(create_app(SQLiteRepository(path)))
    assert (
        first.post(
            "/api/setup", json={"email": "admin@example.test", "password": "admin-password"}
        ).status_code
        == 201
    )
    admin_headers = _login_with(first, "admin@example.test", "admin-password")
    created = first.post(
        "/api/users",
        headers=admin_headers,
        json={
            "email": "user@example.test",
            "name": "User",
            "password": "initial-password",
            "permissions": {"proxy_hosts": "view"},
        },
    )
    assert created.status_code == 201
    assert "password" not in created.json()

    user_headers = _login_with(first, "user@example.test", "initial-password")
    assert first.get("/api/v2/me", headers=user_headers).json()["email"] == "user@example.test"
    changed = first.put("/api/v2/me", headers=user_headers, json={"nickname": "Wyrm Rider"})
    assert changed.status_code == 200
    token = first.post(
        "/api/v2/tokens",
        headers=user_headers,
        json={"name": "npmctl", "scopes": ["user"]},
    )
    assert token.status_code == 201
    plaintext = token.json()["token"]
    assert plaintext.startswith("pwyrm_")
    assert first.delete("/api/tokens", headers=user_headers).status_code == 204
    assert first.get("/api/v2/me", headers=user_headers).status_code == 401

    restarted = TestClient(create_app(SQLiteRepository(path)))
    assert (
        restarted.get("/api/v2/me", headers={"Authorization": f"Bearer {plaintext}"}).json()[
            "nickname"
        ]
        == "Wyrm Rider"
    )
    restarted_user = _login_with(restarted, "user@example.test", "initial-password")
    changed_password = restarted.put(
        f"/api/users/{created.json()['id']}/auth",
        headers=restarted_user,
        json={"current": "initial-password", "password": "replacement-password"},
    )
    assert changed_password.status_code == 204
    assert (
        restarted.post(
            "/api/tokens",
            json={"identity": "user@example.test", "secret": "initial-password"},
        ).status_code
        == 401
    )
    assert _login_with(restarted, "user@example.test", "replacement-password")


def test_admin_can_crud_action_grants_and_existing_session_updates_immediately(
    tmp_path: Path,
) -> None:
    client = TestClient(create_app(SQLiteRepository(tmp_path / "permissions.sqlite")))
    assert (
        client.post(
            "/api/setup", json={"email": "admin@example.test", "password": "admin-password"}
        ).status_code
        == 201
    )
    admin = _login_with(client, "admin@example.test", "admin-password")
    created_user = client.post(
        "/api/users",
        headers=admin,
        json={
            "email": "creator@example.test",
            "name": "Creator",
            "password": "creator-password",
            "permissions": {
                "proxy_hosts": {
                    "create": False,
                    "read": True,
                    "update": False,
                    "delete": False,
                }
            },
        },
    )
    assert created_user.status_code == 201
    creator = _login_with(client, "creator@example.test", "creator-password")
    host_payload = {
        "domain_names": ["creator.example.test"],
        "forward_scheme": "http",
        "forward_host": "application",
        "forward_port": 8080,
    }
    assert client.get("/api/nginx/proxy-hosts", headers=creator).status_code == 200
    assert (
        client.post("/api/nginx/proxy-hosts", headers=creator, json=host_payload).status_code
        == 403
    )

    grant = {
        "create": True,
        "read": True,
        "update": False,
        "delete": False,
    }
    updated = client.put(
        f"/api/users/{created_user.json()['id']}",
        headers=admin,
        json={"permissions": {"proxy_hosts": grant}},
    )
    assert updated.status_code == 200
    assert updated.json()["permissions"]["proxy_hosts"] == grant
    # No re-login: the authorization dependency reloads the persisted grant.
    assert (
        client.post("/api/nginx/proxy-hosts", headers=creator, json=host_payload).status_code
        == 201
    )

    invalid = client.post(
        "/api/users",
        headers=admin,
        json={
            "email": "invalid@example.test",
            "password": "invalid-password",
            "permissions": {"proxy_hosts": {"publish": True}},
        },
    )
    assert invalid.status_code == 400


def test_mfa_enrollment_totp_and_one_use_backup_code_survive_restart(tmp_path: Path) -> None:
    path = tmp_path / "mfa.sqlite"
    first = TestClient(create_app(SQLiteRepository(path)))
    first.post("/api/setup", json={"email": "admin@example.test", "password": "admin-password"})
    headers = _login_with(first, "admin@example.test", "admin-password")
    enrollment = first.post("/api/v2/mfa/enroll", headers=headers)
    assert enrollment.status_code == 200
    code = totp_code(enrollment.json()["secret"])
    assert (
        first.post("/api/v2/mfa/confirm", headers=headers, json={"code": code}).status_code == 204
    )
    challenge = first.post(
        "/api/tokens", json={"identity": "admin@example.test", "secret": "admin-password"}
    )
    assert challenge.status_code == 200
    assert challenge.json()["result"]["scope"] == "mfa"
    challenge_headers = {"Authorization": f"Bearer {challenge.json()['result']['token']}"}
    assert first.get("/api/v2/me", headers=challenge_headers).status_code == 403
    completed = first.post(
        "/api/tokens/2fa",
        headers=challenge_headers,
        json={"code": totp_code(enrollment.json()["secret"])},
    )
    assert completed.status_code == 200
    assert completed.json()["result"]["scope"] == "user"
    with SQLiteRepository(path).transaction() as tx:
        stored = tx.get("_mfa", "1")
    assert "secret" not in stored
    assert enrollment.json()["secret"] not in stored["secret_ciphertext"]

    backup = enrollment.json()["backup_codes"][0]
    restarted = TestClient(create_app(SQLiteRepository(path)))
    accepted = restarted.post(
        "/api/tokens",
        json={
            "identity": "admin@example.test",
            "secret": "admin-password",
            "mfa_code": backup,
        },
    )
    assert accepted.status_code == 200
    replay = restarted.post(
        "/api/tokens",
        json={
            "identity": "admin@example.test",
            "secret": "admin-password",
            "mfa_code": backup,
        },
    )
    assert replay.status_code == 401


def _login_with(client: TestClient, identity: str, secret: str) -> dict[str, str]:
    response = client.post("/api/tokens", json={"identity": identity, "secret": secret})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['result']['token']}"}


def test_routing_mutation_publishes_active_nginx_generation(tmp_path: Path) -> None:
    service = PersistentControlPlane(SQLiteRepository(tmp_path / "state.sqlite"))
    coordinator = RuntimeCoordinator(service, tmp_path / "nginx", validate=False, reload=False)
    service.on_change = coordinator.changed

    service.create(
        "proxy-hosts",
        {
            "domain_names": ["socket.example.test"],
            "forward_scheme": "http",
            "forward_host": "realtime",
            "forward_port": 9000,
            "allow_websocket_upgrade": 1,
            "caching_enabled": 1,
        },
    )

    active = tmp_path / "nginx" / "current"
    config = (active / "http" / "proxy-1.conf").read_text(encoding="utf-8")
    assert "server_name socket.example.test" in config
    assert "proxy_set_header Upgrade $http_upgrade" in config
    assert "proxy_cache public-cache" in config


def test_identity_membership_renders_write_only_access_credentials(tmp_path: Path) -> None:
    service = PersistentControlPlane(SQLiteRepository(tmp_path / "identity-acl.sqlite"))
    identity = service.create(
        "users",
        {
            "email": "operator@example.test",
            "nickname": "operator",
            "password": "operator-password",
        },
    )
    access_list = service.create(
        "access-lists",
        {"name": "operators", "identity_ids": [identity["id"]], "clients": []},
    )
    coordinator = RuntimeCoordinator(service, tmp_path / "nginx", validate=False, reload=False)
    service.on_change = coordinator.changed

    service.create(
        "proxy-hosts",
        {
            "domain_names": ["private.example.test"],
            "forward_scheme": "http",
            "forward_host": "application",
            "forward_port": 8080,
            "access_list_ids": [access_list["id"]],
        },
    )

    active = tmp_path / "nginx" / "current"
    credentials = (active / "access" / str(access_list["id"])).read_text(encoding="utf-8")
    assert credentials.startswith("operator:$argon2")
    assert "operator-password" not in credentials


def test_successful_runtime_applies_persist_versioned_host_snapshots(tmp_path: Path) -> None:
    path = tmp_path / "applied-history.sqlite"
    service = PersistentControlPlane(SQLiteRepository(path))
    coordinator = RuntimeCoordinator(service, tmp_path / "nginx", validate=False, reload=False)
    service.on_change = coordinator.changed
    created = service.create(
        "proxy-hosts",
        {
            "domain_names": ["history.example.test"],
            "forward_scheme": "http",
            "forward_host": "first-upstream",
            "forward_port": 8080,
        },
    )
    service.update(
        "proxy-hosts",
        created["id"],
        {**created, "forward_host": "second-upstream", "forward_port": 9090},
    )

    restarted = PersistentControlPlane(SQLiteRepository(path))
    versions = [
        event
        for event in restarted.audit_since()
        if event["action"] == "configuration.applied"
        and event["object_type"] == "proxy-hosts"
        and event["meta"]["id"] == created["id"]
    ]
    assert len(versions) == 2
    assert versions[0]["meta"]["snapshot"]["forward_host"] == "first-upstream"
    assert versions[1]["meta"]["snapshot"]["forward_host"] == "second-upstream"
    assert versions[0]["meta"]["generation"] != versions[1]["meta"]["generation"]


def test_cli_resource_commands_use_compatible_api_paths(monkeypatch) -> None:
    calls: list[tuple[str, str, object]] = []

    def request(_args, method: str, path: str, payload=None):
        calls.append((method, path, payload))
        return {"ok": True}

    monkeypatch.setattr(remote, "request", request)
    args = argparse.Namespace(
        command="create",
        collection="proxy-hosts",
        resource_id=None,
        data='{"domain_names":["cli.example.test"]}',
        url="http://portwyrm:81",
        timeout=10,
        token="secret",
    )
    assert cli.run(args) == {"ok": True}
    assert calls == [("POST", "/api/nginx/proxy-hosts", {"domain_names": ["cli.example.test"]})]


def test_cli_portability_commands_use_preview_and_explicit_apply(monkeypatch) -> None:
    calls: list[tuple[str, str, object]] = []

    def request(_args, method: str, path: str, payload=None):
        calls.append((method, path, payload))
        return {"ok": True}

    monkeypatch.setattr(remote, "request", request)
    args = argparse.Namespace(
        command="npm-import",
        data='{"user":[]}',
        apply=False,
        replace=False,
        url="http://portwyrm:81",
        timeout=10,
        token="secret",
    )
    assert cli.run(args) == {"ok": True}
    assert calls == [
        (
            "POST",
            "/api/v2/migration/npm/import?dry_run=true&replace=false",
            {"source": {"user": []}},
        )
    ]


def test_installed_server_defaults_to_durable_sqlite(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.delenv("PORTWYRM_DB_BACKEND", raising=False)
    monkeypatch.delenv("PORTWYRM_SQLITE_PATH", raising=False)
    monkeypatch.setenv("PORTWYRM_DATA_ROOT", str(tmp_path))

    repository = create_default_repository()

    assert isinstance(repository, SQLiteRepository)
    assert repository.path == tmp_path / "portwyrm.sqlite"


def test_admin_portability_and_npm_cutover_endpoints_reload_live_service(tmp_path: Path) -> None:
    client = TestClient(create_app(SQLiteRepository(tmp_path / "cutover.sqlite")))
    assert (
        client.post(
            "/api/setup", json={"email": "admin@example.test", "password": "admin-password"}
        ).status_code
        == 201
    )
    headers = _login_with(client, "admin@example.test", "admin-password")
    exported = client.get("/api/v2/export", headers=headers)
    assert exported.status_code == 200
    collections = {entry["collection"] for entry in exported.json()["records"]}
    assert "_credentials" in collections
    assert "_sessions" not in collections and "_personal_access_tokens" not in collections
    assert (
        client.post("/api/v2/import/preview", headers=headers, json=exported.json()).json()[
            "unchanged"
        ]
        >= 2
    )

    migrated_hash = bcrypt.hashpw(b"migrated-password", bcrypt.gensalt()).decode()
    source = {
        "user": [{"id": 20, "email": "migrated@example.test", "is_disabled": 0}],
        "auth": [{"id": 21, "user_id": 20, "type": "password", "secret": migrated_hash}],
        "user_permission": [{"user_id": 20, "visibility": "all", "proxy_hosts": "manage"}],
    }
    applied = client.post(
        "/api/v2/migration/npm/import?dry_run=false", headers=headers, json={"source": source}
    )
    assert applied.status_code == 200
    assert applied.json()["created"] == 2
    assert _login_with(client, "migrated@example.test", "migrated-password")
