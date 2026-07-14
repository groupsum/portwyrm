from __future__ import annotations

import argparse
from pathlib import Path

from fastapi.testclient import TestClient

from portwyrm import __main__ as cli
from portwyrm.api import create_app
from portwyrm.api.dependencies import create_default_repository
from portwyrm.cli.commands import remote
from portwyrm.persistence import SQLiteRepository
from portwyrm.persistent import PersistentControlPlane
from portwyrm.runtime.coordinator import RuntimeCoordinator


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
