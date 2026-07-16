from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from tigrbl.factories.engine import sqlitef

from deploy.entrypoint import seed_demo_proxy_host
from portwyrm.api import create_app
from portwyrm.config import PortwyrmSettings
from tests.support import TestClient

_SHARED_CLIENT: TestClient | None = None
_TEST_ROOT = Path(tempfile.mkdtemp(prefix="portwyrm-app-", dir=".tmp"))


def _client() -> TestClient:
    global _SHARED_CLIENT
    if _SHARED_CLIENT is None:
        _SHARED_CLIENT = TestClient(
            create_app(
                settings=PortwyrmSettings(backend="sqlite", sqlite_path=_TEST_ROOT / "app.sqlite"),
                engine=sqlitef(str(_TEST_ROOT / "app.sqlite"), async_=False),
            )
        )
    return _SHARED_CLIENT


def test_setup_login_and_proxy_host_crud_use_composed_tigrbl_app() -> None:
    client = _client()
    setup = client.post(
        "/api/setup",
        json={"email": "admin@example.test", "password": "a strong admin password"},
    )
    assert setup.status_code == 201
    login = client.post(
        "/api/tokens",
        json={"identity": "admin@example.test", "secret": "a strong admin password"},
    )
    assert login.status_code == 200
    token = login.json()["result"]["token"]
    headers = {"Authorization": f"Bearer {token}"}

    created = client.post(
        "/api/nginx/proxy-hosts",
        headers=headers,
        json={
            "domain_names": ["one.example.test", "two.example.test"],
            "forward_scheme": "http",
            "forward_host": "upstream",
            "forward_port": 8080,
            "target_kind": "docker",
            "enabled": 1,
        },
    )
    assert created.status_code == 201
    host = created.json()
    assert host["domain_names"] == ["one.example.test", "two.example.test"]
    assert host["forward_host"] == "upstream"

    listed = client.get("/api/nginx/proxy-hosts", headers=headers)
    assert listed.status_code == 200 and listed.json()[0]["id"] == host["id"]
    assert client.get("/health/ready").json()["components"]["database"]["backend"] == "sqlite"
    status = client.get("/api/v2/system/status", headers=headers).json()
    assert status["components"]["nginx"]["status"] == "disabled"
    assert "active_generation" in status["components"]["nginx"]


def test_export_and_preview_are_table_backed_and_checksummed() -> None:
    client = _client()
    setup = client.post(
        "/api/setup",
        json={"email": "admin@example.test", "password": "a strong admin password"},
    )
    assert setup.status_code in {201, 403}
    login = client.post(
        "/api/tokens",
        json={"identity": "admin@example.test", "secret": "a strong admin password"},
    )
    headers = {"Authorization": f"Bearer {login.json()['result']['token']}"}
    bundle = client.get("/api/v2/export", headers=headers)
    assert bundle.status_code == 200
    payload = bundle.json()
    assert payload["schema_version"] == "portwyrm.export.v2"
    assert len(payload["checksum"]) == 64
    preview = client.post("/api/v2/import/preview", headers=headers, json=payload)
    assert preview.status_code == 200
    assert preview.json()["unchanged"] == len(payload["records"])


def test_runtime_changes_persist_and_publish_immutable_generation(tmp_path: Path) -> None:
    settings = PortwyrmSettings(
        backend="sqlite",
        data_root=tmp_path,
        sqlite_path=tmp_path / "portwyrm.sqlite",
        nginx_runtime=True,
        nginx_root=tmp_path / "nginx",
        nginx_validate=False,
        nginx_reload=False,
    )
    app = create_app(settings=settings)
    resources = app.state.control_plane

    async def exercise() -> None:
        access_list = await resources.create_resource(
            "access_lists",
            {
                "name": "private",
                "items": [{"username": "operator", "password": "write-only-secret"}],
            },
        )
        host = await resources.create_resource(
            "proxy_hosts",
            {
                "domain_names": ["runtime.example.test"],
                "forward_scheme": "http",
                "forward_host": "upstream",
                "forward_port": 8080,
                "access_list_id": access_list["id"],
                "enabled": 1,
            },
        )
        generations = await app.core.GenerationStore.list({})
        attempts = await app.core.ReconcileStore.list({})
        assert len(generations) >= 1
        assert sum(bool(row["is_active"]) for row in generations) == 1
        assert any(row["applied"] for row in attempts)

        rendered = await app.core.GenerationStore.render({})
        assert rendered["generation"] == app.state.runtime.active_generation
        assert rendered["digest"].startswith(rendered["generation"])
        assert "http/proxy-1.conf" in rendered["files"]

        staged = await app.core.GenerationStore.stage({})
        assert staged["generation"] == rendered["generation"]
        assert staged["state"] == "active"
        assert await app.core.GenerationStore.validate({"generation": staged["generation"]}) == {
            "generation": staged["generation"],
            "valid": True,
        }

        difference = await app.core.GenerationStore.diff({})
        assert difference == {
            "base_generation": rendered["generation"],
            "target_generation": rendered["generation"],
            "files": [],
        }
        preview = await app.core.RoutingHostStore.preview({"id": host["id"]})
        assert preview["path"] == f"http/proxy-{host['id']}.conf"
        assert "auth_basic_user_file" in preview["config"]
        assert "write-only-secret" not in preview["config"]
        assert "$2" not in preview["config"]

        reconciled = await app.core.GenerationStore.reconcile({})
        assert reconciled["generation"] == rendered["generation"]
        assert reconciled["changed"] is False

    asyncio.run(exercise())
    active = (tmp_path / "nginx" / "ACTIVE").read_text(encoding="utf-8").strip()
    assert active
    password_file = tmp_path / "nginx" / "current" / "access" / "1"
    contents = password_file.read_text(encoding="utf-8")
    assert "operator:$2" in contents
    assert "write-only-secret" not in contents


def test_demo_seed_reuses_an_existing_canonical_domain(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.setenv("PORTWYRM_DEMO_HOST", "demo.portwyrm.localhost")
    app = create_app(
        settings=PortwyrmSettings(
            backend="sqlite",
            sqlite_path=tmp_path / "seed.sqlite",
            nginx_runtime=False,
        )
    )
    resources = app.state.control_plane

    async def exercise() -> None:
        original = await resources.create_resource(
            "proxy_hosts",
            {
                "domain_names": ["demo.portwyrm.localhost"],
                "forward_scheme": "http",
                "forward_host": "stale-upstream",
                "forward_port": 8080,
            },
        )
        await seed_demo_proxy_host(resources)
        await seed_demo_proxy_host(resources)
        hosts = await resources.list_resources("proxy_hosts")
        assert len(hosts) == 1
        assert hosts[0]["id"] == original["id"]
        assert hosts[0]["forward_host"] == "127.0.0.1"
        assert hosts[0]["forward_port"] == 81

    asyncio.run(exercise())
