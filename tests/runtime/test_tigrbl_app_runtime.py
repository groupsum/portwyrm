from __future__ import annotations

import asyncio
import os
from pathlib import Path

from tigrbl.factories.engine import sqlitef

from portwyrm.api import create_app
from portwyrm.api.app import _load_or_create_bootstrap_credentials
from portwyrm.config import PortwyrmSettings
from portwyrm.runtime.bootstrap import seed_demo_proxy_host
from tests.support import TestClient

_SHARED_CLIENT: TestClient | None = None
_TEST_ROOT = Path(f".pytest-tmp-app-runtime-{os.getpid()}").resolve()
_TEST_ROOT.mkdir(exist_ok=True)
_TEST_DATABASE = _TEST_ROOT / "app.sqlite"


def _client() -> TestClient:
    global _SHARED_CLIENT
    if _SHARED_CLIENT is None:
        _SHARED_CLIENT = TestClient(
            create_app(
                settings=PortwyrmSettings(
                    backend="sqlite",
                    data_root=_TEST_ROOT,
                    sqlite_path=_TEST_DATABASE,
                ),
                engine=sqlitef(str(_TEST_DATABASE), async_=False),
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

    disabled = client.post(f"/api/nginx/proxy-hosts/{host['id']}/disable", headers=headers)
    assert disabled.status_code == 200
    assert bool(disabled.json()["enabled"]) is False
    persisted_disabled = client.get(f"/api/nginx/proxy-hosts/{host['id']}", headers=headers)
    assert bool(persisted_disabled.json()["enabled"]) is False

    enabled = client.post(f"/api/nginx/proxy-hosts/{host['id']}/enable", headers=headers)
    assert enabled.status_code == 200
    assert bool(enabled.json()["enabled"]) is True

    updated = client.patch(
        f"/api/nginx/proxy-hosts/{host['id']}",
        headers=headers,
        json={"forward_port": 9090},
    )
    assert updated.status_code == 200
    assert updated.json()["forward_port"] == 9090
    replaced = client.put(
        f"/api/nginx/proxy-hosts/{host['id']}",
        headers=headers,
        json={
            "domain_names": ["one.example.test", "two.example.test"],
            "forward_scheme": "http",
            "forward_host": "replacement-upstream",
            "forward_port": 9191,
            "target_kind": "docker",
            "enabled": 1,
        },
    )
    assert replaced.status_code == 200, replaced.text
    assert replaced.json()["forward_host"] == "replacement-upstream"
    assert replaced.json()["forward_port"] == 9191
    audit = client.get("/api/audit-log", headers=headers)
    assert audit.status_code == 200
    host_events = [
        event
        for event in audit.json()
        if event["object_type"] == "proxy_hosts" and event["object_id"] == str(host["id"])
    ]
    assert {event["action"] for event in host_events} >= {
        "created",
        "disabled",
        "enabled",
        "updated",
        "replaced",
    }
    assert {event["user_id"] for event in host_events} == {1}
    assert client.get("/health/ready").json()["components"]["database"]["backend"] == "sqlite"
    status = client.get("/api/v2/system/status", headers=headers).json()
    assert status["components"]["nginx"]["status"] == "disabled"
    assert "active_generation" in status["components"]["nginx"]


def test_generated_bootstrap_credentials_are_unique_to_the_deployment(
    tmp_path: Path, monkeypatch: object
) -> None:
    credential_file = tmp_path / "bootstrap-admin.json"
    monkeypatch.setenv("PORTWYRM_BOOTSTRAP_CREDENTIAL_FILE", str(credential_file))
    settings = PortwyrmSettings(backend="memory", data_root=tmp_path)
    first = _load_or_create_bootstrap_credentials(settings)
    second = _load_or_create_bootstrap_credentials(settings)
    assert first == second
    assert first[0] == "admin@example.com"
    assert len(first[1]) >= 24
    assert first[1] != "changeme"


def test_bootstrap_admin_must_change_password_before_control_plane_access(
    tmp_path: Path, monkeypatch: object
) -> None:
    credential_file = tmp_path / "bootstrap-admin.json"
    credential_file.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("PORTWYRM_BOOTSTRAP_CREDENTIAL_FILE", str(credential_file))
    app = create_app(settings=PortwyrmSettings(backend="memory"))
    asyncio.run(
        app.state.control_plane.bootstrap_admin(
            "admin@example.com",
            "one-time-password",
            must_change_password=True,
        )
    )
    client = TestClient(app)

    login = client.post(
        "/api/v2/browser/login",
        json={"identity": "admin@example.com", "secret": "one-time-password"},
    )
    assert login.status_code == 200
    assert login.json()["result"]["must_change_password"] is True
    blocked = client.get("/api/v2/system/status")
    assert blocked.status_code == 403
    assert blocked.json()["detail"] == "password change required"

    csrf = client.cookies.get("portwyrm_csrf")
    assert csrf is not None
    changed = client.post(
        "/api/v2/browser/password",
        headers={"X-CSRF-Token": csrf},
        json={
            "current_password": "one-time-password",
            "new_password": "private-administrator-password",
        },
    )
    assert changed.status_code == 204, changed.text
    assert not credential_file.exists()
    assert (
        client.post(
            "/api/v2/browser/login",
            json={"identity": "admin@example.com", "secret": "one-time-password"},
        ).status_code
        == 401
    )
    relogin = client.post(
        "/api/v2/browser/login",
        json={"identity": "admin@example.com", "secret": "private-administrator-password"},
    )
    assert relogin.status_code == 200
    assert relogin.json()["result"]["must_change_password"] is False
    assert client.get("/api/v2/system/status").status_code == 200


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
    assert preview.status_code == 200, preview.text
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
