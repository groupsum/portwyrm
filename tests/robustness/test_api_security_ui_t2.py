"""Adversarial API policy and compiled-UI assurance coverage."""

import asyncio
from pathlib import Path

import pytest
from tigrbl import HTTPException

from portwyrm.api import create_app
from portwyrm.config import PortwyrmSettings
from tests.support import TestClient


def test_non_admin_cannot_inject_raw_nginx_but_admin_can() -> None:
    async def run() -> None:
        app = create_app(settings=PortwyrmSettings(backend="memory"))
        host = await app.core.RoutingHostStore.create(
            {
                "kind": "proxy",
                "domain_names": ["policy.example.test"],
                "forward_scheme": "http",
                "forward_host": "backend",
                "forward_port": 8080,
                "target_kind": "dns",
            }
        )
        editor = {
            "is_admin": False,
            "permissions": {"proxy_hosts": "manage"},
            "visibility": "all",
        }
        with pytest.raises(HTTPException, match="advanced Nginx configuration requires"):
            await app.core.RoutingHostStore.update(
                {"id": host["id"], "advanced_config": "return 418;"},
                ctx={"principal": editor},
            )
        updated = await app.core.RoutingHostStore.update(
            {"id": host["id"], "advanced_config": "client_max_body_size 32m;"},
            ctx={"principal": {"is_admin": True}},
        )
        assert updated["advanced_config"] == "client_max_body_size 32m;"

    asyncio.run(run())


def test_operator_filters_have_accessible_names_in_source() -> None:
    components = Path(__file__).parents[2] / "frontend" / "src" / "components"
    source = "\n".join(path.read_text(encoding="utf-8") for path in components.glob("*.tsx"))
    assert 'aria-label="Filter' in source or 'aria-label="Search' in source


def test_pat_scope_lifecycle_and_cross_user_denials(tmp_path: Path) -> None:
    client = TestClient(
        create_app(
            settings=PortwyrmSettings(
                backend="sqlite",
                data_root=tmp_path,
                sqlite_path=tmp_path / "pat-security.sqlite",
            )
        )
    )
    assert (
        client.post(
            "/api/setup",
            json={"email": "admin@example.test", "password": "a strong admin password"},
        ).status_code
        == 201
    )
    admin_login = client.post(
        "/api/tokens",
        json={"identity": "admin@example.test", "secret": "a strong admin password"},
    )
    admin_headers = {"Authorization": f"Bearer {admin_login.json()['result']['token']}"}
    created_user = client.post(
        "/api/users",
        headers=admin_headers,
        json={
            "name": "Reader",
            "nickname": "reader",
            "email": "reader@example.test",
            "password": "a strong reader password",
            "is_admin": 0,
            "visibility": "all",
            "permissions": {"proxy_hosts": {"read": True}},
        },
    )
    assert created_user.status_code == 201, created_user.text
    reader_id = int(created_user.json()["id"])
    reader_login = client.post(
        "/api/tokens",
        json={"identity": "reader@example.test", "secret": "a strong reader password"},
    )
    assert reader_login.status_code == 200, reader_login.text
    reader_headers = {"Authorization": f"Bearer {reader_login.json()['result']['token']}"}

    issued = client.post(
        "/api/v2/tokens",
        headers=reader_headers,
        json={"name": "read only", "scopes": ["proxy_hosts:read"]},
    )
    assert issued.status_code == 201, issued.text
    token_id = issued.json()["id"]
    pat_headers = {"Authorization": f"Bearer {issued.json()['token']}"}
    assert client.get("/api/nginx/proxy-hosts", headers=pat_headers).status_code == 200
    denied = client.post(
        "/api/nginx/proxy-hosts",
        headers=pat_headers,
        json={
            "domain_names": ["denied.example.test"],
            "forward_host": "backend",
            "forward_port": 8080,
        },
    )
    assert denied.status_code == 403

    admin_pat = client.post(
        "/api/v2/tokens",
        headers=admin_headers,
        json={"name": "admin token", "scopes": ["user"]},
    )
    assert admin_pat.status_code == 201
    assert (
        client.delete(
            f"/api/v2/tokens/{admin_pat.json()['id']}", headers=reader_headers
        ).status_code
        == 404
    )
    assert {
        row["user_id"] for row in client.get("/api/v2/tokens", headers=reader_headers).json()
    } == {reader_id}
    admin_view = client.get(f"/api/v2/users/{reader_id}/tokens", headers=admin_headers)
    assert admin_view.status_code == 200
    assert {row["id"] for row in admin_view.json()} == {token_id}
    delegated = client.post(
        f"/api/v2/users/{reader_id}/tokens",
        headers=admin_headers,
        json={"name": "admin issued", "scopes": ["proxy_hosts:read"]},
    )
    assert delegated.status_code == 201, delegated.text
    delegated_event = next(
        event
        for event in client.get("/api/audit-log", headers=admin_headers).json()
        if event["object_type"] == "personal_access_tokens"
        and event["action"] == "issue"
        and event["target_principal_id"] == reader_id
        and event["actor_email"] == "admin@example.test"
    )
    assert delegated_event["actor_name"] == "admin"

    updated = client.patch(
        f"/api/v2/tokens/{token_id}",
        headers=reader_headers,
        json={"expires_at": 4_102_444_800},
    )
    assert updated.status_code == 200 and updated.json()["expires_at"] == 4_102_444_800
    rotated = client.post(f"/api/v2/tokens/{token_id}/rotate", headers=reader_headers)
    assert rotated.status_code == 201, rotated.text
    assert client.get("/api/nginx/proxy-hosts", headers=pat_headers).status_code == 401
    replacement_headers = {"Authorization": f"Bearer {rotated.json()['token']}"}
    assert client.get("/api/nginx/proxy-hosts", headers=replacement_headers).status_code == 200
    assert (
        client.delete(f"/api/v2/tokens/{rotated.json()['id']}", headers=reader_headers).status_code
        == 204
    )
    assert client.get("/api/nginx/proxy-hosts", headers=replacement_headers).status_code == 401
    assert (
        client.get(
            "/api/nginx/proxy-hosts", headers={"Authorization": "Bearer malformed"}
        ).status_code
        == 401
    )
    assert (
        client.get(
            "/api/nginx/proxy-hosts",
            headers={"Authorization": "Bearer pwyrm_000000000000000000000000_unknown"},
        ).status_code
        == 401
    )

    disabled_token = client.post(
        "/api/v2/tokens",
        headers=reader_headers,
        json={"name": "disabled principal", "scopes": ["proxy_hosts:read"]},
    )
    assert disabled_token.status_code == 201
    disabled_headers = {"Authorization": f"Bearer {disabled_token.json()['token']}"}
    disabled = client.patch(
        f"/api/users/{reader_id}", headers=admin_headers, json={"is_disabled": 1}
    )
    assert disabled.status_code == 200, disabled.text
    assert client.get("/api/nginx/proxy-hosts", headers=disabled_headers).status_code == 401


def test_console_pages_are_directly_requestable() -> None:
    client = TestClient(create_app(settings=PortwyrmSettings(backend="memory")))
    for route in ("hosts", "users", "access-tokens", "audit", "settings"):
        response = client.get(f"/ui/{route}")
        assert response.status_code == 200
        assert '<div id="root"></div>' in response.text
