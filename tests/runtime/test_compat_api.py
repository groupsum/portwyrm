"""Assurance coverage for the frozen NPM-shaped compatibility transport."""

from portwyrm.api import create_app
from portwyrm.config import PortwyrmSettings
from tests.support import TestClient


def test_compat_transport_preserves_crud_toggle_and_audit_operation_identity() -> None:
    client = TestClient(create_app(settings=PortwyrmSettings(backend="memory")))
    assert (
        client.post(
            "/api/setup",
            json={"email": "admin@example.test", "password": "a strong admin password"},
        ).status_code
        == 201
    )
    login = client.post(
        "/api/tokens",
        json={"identity": "admin@example.test", "secret": "a strong admin password"},
    )
    headers = {"Authorization": f"Bearer {login.json()['result']['token']}"}

    created = client.post(
        "/api/nginx/proxy-hosts",
        headers=headers,
        json={
            "domain_names": ["compat.example.test"],
            "forward_scheme": "http",
            "forward_host": "backend",
            "forward_port": 8080,
            "target_kind": "dns",
        },
    )
    assert created.status_code == 201
    host_id = created.json()["id"]
    assert not bool(
        client.post(f"/api/nginx/proxy-hosts/{host_id}/disable", headers=headers).json()["enabled"]
    )
    assert bool(
        client.post(f"/api/nginx/proxy-hosts/{host_id}/enable", headers=headers).json()["enabled"]
    )

    events = client.get("/api/audit-log", headers=headers).json()
    actions = {
        event["action"]
        for event in events
        if event["object_type"] == "proxy_hosts" and event["object_id"] == str(host_id)
    }
    assert {"created", "disabled", "enabled"} <= actions
