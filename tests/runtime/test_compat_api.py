from __future__ import annotations

import threading
from copy import deepcopy
from typing import Any

import pytest
from fastapi.testclient import TestClient

from portwyrm.api import create_app
from portwyrm.api.compat import COLLECTIONS, create_compat_app
from portwyrm.application import ControlPlane
from portwyrm.persistence import MemoryRepository
from portwyrm.security import Principal


class FakeService:
    def __init__(self) -> None:
        self.data: dict[str, list[dict[str, Any]]] = {
            collection: [] for collection, _ in COLLECTIONS.values()
        }
        self.next_id = 1
        self.audit: list[dict[str, Any]] = []

    def authenticate(self, identity: str, secret: str) -> Principal | None:
        if secret != "correct":
            return None
        if identity == "admin@example.com":
            return Principal(1, identity, is_admin=True, visibility="all")
        if identity == "viewer@example.com":
            permissions = {
                section: "view" for section in self.data if section not in {"users", "settings"}
            }
            return Principal(2, identity, permissions=permissions, visibility="user")
        if identity == "manager@example.com":
            permissions = {
                section: "manage" for section in self.data if section not in {"users", "settings"}
            }
            return Principal(2, identity, permissions=permissions, visibility="user")
        return None

    def list_resources(self, collection: str) -> list[dict[str, Any]]:
        return deepcopy(self.data[collection])

    def get_resource(self, collection: str, resource_id: int | str) -> dict[str, Any] | None:
        return deepcopy(
            next((item for item in self.data[collection] if item["id"] == resource_id), None)
        )

    def create_resource(self, collection: str, payload: dict[str, Any]) -> dict[str, Any]:
        item = deepcopy(payload)
        if collection == "settings":
            item["id"] = str(item.get("name", f"setting-{self.next_id}"))
        else:
            item["id"] = self.next_id
        self.next_id += 1
        self.data[collection].append(item)
        self.audit.append(
            {"id": len(self.audit) + 1, "action": "created", "object_type": collection}
        )
        return deepcopy(item)

    def update_resource(
        self, collection: str, resource_id: int | str, payload: dict[str, Any]
    ) -> dict[str, Any] | None:
        for index, item in enumerate(self.data[collection]):
            if item["id"] == resource_id:
                self.data[collection][index] = deepcopy(payload)
                return deepcopy(payload)
        return None

    def delete_resource(self, collection: str, resource_id: int | str) -> bool:
        for index, item in enumerate(self.data[collection]):
            if item["id"] == resource_id:
                del self.data[collection][index]
                return True
        return False

    def list_audit(self, since: str | None = None) -> list[dict[str, Any]]:
        if since is None:
            return deepcopy(self.audit)
        return [item for item in deepcopy(self.audit) if item["id"] > int(since)]


@pytest.fixture
def service() -> FakeService:
    return FakeService()


@pytest.fixture
def client(service: FakeService) -> TestClient:
    return TestClient(create_compat_app(service))


def login(client: TestClient, identity: str = "admin@example.com") -> dict[str, str]:
    response = client.post(
        "/api/tokens", json={"identity": identity, "secret": "correct", "scope": "user"}
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['result']['token']}"}


def test_password_verification_runs_outside_the_event_loop(service: FakeService) -> None:
    verifier_threads: list[str] = []

    def authenticate(identity: str, _secret: str) -> Principal:
        verifier_threads.append(threading.current_thread().name)
        return Principal(1, identity, is_admin=True, visibility="all")

    response = TestClient(create_compat_app(service, authenticator=authenticate)).post(
        "/api/tokens",
        json={"identity": "admin@example.com", "secret": "correct", "scope": "user"},
    )

    assert response.status_code == 200
    assert verifier_threads == ["AnyIO worker thread"]


def test_health_schema_login_and_refresh(client: TestClient) -> None:
    health = client.get("/api/")
    assert health.status_code == 200
    assert health.json()["status"] == "OK"

    schema = client.get("/api/schema").json()
    assert schema["info"]["version"] == "2.10.4"
    assert set(schema["paths"]["/nginx/proxy-hosts"]) >= {"get", "post"}
    assert set(schema["paths"]["/nginx/proxy-hosts/{resource_id}"]) >= {
        "get",
        "put",
        "patch",
        "delete",
    }

    headers = login(client)
    refreshed = client.get("/api/tokens", headers=headers)
    assert refreshed.status_code == 200
    assert refreshed.json()["token"]
    assert isinstance(refreshed.json()["expires"], int)
    assert client.get("/api/nginx/proxy-hosts", headers=headers).status_code == 401


def test_browser_session_is_httponly_and_unsafe_requests_require_csrf(client: TestClient) -> None:
    response = client.post(
        "/api/v2/browser/login",
        json={"identity": "admin@example.com", "secret": "correct", "scope": "user"},
    )
    assert response.status_code == 200
    cookies = response.headers.get_list("set-cookie")
    assert any("portwyrm_session=" in value and "HttpOnly" in value for value in cookies)
    assert any("portwyrm_csrf=" in value and "HttpOnly" not in value for value in cookies)
    assert client.get("/api/nginx/proxy-hosts").status_code == 200
    blocked = client.post("/api/nginx/proxy-hosts", json={"domain_names": ["blocked.test"]})
    assert blocked.status_code == 403
    allowed = client.post(
        "/api/nginx/proxy-hosts",
        headers={"X-CSRF-Token": client.cookies["portwyrm_csrf"]},
        json={"domain_names": ["allowed.test"]},
    )
    assert allowed.status_code == 201


def test_proxy_crud_preserves_id_unknown_fields_and_metadata(client: TestClient) -> None:
    headers = login(client)
    payload = {
        "domain_names": ["app.example.com"],
        "forward_host": "app",
        "forward_port": 3000,
        "unknown_extension": {"keep": True},
        "meta": {"managed_by": "npmctl", "owner": "site", "resource_id": "proxy.app"},
    }
    created = client.post("/api/nginx/proxy-hosts", headers=headers, json=payload)
    assert created.status_code == 201
    assert created.json()["id"] == 1

    updated = client.put("/api/nginx/proxy-hosts/1", headers=headers, json={"forward_port": 4000})
    assert updated.status_code == 200
    assert updated.json()["id"] == 1
    assert updated.json()["unknown_extension"] == {"keep": True}
    assert updated.json()["meta"] == payload["meta"]

    listed = client.get("/api/nginx/proxy-hosts", headers=headers)
    assert isinstance(listed.json(), list)
    assert listed.json() == [updated.json()]
    assert client.delete("/api/nginx/proxy-hosts/1", headers=headers).json() is True
    assert client.get("/api/nginx/proxy-hosts/1", headers=headers).status_code == 404


def test_host_enable_disable_routes_are_explicit_and_idempotent(client: TestClient) -> None:
    headers = login(client)
    created = client.post(
        "/api/nginx/proxy-hosts",
        headers=headers,
        json={"domain_names": ["toggle.example.com"], "enabled": 1},
    ).json()

    disabled = client.post(f"/api/nginx/proxy-hosts/{created['id']}/disable", headers=headers)
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] == 0
    assert (
        client.post(f"/api/nginx/proxy-hosts/{created['id']}/disable", headers=headers).json()[
            "enabled"
        ]
        == 0
    )

    enabled = client.post(f"/api/nginx/proxy-hosts/{created['id']}/enable", headers=headers)
    assert enabled.status_code == 200
    assert enabled.json()["enabled"] == 1


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/api/nginx/certificates", {"nice_name": "cert", "provider": "letsencrypt"}),
        ("/api/nginx/access-lists", {"name": "private", "clients": [], "items": []}),
        ("/api/nginx/redirection-hosts", {"domain_names": ["from.example.com"]}),
        ("/api/nginx/dead-hosts", {"domain_names": ["gone.example.com"]}),
        ("/api/nginx/streams", {"incoming_port": 5432, "protocol": "tcp"}),
        ("/api/users", {"email": "person@example.com"}),
        ("/api/settings", {"name": "default-site", "value": "404"}),
    ],
)
def test_all_collections_offer_raw_crud(
    client: TestClient, path: str, payload: dict[str, Any]
) -> None:
    headers = login(client)
    created = client.post(path, headers=headers, json={**payload, "vendor_field": "preserved"})
    assert created.status_code == 201
    resource_id = created.json()["id"]
    assert client.get(path, headers=headers).json() == [created.json()]
    assert client.get(f"{path}/{resource_id}", headers=headers).json() == created.json()
    patched = client.patch(f"{path}/{resource_id}", headers=headers, json={"changed": True})
    assert patched.json()["vendor_field"] == "preserved"
    assert client.delete(f"{path}/{resource_id}", headers=headers).json() is True


def test_audit_since_is_admin_only_and_returns_array(client: TestClient) -> None:
    admin = login(client)
    client.post("/api/nginx/proxy-hosts", headers=admin, json={"domain_names": ["one.test"]})
    client.post("/api/nginx/proxy-hosts", headers=admin, json={"domain_names": ["two.test"]})
    assert [
        entry["id"] for entry in client.get("/api/audit-log?since=1", headers=admin).json()
    ] == [2]
    assert (
        client.get("/api/audit-log", headers=login(client, "viewer@example.com")).status_code == 403
    )


def test_invalid_auth_payload_ids_and_metadata_are_rejected(client: TestClient) -> None:
    assert client.post("/api/tokens", json={"identity": "admin@example.com"}).status_code == 400
    assert (
        client.post(
            "/api/tokens", json={"identity": "admin@example.com", "secret": "wrong"}
        ).status_code
        == 401
    )
    assert client.get("/api/nginx/proxy-hosts").status_code == 401
    headers = login(client)
    assert client.get("/api/nginx/proxy-hosts/not-an-id", headers=headers).status_code == 422
    assert (
        client.post("/api/nginx/proxy-hosts", headers=headers, json={"meta": "bad"}).status_code
        == 422
    )
    assert (
        client.post("/api/nginx/proxy-hosts", headers=headers, json={"id": 99}).status_code == 400
    )


def test_rbac_visibility_and_write_fences(client: TestClient, service: FakeService) -> None:
    service.data["proxy_hosts"] = [
        {"id": 1, "owner_user_id": 2, "domain_names": ["mine.test"]},
        {"id": 2, "owner_user_id": 3, "domain_names": ["foreign.test"]},
    ]
    viewer = login(client, "viewer@example.com")
    assert [item["id"] for item in client.get("/api/nginx/proxy-hosts", headers=viewer).json()] == [
        1
    ]
    assert client.get("/api/nginx/proxy-hosts/2", headers=viewer).status_code == 404
    assert client.post("/api/nginx/proxy-hosts", headers=viewer, json={}).status_code == 403
    assert client.get("/api/users", headers=viewer).status_code == 403

    manager = login(client, "manager@example.com")
    created = client.post(
        "/api/nginx/proxy-hosts",
        headers=manager,
        json={"owner_user_id": 2, "domain_names": ["new.test"]},
    )
    assert created.status_code == 201
    assert client.delete("/api/nginx/proxy-hosts/2", headers=manager).status_code == 404


def test_facade_adapts_the_shared_control_plane_service() -> None:
    control_plane = ControlPlane()

    def authenticate(identity: str, secret: str) -> Principal | None:
        if (identity, secret) != ("admin@example.com", "correct"):
            return None
        return Principal(1, identity, is_admin=True, visibility="all")

    client = TestClient(create_compat_app(control_plane, authenticator=authenticate))
    headers = login(client)
    created = client.post(
        "/api/nginx/proxy-hosts",
        headers=headers,
        json={
            "domain_names": ["integrated.example.com"],
            "forward_scheme": "http",
            "forward_host": "app",
            "forward_port": 8080,
            "meta": {
                "managed_by": "npmctl",
                "owner": "site",
                "resource_id": "proxy.integrated",
            },
        },
    )
    assert created.status_code == 201
    assert client.get("/api/nginx/proxy-hosts", headers=headers).json() == [created.json()]


def test_packaged_factory_bootstraps_from_environment_and_mounts_ui(monkeypatch) -> None:
    monkeypatch.setenv("INITIAL_ADMIN_EMAIL", "owner@example.com")
    monkeypatch.setenv("INITIAL_ADMIN_PASSWORD", "environment-secret")
    client = TestClient(create_app(MemoryRepository()))
    authenticated = client.post(
        "/api/tokens",
        json={"identity": "OWNER@example.com", "secret": "environment-secret", "scope": "user"},
    )
    assert authenticated.status_code == 200
    assert client.get("/").status_code == 200
    assert "Portwyrm" in client.get("/console").text


def test_packaged_app_requires_explicit_first_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "PORTWYRM_INITIAL_ADMIN_EMAIL",
        "PORTWYRM_INITIAL_ADMIN_PASSWORD",
        "INITIAL_ADMIN_EMAIL",
        "INITIAL_ADMIN_PASSWORD",
    ):
        monkeypatch.delenv(name, raising=False)
    client = TestClient(create_app(MemoryRepository()))
    assert client.get("/api/setup").json() == {"setup": False}
    created = client.post(
        "/api/setup",
        json={"email": "first@example.com", "password": "correct horse battery staple"},
    )
    assert created.status_code == 201
    assert created.json()["is_admin"] == 1
    assert client.get("/api/setup").json() == {"setup": True}
    duplicate = client.post("/api/setup", json={"email": "second@example.com", "password": "nope"})
    assert duplicate.status_code == 403


def test_admin_can_impersonate_active_user_but_cannot_delete_self(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("PORTWYRM_MFA_KEY_PATH", str(tmp_path / "mfa.key"))
    client = TestClient(create_app(MemoryRepository()))
    assert (
        client.post(
            "/api/setup",
            json={"email": "admin@example.com", "password": "correct horse battery staple"},
        ).status_code
        == 201
    )
    authenticated = client.post(
        "/api/tokens",
        json={
            "identity": "admin@example.com",
            "secret": "correct horse battery staple",
            "scope": "user",
        },
    )
    admin = {"Authorization": f"Bearer {authenticated.json()['result']['token']}"}
    user = client.post(
        "/api/users",
        headers=admin,
        json={"email": "operator@example.com", "password": "operator password"},
    ).json()

    impersonation = client.post(f"/api/users/{user['id']}/login", headers=admin)

    assert impersonation.status_code == 200
    operator = {"Authorization": f"Bearer {impersonation.json()['token']}"}
    assert client.get("/api/v2/me", headers=operator).json()["email"] == "operator@example.com"
    assert client.delete("/api/users/1", headers=admin).status_code == 409
    actions = {entry["action"] for entry in client.get("/api/audit-log", headers=admin).json()}
    assert {"authenticated", "user.impersonated"} <= actions
