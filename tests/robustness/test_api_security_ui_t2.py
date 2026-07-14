from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from portwyrm.api import create_app
from portwyrm.api.compat import COLLECTIONS, create_compat_app
from portwyrm.persistence import MemoryRepository
from portwyrm.security import (
    Principal,
    TokenStore,
    consume_backup_code,
    generate_backup_codes,
    generate_totp_secret,
    totp_code,
    verify_totp,
)


class WireService:
    """Small deterministic compatibility port used to isolate HTTP boundary behavior."""

    def __init__(self) -> None:
        self.data: dict[str, list[dict[str, Any]]] = {
            collection: [] for collection, _ in COLLECTIONS.values()
        }
        self.next_id = 1

    def authenticate(self, identity: str, secret: str) -> Principal | None:
        if secret != "correct":
            return None
        if identity == "admin@example.com":
            return Principal(1, identity, is_admin=True, visibility="all")
        permissions = {section: "view" for section in self.data}
        if identity == "viewer@example.com":
            return Principal(2, identity, permissions=permissions, visibility="user")
        if identity == "manager@example.com":
            return Principal(
                2,
                identity,
                permissions={section: "manage" for section in self.data},
                visibility="user",
            )
        return None

    def list_resources(self, collection: str) -> list[dict[str, Any]]:
        return deepcopy(self.data[collection])

    def get_resource(self, collection: str, resource_id: int | str) -> dict[str, Any] | None:
        return deepcopy(
            next((row for row in self.data[collection] if row["id"] == resource_id), None)
        )

    def create_resource(self, collection: str, payload: dict[str, Any]) -> dict[str, Any]:
        row = deepcopy(payload)
        row["id"] = (
            str(payload.get("name", "setting")) if collection == "settings" else self.next_id
        )
        self.next_id += 1
        self.data[collection].append(row)
        return deepcopy(row)

    def update_resource(
        self, collection: str, resource_id: int | str, payload: dict[str, Any]
    ) -> dict[str, Any] | None:
        for index, row in enumerate(self.data[collection]):
            if row["id"] == resource_id:
                self.data[collection][index] = deepcopy(payload)
                return deepcopy(payload)
        return None

    def delete_resource(self, collection: str, resource_id: int | str) -> bool:
        for index, row in enumerate(self.data[collection]):
            if row["id"] == resource_id:
                del self.data[collection][index]
                return True
        return False

    def list_audit(self, since: str | None = None) -> list[dict[str, Any]]:
        del since
        return []


@pytest.fixture
def wire_service() -> WireService:
    return WireService()


@pytest.fixture
def client(wire_service: WireService) -> TestClient:
    return TestClient(create_compat_app(wire_service, version="7.12.3rc1"))


def login(client: TestClient, identity: str = "admin@example.com") -> tuple[str, dict[str, str]]:
    response = client.post(
        "/api/tokens", json={"identity": identity, "secret": "correct", "scope": "user"}
    )
    assert response.status_code == 200
    token = response.json()["result"]["token"]
    return token, {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize(
    "authorization",
    [None, "", "Basic dXNlcjpwYXNz", "bearer invalid", "Bearer", "Bearer ", "Bearer fabricated"],
)
def test_authentication_fails_closed_for_missing_malformed_and_forged_credentials(
    client: TestClient, authorization: str | None
) -> None:
    headers = {} if authorization is None else {"Authorization": authorization}
    response = client.get("/api/nginx/proxy-hosts", headers=headers)
    assert response.status_code == 401
    assert response.json()["detail"] in {"bearer token required", "invalid token"}


def test_refresh_rotates_session_and_rejects_replay(client: TestClient) -> None:
    old_token, old_headers = login(client)
    refreshed = client.get("/api/tokens", headers=old_headers)
    assert refreshed.status_code == 200
    new_token = refreshed.json()["token"]
    assert new_token != old_token
    assert client.get("/api/nginx/proxy-hosts", headers=old_headers).status_code == 401
    new_headers = {"Authorization": f"Bearer {new_token}"}
    assert client.get("/api/nginx/proxy-hosts", headers=new_headers).status_code == 200


def test_token_store_expiry_pat_tamper_revocation_and_hash_at_rest() -> None:
    principal = Principal(7, "robot@example.com", is_admin=True)
    store = TokenStore(session_ttl_seconds=10)
    session, _ = store.issue_session(principal, now=100)
    assert store.verify(session, now=109) == principal
    with pytest.raises(ValueError, match="expired"):
        store.verify(session, now=110)

    record, plaintext = store.create_pat(
        name=" deployment ", principal=principal, expires_at=200, now=100
    )
    assert record.name == "deployment"
    assert plaintext not in record.token_hash
    assert store.verify(plaintext, now=150) == principal
    assert record.last_used_at == 150
    with pytest.raises(ValueError, match="invalid"):
        store.verify(f"{plaintext}tampered", now=150)
    assert store.revoke_pat(record.id, now=151) is True
    assert store.revoke_pat(record.id, now=152) is False
    with pytest.raises(ValueError, match="invalid"):
        store.verify(plaintext, now=152)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"identity": "admin@example.com"},
        {"identity": "", "secret": "correct"},
        {"identity": 1, "secret": "correct"},
        {"identity": "admin@example.com", "secret": "correct", "scope": "admin"},
    ],
)
def test_login_rejects_malformed_or_scope_escalating_payloads(
    client: TestClient, payload: dict[str, Any]
) -> None:
    assert client.post("/api/tokens", json=payload).status_code == 400


def test_resource_boundary_rejects_non_objects_ids_bad_metadata_and_bad_routes(
    client: TestClient,
) -> None:
    _, headers = login(client)
    path = "/api/nginx/proxy-hosts"
    assert client.post(path, headers=headers, json=[]).status_code == 422
    assert client.post(path, headers=headers, json={"id": 99}).status_code == 400
    assert client.post(path, headers=headers, json={"meta": "npmctl"}).status_code == 422
    assert client.get(f"{path}/0", headers=headers).status_code == 422
    assert client.get(f"{path}/-1", headers=headers).status_code == 422
    assert client.get(f"{path}/not-a-number", headers=headers).status_code == 422
    malformed = client.post(
        path,
        headers={**headers, "content-type": "application/json"},
        content=b'{"domain_names": [}',
    )
    assert malformed.status_code == 422


def test_rbac_and_visibility_do_not_disclose_foreign_resources(
    client: TestClient, wire_service: WireService
) -> None:
    wire_service.data["proxy_hosts"] = [
        {"id": 1, "owner_user_id": 2, "domain_names": ["mine.example"]},
        {"id": 2, "owner_user_id": 9, "domain_names": ["foreign.example"]},
        {"id": 3, "domain_names": ["unowned.example"]},
    ]
    _, viewer = login(client, "viewer@example.com")
    assert [row["id"] for row in client.get("/api/nginx/proxy-hosts", headers=viewer).json()] == [1]
    assert client.get("/api/nginx/proxy-hosts/2", headers=viewer).status_code == 404
    assert client.get("/api/nginx/proxy-hosts/3", headers=viewer).status_code == 404
    assert client.patch("/api/nginx/proxy-hosts/1", headers=viewer, json={}).status_code == 403
    assert client.get("/api/users", headers=viewer).status_code == 403
    assert client.get("/api/audit-log", headers=viewer).status_code == 403

    _, manager = login(client, "manager@example.com")
    assert (
        client.patch("/api/nginx/proxy-hosts/2", headers=manager, json={"enabled": 0}).status_code
        == 404
    )
    assert client.delete("/api/nginx/proxy-hosts/2", headers=manager).status_code == 404


def test_npmctl_wire_contract_preserves_raw_arrays_ids_extensions_and_owner_metadata(
    client: TestClient,
) -> None:
    _, headers = login(client)
    metadata = {"managed_by": "npmctl", "owner": "groupsum", "resource_id": "proxy.web"}
    payload = {
        "domain_names": ["web.example.com"],
        "forward_scheme": "http",
        "forward_host": "web",
        "forward_port": 8080,
        "meta": metadata,
        "npmctl_extension": {"generation": 12, "labels": ["prod"]},
    }
    created = client.post("/api/nginx/proxy-hosts", headers=headers, json=payload)
    assert created.status_code == 201
    assert created.json() == {**payload, "id": 1}
    listed = client.get("/api/nginx/proxy-hosts", headers=headers)
    assert listed.headers["content-type"].startswith("application/json")
    assert listed.json() == [created.json()]

    patched = client.patch("/api/nginx/proxy-hosts/1", headers=headers, json={"forward_port": 9090})
    assert patched.status_code == 200
    assert patched.json()["id"] == 1
    assert patched.json()["meta"] == metadata
    assert patched.json()["npmctl_extension"] == payload["npmctl_extension"]
    assert patched.json()["forward_port"] == 9090

    schema = client.get("/api/schema").json()
    assert schema["info"]["version"] == "2.10.4"
    assert schema["paths"]["/nginx/proxy-hosts/{resource_id}"]["patch"]
    assert client.get("/api/").json()["version"] == {"major": 7, "minor": 12, "revision": 31}


def test_totp_vectors_window_validation_and_backup_codes_are_single_use() -> None:
    # RFC 6238 SHA-1 test secret and the six-digit truncation of its t=59 vector.
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert totp_code(secret, at=59, digits=8) == "94287082"
    code = totp_code(secret, at=59)
    assert verify_totp(secret, code, at=59, window=0)
    assert not verify_totp(secret, code, at=90, window=0)
    assert not verify_totp(secret, "12ab56", at=59)
    assert len(generate_totp_secret()) >= 26
    with pytest.raises(ValueError, match="base32"):
        totp_code("not valid ***", at=59)

    codes, immutable_hashes = generate_backup_codes(count=3)
    hashes = list(immutable_hashes)
    assert all(code not in hashes for code in codes)
    assert consume_backup_code(codes[0], hashes)
    assert not consume_backup_code(codes[0], hashes)
    assert len(hashes) == 2


def test_initial_setup_is_one_shot_casefolded_and_never_echoes_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "PORTWYRM_INITIAL_ADMIN_EMAIL",
        "PORTWYRM_INITIAL_ADMIN_PASSWORD",
        "INITIAL_ADMIN_EMAIL",
        "INITIAL_ADMIN_PASSWORD",
    ):
        monkeypatch.delenv(name, raising=False)
    client = TestClient(create_app(MemoryRepository()))
    assert client.get("/api/setup").json() == {"setup": False}
    password = "correct horse battery staple"
    created = client.post(
        "/api/setup", json={"email": "  OWNER@Example.COM ", "password": password}
    )
    assert created.status_code == 201
    assert created.json()["email"] == "owner@example.com"
    assert password not in created.text
    assert (
        client.post(
            "/api/setup", json={"email": "attacker@example.com", "password": "replacement"}
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/tokens",
            json={"identity": "OWNER@example.com", "secret": password, "scope": "user"},
        ).status_code
        == 200
    )


def test_no_build_ui_has_accessibility_and_static_security_invariants() -> None:
    root = Path(__file__).parents[2]
    html = (root / "src/portwyrm/ui/index.html").read_text(encoding="utf-8")
    script = (root / "src/portwyrm/ui/app.js").read_text(encoding="utf-8")
    assert '<html lang="en"' in html
    assert 'href="#content"' in html
    assert 'aria-label="Primary"' in html
    assert 'role="status"' in html and 'aria-live="polite"' in html
    assert 'aria-busy="true"' in html
    assert '<script type="module" src="/ui/app.js"></script>' in html
    assert "<script>" not in html
    assert "http://" not in html and "https://" not in html
    assert "eval(" not in script and "new Function" not in script
    assert 'localStorage.getItem("portwyrm.token")' not in script
    assert "/api/v2/browser/login" in script
    assert "X-CSRF-Token" in script
    assert json.dumps("correct horse battery staple") not in html + script
    assert "function escapeHtml(value)" in script
    assert "function displayValue(key, value)" in script
    assert "displayValue(key, row[key])" in script
    assert "<pre>${escapeHtml(JSON.stringify(health.components" in script
    assert "<p>${escapeHtml(error.message)}" in script

    app_client = TestClient(create_app(MemoryRepository()))
    page = app_client.get("/ui/")
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    assert app_client.get("/ui/app.js").headers["content-type"].startswith("text/javascript")
    assert app_client.get("/ui/styles.css").headers["content-type"].startswith("text/css")
