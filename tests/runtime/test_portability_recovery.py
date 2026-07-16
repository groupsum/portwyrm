from __future__ import annotations

from pathlib import Path

from tigrbl.factories.engine import sqlitef

from portwyrm.api import create_app
from portwyrm.config import PortwyrmSettings
from tests.support import TestClient


def _client(root: Path) -> TestClient:
    root.mkdir(parents=True, exist_ok=True)
    database = root / "portwyrm.sqlite"
    return TestClient(
        create_app(
            settings=PortwyrmSettings(
                backend="sqlite",
                data_root=root,
                sqlite_path=database,
            ),
            engine=sqlitef(str(database), async_=False),
        )
    )


def _admin(client: TestClient, email: str) -> dict[str, str]:
    password = "a strong recovery password"
    assert client.post("/api/setup", json={"email": email, "password": password}).status_code == 201
    login = client.post("/api/tokens", json={"identity": email, "secret": password})
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['result']['token']}"}


def test_configuration_bundle_restores_into_fresh_instance_with_stable_ids(
    tmp_path: Path,
) -> None:
    source = _client(tmp_path / "source")
    source_headers = _admin(source, "source-admin@example.test")
    access_list = source.post(
        "/api/nginx/access-lists",
        headers=source_headers,
        json={
            "name": "Recovery policy",
            "clients": [{"address": "10.0.0.0/8", "directive": "allow"}],
            "meta": {
                "managed_by": "npmctl",
                "owner": "recovery",
                "resource_id": "acl.recovery",
            },
        },
    )
    assert access_list.status_code == 201, access_list.text
    host = source.post(
        "/api/nginx/proxy-hosts",
        headers=source_headers,
        json={
            "domain_names": ["recovery.example.test"],
            "forward_scheme": "http",
            "forward_host": "recovered-upstream",
            "forward_port": 8080,
            "access_list_id": access_list.json()["id"],
            "meta": {
                "managed_by": "npmctl",
                "owner": "recovery",
                "resource_id": "proxy.recovery",
            },
        },
    )
    assert host.status_code == 201, host.text

    exported = source.get("/api/v2/export", headers=source_headers)
    assert exported.status_code == 200
    bundle = exported.json()
    assert "users" not in {entry["collection"] for entry in bundle["records"]}

    target = _client(tmp_path / "target")
    target_headers = _admin(target, "target-admin@example.test")
    preview = target.post("/api/v2/import/preview", headers=target_headers, json=bundle)
    assert preview.status_code == 200, preview.text
    assert preview.json()["created"] == len(bundle["records"])
    restored = target.post("/api/v2/import", headers=target_headers, json=bundle)
    assert restored.status_code == 200, restored.text
    assert restored.json()["created"] == len(bundle["records"])

    recovered_host = target.get(
        f"/api/nginx/proxy-hosts/{host.json()['id']}", headers=target_headers
    )
    assert recovered_host.status_code == 200
    assert recovered_host.json()["forward_host"] == "recovered-upstream"
    assert recovered_host.json()["access_list_id"] == access_list.json()["id"]
    assert recovered_host.json()["meta"] == {
        "managed_by": "npmctl",
        "owner": "recovery",
        "resource_id": "proxy.recovery",
    }


def test_configuration_bundle_rejects_checksum_tampering(tmp_path: Path) -> None:
    client = _client(tmp_path / "tamper")
    headers = _admin(client, "tamper-admin@example.test")
    bundle = client.get("/api/v2/export", headers=headers).json()
    bundle["source_backend"] = "tampered"
    response = client.post("/api/v2/import/preview", headers=headers, json=bundle)
    assert response.status_code == 400
    assert "checksum mismatch" in response.text
