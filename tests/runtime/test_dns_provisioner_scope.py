from __future__ import annotations

import asyncio
from pathlib import Path

from tigrbl.factories.engine import sqlitef

from portwyrm.api import create_app
from portwyrm.config import PortwyrmSettings
from portwyrm.tables.certificates import CertificateStore
from tests.runtime.test_certificates_runtime import FakeIssuer
from tests.support import TestClient


def test_dns_provisioner_api_key_enforces_owned_resources(tmp_path: Path) -> None:
    database = tmp_path / "portwyrm.sqlite"
    app = create_app(
        settings=PortwyrmSettings(backend="sqlite", data_root=tmp_path, sqlite_path=database),
        engine=sqlitef(str(database), async_=False),
    )
    client = TestClient(app)
    credentials = {"email": "admin@example.test", "password": "a strong admin password"}
    assert client.post("/api/setup", json=credentials).status_code == 201
    login = client.post(
        "/api/tokens", json={"identity": credentials["email"], "secret": credentials["password"]}
    )
    assert login.status_code == 200, login.text
    admin = {"Authorization": f"Bearer {login.json()['result']['token']}"}
    scopes = ["dns_provisioner:execute"]
    assert (
        client.post(
            "/api/v2/tokens", headers=admin, json={"name": "invalid", "scopes": scopes}
        ).status_code
        == 403
    )
    permissions = {
        name: {action: True for action in ("read", "create", "update", "delete")}
        for name in ("proxy_hosts", "certificates")
    }
    user = client.post(
        "/api/users",
        headers=admin,
        json={
            "name": "Executor",
            "nickname": "executor",
            "email": "executor@example.test",
            "password": "a strong executor password",
            "is_admin": 0,
            "visibility": "all",
            "permissions": permissions,
        },
    )
    assert user.status_code == 201, user.text
    owner_id = user.json()["id"]
    issued = client.post(
        f"/api/v2/users/{owner_id}/tokens",
        headers=admin,
        json={"name": "provisioner", "scopes": scopes},
    )
    assert issued.status_code == 201, issued.text
    key = {"Authorization": f"Bearer {issued.json()['token']}"}
    capability = client.get("/api/v2/dns-provisioner/capabilities", headers=key)
    assert capability.status_code == 200, capability.text
    assert capability.json() == {
        "scope": scopes[0],
        "owned_only": True,
        "certificate_download": False,
    }

    async def seed_certificates():
        result = []
        for owner, label, manager in (
            (1, "foreign", "domain-provisioner"),
            (owner_id, "manual", "other"),
        ):
            cert = await app.core.CertificateStore.create(
                {
                    "nice_name": label,
                    "owner_principal_id": owner,
                    "provider": "letsencrypt",
                    "domain_names": [f"{label}.example.test"],
                    "status": "active",
                    "material_ref": "local-material-reference",
                    "expires_at": 2147483647,
                    "meta": {
                        "managed_by": manager,
                        "owner": "p" * 22,
                        "resource_id": label[0] * 22,
                    },
                }
            )
            result.append(cert["id"])
        return result

    foreign, manual = asyncio.run(seed_certificates())
    issuer = FakeIssuer()
    CertificateStore._require_workflow().issuer = issuer
    certificates = "/api/nginx/certificates"
    proxies = "/api/nginx/proxy-hosts"
    requested = client.post(
        f"{certificates}/request",
        headers=key,
        json={
            "nice_name": "own",
            "provider": "letsencrypt",
            "domain_names": ["app.example.com"],
            "challenge_type": "http-01",
            "email": "admin@example.test",
            "meta": {
                "managed_by": "domain-provisioner",
                "owner": "p" * 22,
                "resource_id": "c" * 22,
            },
        },
    )
    assert requested.status_code == 201, requested.text
    assert requested.json()["status"] == "active"
    own = requested.json()["id"]
    assert "provisioner_lineage" not in requested.json()["meta"]
    renewed = client.post(f"{certificates}/{own}/renew?force=true", headers=key)
    assert renewed.status_code == 200, renewed.text
    assert len(issuer.requests) == 2
    assert issuer.requests[0][1]["lineage"] == issuer.requests[1][1]["lineage"]
    assert issuer.requests[1][1]["force_renewal"] is True
    visible = client.get(certificates, headers=key)
    assert visible.status_code == 200, visible.text
    assert [item["id"] for item in visible.json()] == [own]
    assert "material_ref" not in visible.json()[0]
    for identifier in (foreign, manual):
        assert client.get(f"{certificates}/{identifier}", headers=key).status_code == 404
        assert client.post(f"{certificates}/{identifier}/renew", headers=key).status_code == 404
        assert client.delete(f"{certificates}/{identifier}", headers=key).status_code == 404
    assert client.get(f"{certificates}/{own}/download", headers=key).status_code == 403
    assert client.get("/api/v2/tokens", headers=key).status_code == 403
    payload = {
        "domain_names": ["app.example.com"],
        "forward_scheme": "http",
        "forward_host": "backend",
        "forward_port": 8080,
        "certificate_id": own,
        "enabled": 1,
        "meta": {"managed_by": "domain-provisioner", "owner": "p" * 22, "resource_id": "r" * 22},
    }
    denied = client.post(proxies, headers=key, json={**payload, "certificate_id": foreign})
    assert denied.status_code == 404, denied.text
    created = client.post(proxies, headers=key, json=payload)
    assert created.status_code == 201, created.text
    proxy_id = created.json()["id"]
    path = f"{proxies}/{proxy_id}"
    manual_proxy = client.post(
        proxies,
        headers=admin,
        json={
            "domain_names": ["admin.example.test"],
            "forward_host": "backend",
            "forward_port": 8080,
        },
    )
    assert manual_proxy.status_code == 201, manual_proxy.text
    manual_path = f"{proxies}/{manual_proxy.json()['id']}"
    assert client.get(manual_path, headers=key).status_code == 404
    assert client.delete(manual_path, headers=key).status_code == 404
    assert client.get(path, headers=key).json()["certificate_id"] == own
    updated = client.put(path, headers=key, json={**payload, "forward_port": 8081})
    assert updated.status_code == 200, updated.text
    assert updated.json()["forward_port"] == 8081
    assert client.delete(path, headers=key).status_code == 200
    assert client.delete(f"{certificates}/{own}", headers=key).status_code == 200
