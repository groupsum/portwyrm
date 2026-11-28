from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from tigrbl.factories.engine import sqlitef

from portwyrm.api import create_app
from portwyrm.certificates import IssuedCertificate
from portwyrm.config import PortwyrmSettings
from portwyrm.tables.certificates import CertificateStore
from tests.runtime.test_certificates_runtime import CERTIFICATE, PRIVATE_KEY
from tests.support import TestClient


def test_standard_certificate_permissions_and_ownership(tmp_path: Path, monkeypatch) -> None:
    database = tmp_path / "portwyrm.sqlite"
    app = create_app(
        settings=PortwyrmSettings(backend="sqlite", data_root=tmp_path, sqlite_path=database),
        engine=sqlitef(str(database), async_=False),
    )
    client = TestClient(app)
    password = "a strong local test password"
    email = "admin@example.test"
    assert client.post("/api/setup", json={"email": email, "password": password}).status_code == 201
    login = client.post("/api/tokens", json={"identity": email, "secret": password})
    assert login.status_code == 200
    admin = {"Authorization": "Bearer " + login.json()["result"]["token"]}

    def account(name, grant):
        response = client.post(
            "/api/users",
            headers=admin,
            json={
                "name": name,
                "nickname": name,
                "email": f"{name}@example.test",
                "password": password,
                "visibility": "all",
                "permissions": {"certificates": grant},
            },
        )
        assert response.status_code == 201, response.text
        user_id = response.json()["id"]
        updated = client.patch(f"/api/users/{user_id}", headers=admin, json={"visibility": "all"})
        assert updated.status_code == 200
        return user_id

    def key(user_id, *scopes, status=201):
        issued = client.post(
            f"/api/v2/users/{user_id}/tokens",
            headers=admin,
            json={"name": "certificate contract test", "scopes": list(scopes)},
        )
        assert issued.status_code == status
        if status == 201:
            return {"Authorization": "Bearer " + issued.json()["token"]}

    owner = account(
        "owner", dict.fromkeys(("create", "read", "update", "delete", "download"), True)
    )
    other = account("other", dict.fromkeys(("read", "update", "delete", "download"), True))
    legacy = account("legacy", "manage")
    owner_key = key(
        owner,
        "certificates:create",
        "certificates:read",
        "certificates:update",
        "certificates:delete",
    )
    download_key = key(owner, "certificates:download")
    other_key = key(
        other,
        "certificates:read",
        "certificates:update",
        "certificates:delete",
        "certificates:download",
    )
    key(legacy, "certificates:download", status=403)
    key(owner, "proxy_hosts:download", status=403)

    issued_domains = []

    class TestIssuer:
        def issue(self, domains, **kwargs):
            issued_domains.append(domains)
            return IssuedCertificate(
                CERTIFICATE, PRIVATE_KEY, CERTIFICATE, datetime(2030, 1, 1, tzinfo=UTC)
            )

    monkeypatch.setattr(CertificateStore._require_workflow(), "issuer", TestIssuer())
    endpoint = "/api/nginx/certificates"
    certificate = client.post(
        f"{endpoint}/request",
        headers=owner_key,
        json={"nice_name": "App", "domain_names": ["app.example.com"], "email": email},
    )
    assert certificate.status_code == 201, certificate.text
    path = f"{endpoint}/{certificate.json()['id']}"
    assert client.get(path, headers=owner_key).status_code == 200
    assert client.get(path, headers=other_key).status_code == 200
    assert client.get(path, headers=download_key).status_code == 403
    assert client.get(f"{path}/download", headers=owner_key).status_code == 403
    assert client.get(f"{path}/download", headers=other_key).status_code == 404
    assert client.get(f"{path}/download", headers=admin).status_code == 200

    archive = client.get(f"{path}/download", headers=download_key)
    assert archive.status_code == 200
    assert archive.headers["content-type"] == "application/zip"
    assert archive.content.startswith(b"PK")

    assert client.post(f"{path}/renew", headers=other_key).status_code == 404
    assert client.delete(path, headers=other_key).status_code == 404
    assert client.patch(path, headers=other_key, json={"nice_name": "Different"}).status_code == 404
    assert issued_domains == [("app.example.com",)]
    assert client.post(f"{path}/renew?force=true", headers=owner_key).status_code == 200
    assert issued_domains == [("app.example.com",), ("app.example.com",)]
    assert client.delete(path, headers=owner_key).status_code == 200
    assert client.get(path, headers=admin).status_code == 404
