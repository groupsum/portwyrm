from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from portwyrm.certificates import (
    CertificateMaterialStore,
    CertificateRequest,
    IssuedCertificate,
    TableCertificateManager,
)


class Issuer:
    def issue(self, domains: tuple[str, ...], **_kwargs: Any) -> IssuedCertificate:
        assert domains == ("video.example.test",)
        return IssuedCertificate(
            "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
            "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
            "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----",
            datetime(2030, 1, 1, tzinfo=UTC),
        )


class ObservingResources:
    def __init__(self, material_root: Path) -> None:
        self.material_root = material_root
        self.rows: dict[int, dict[str, Any]] = {}
        self.status_events: list[tuple[str, str]] = []

    async def create_resource(
        self,
        collection: str,
        payload: dict[str, Any],
        **_kwargs: Any,
    ) -> dict[str, Any]:
        assert collection == "certificates"
        row = {**payload, "id": 1}
        self.rows[1] = row
        self.status_events.append(("create", str(row["status"])))
        return dict(row)

    async def update_resource(
        self,
        collection: str,
        resource_id: int,
        payload: dict[str, Any],
        **_kwargs: Any,
    ) -> dict[str, Any]:
        assert collection == "certificates"
        if payload.get("status") == "active":
            assert (self.material_root / f"npm-{resource_id}" / "fullchain.pem").is_file()
        self.rows[resource_id].update(payload)
        self.status_events.append(("update", str(self.rows[resource_id]["status"])))
        return dict(self.rows[resource_id])

    async def delete_resource(self, _collection: str, resource_id: int) -> bool:
        return self.rows.pop(resource_id, None) is not None


def test_acme_certificate_material_exists_before_record_activation(tmp_path: Path) -> None:
    material_root = tmp_path / "live"
    resources = ObservingResources(material_root)
    manager = TableCertificateManager(
        resources,  # type: ignore[arg-type]
        CertificateMaterialStore(material_root),
        issuer=Issuer(),
    )

    async def exercise() -> None:
        created = await manager.request(
            CertificateRequest("Video", ("video.example.test",), "admin@example.test")
        )
        assert created["status"] == "active"

    asyncio.run(exercise())
    assert resources.status_events == [("create", "pending"), ("update", "active")]
