from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

from portwyrm.api.compat import _service_create
from portwyrm.api.compat.resources import TableResources
from portwyrm.security import Principal


class RecordingCertificateStore:
    def __init__(self) -> None:
        self.payload: dict[str, Any] | None = None
        self.context: dict[str, Any] | None = None

    async def request(
        self,
        payload: dict[str, Any],
        *,
        ctx: dict[str, Any],
    ) -> dict[str, Any]:
        self.payload = payload
        self.context = ctx
        return {"id": 9, **payload, "provider": "letsencrypt", "status": "active"}


def test_generic_npm_letsencrypt_create_dispatches_real_issuance_operation() -> None:
    certificates = RecordingCertificateStore()
    service = TableResources(SimpleNamespace(core=SimpleNamespace(CertificateStore=certificates)))
    principal = Principal(
        user_id=7,
        identity="automation@example.test",
        is_admin=True,
        owner="tigrbl-wt-video-demo",
    )
    meta = {
        "letsencrypt_email": "admin@example.test",
        "letsencrypt_agree": True,
        "dns_challenge": False,
        "managed_by": "wyrmctl",
        "owner": "tigrbl-wt-video-demo",
        "resource_id": "cert.tigrbl-wt-video-demo",
    }

    created = asyncio.run(
        _service_create(
            service,
            "certificates",
            {
                "nice_name": "video.example.test",
                "provider": "letsencrypt",
                "domain_names": ["video.example.test"],
                "meta": meta,
            },
            principal,
        )
    )

    assert created["status"] == "active"
    assert certificates.payload == {
        "nice_name": "video.example.test",
        "provider": "letsencrypt",
        "domain_names": ["video.example.test"],
        "email": "admin@example.test",
        "challenge_type": "http-01",
        "dns_provider": None,
        "dns_credentials": None,
        "meta": meta,
    }
    assert certificates.context is not None
    actor = certificates.context["principal"]
    assert (actor.id, actor.owner, actor.is_admin) == (7, "tigrbl-wt-video-demo", True)
