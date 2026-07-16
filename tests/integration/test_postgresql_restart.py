from __future__ import annotations

import asyncio
import os
from pathlib import Path
from uuid import uuid4

import pytest

from portwyrm.api import create_app
from portwyrm.config import PortwyrmSettings

pytestmark = pytest.mark.skipif(
    os.getenv("PORTWYRM_RUN_DATABASE_TESTS") != "1",
    reason="set PORTWYRM_RUN_DATABASE_TESTS=1 to exercise PostgreSQL",
)


def _settings(tmp_path: Path) -> PortwyrmSettings:
    return PortwyrmSettings(
        backend="postgres",
        data_root=tmp_path,
        database_host=os.getenv("PORTWYRM_POSTGRES_HOST", "127.0.0.1"),
        database_port=int(os.getenv("PORTWYRM_POSTGRES_PORT", "5432")),
        database_name=os.getenv("PORTWYRM_POSTGRES_DATABASE", "portwyrm"),
        database_user=os.getenv("PORTWYRM_POSTGRES_USER", "portwyrm"),
        database_password=os.getenv("PORTWYRM_POSTGRES_PASSWORD", "portwyrm-test"),
    )


def test_postgresql_identity_and_routing_survive_app_reconstruction(tmp_path: Path) -> None:
    async def run() -> None:
        suffix = uuid4().hex
        email = f"restart-{suffix}@example.test"
        domain = f"restart-{suffix}.example.test"
        password = "correct horse battery staple"
        settings = _settings(tmp_path)

        first = create_app(settings=settings)
        principal = await first.core.PrincipalStore.register(
            {
                "email": email,
                "password": password,
                "display_name": "Restart proof",
                "is_admin": True,
            }
        )
        host = await first.core.RoutingHostStore.create(
            {
                "kind": "proxy",
                "domain_names": [domain],
                "forward_scheme": "http",
                "forward_host": "backend",
                "forward_port": 8080,
                "target_kind": "dns",
            }
        )

        reconstructed = create_app(settings=settings)
        authenticated = await reconstructed.core.CredentialStore.authenticate(
            {"email": email.upper(), "password": password}
        )
        persisted = await reconstructed.core.RoutingHostStore.read({"id": host["id"]})

        assert authenticated["principal_id"] == principal["id"]
        assert persisted["domain_names"] == [domain]
        assert persisted["forward_host"] == "backend"

    asyncio.run(run())
