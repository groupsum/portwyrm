"""Installed composition and restart assurance coverage."""

import asyncio
from pathlib import Path

from portwyrm.api import create_app
from portwyrm.config import PortwyrmSettings


def test_sqlite_identity_and_routing_survive_full_app_reconstruction(tmp_path: Path) -> None:
    async def run() -> None:
        settings = PortwyrmSettings(
            backend="sqlite",
            data_root=tmp_path,
            sqlite_path=tmp_path / "composed.sqlite",
        )
        first = create_app(settings=settings)
        principal = await first.core.PrincipalStore.register(
            {
                "email": "restart@example.test",
                "password": "correct horse battery staple",
                "display_name": "Restart",
                "is_admin": True,
            }
        )
        host = await first.core.RoutingHostStore.create(
            {
                "kind": "proxy",
                "domain_names": ["restart.example.test"],
                "forward_scheme": "http",
                "forward_host": "backend",
                "forward_port": 8080,
                "target_kind": "dns",
            }
        )

        reconstructed = create_app(settings=settings)
        authenticated = await reconstructed.core.CredentialStore.authenticate(
            {"email": "restart@example.test", "password": "correct horse battery staple"}
        )
        persisted = await reconstructed.core.RoutingHostStore.read({"id": host["id"]})
        assert authenticated["principal_id"] == principal["id"]
        assert persisted["domain_names"] == ["restart.example.test"]

    asyncio.run(run())
