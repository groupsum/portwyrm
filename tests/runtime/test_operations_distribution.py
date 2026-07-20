"""Operational hooks and distribution-policy assurance coverage."""

import asyncio
from pathlib import Path

from portwyrm.api import create_app
from portwyrm.config import PortwyrmSettings


def test_global_audit_hook_redacts_credentials_and_records_semantic_actions() -> None:
    async def run() -> None:
        app = create_app(settings=PortwyrmSettings(backend="memory"))
        await app.core.PrincipalStore.register(
            {
                "email": "audit@example.test",
                "password": "never-record-this",
                "display_name": "Audit",
                "is_admin": True,
            }
        )
        host = await app.core.RoutingHostStore.create(
            {
                "kind": "proxy",
                "domain_names": ["audit.example.test"],
                "forward_scheme": "http",
                "forward_host": "backend",
                "forward_port": 8080,
                "target_kind": "dns",
            }
        )
        await app.core.RoutingHostStore.disable({"id": host["id"]})
        events = await app.core.AuditEventStore.list({})
        registration = next(event for event in events if event["action"] == "register")
        assert registration["details"]["password"] == "[redacted]"
        assert any(event["action"] == "disabled" for event in events)

    asyncio.run(run())


def test_distribution_workflow_retains_fail_closed_supply_chain_gates() -> None:
    workflow = (Path(__file__).parents[2] / ".github" / "workflows" / "container.yml").read_text(
        encoding="utf-8"
    )
    for contract in (
        "linux/amd64,linux/arm64",
        "sbom: true",
        "provenance: mode=max",
        "cosign sign --yes",
        "actions/attest@v4",
        'exit-code: "1"',
    ):
        assert contract in workflow


def test_local_compose_image_is_not_a_published_channel() -> None:
    compose = (Path(__file__).parents[2] / "compose.yaml").read_text(encoding="utf-8")
    assert "image: portwyrm:local" in compose
    assert "ghcr.io/groupsum/portwyrm:edge" not in compose
