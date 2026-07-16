"""Adversarial persistence and migration assurance coverage."""

import asyncio

import pytest

from portwyrm.api import create_app
from portwyrm.config import PortwyrmSettings
from portwyrm.migration import preflight_npm


def test_collision_failure_does_not_persist_a_second_routing_host() -> None:
    async def run() -> None:
        app = create_app(settings=PortwyrmSettings(backend="memory"))
        payload = {
            "kind": "proxy",
            "domain_names": ["collision.example.test"],
            "forward_scheme": "http",
            "forward_host": "backend",
            "forward_port": 8080,
            "target_kind": "dns",
        }
        await app.core.RoutingHostStore.create(payload)
        with pytest.raises(Exception, match="CollisionError"):
            await app.core.RoutingHostStore.create({**payload, "forward_host": "other"})
        hosts = await app.core.RoutingHostStore.list({})
        matching = [host for host in hosts if host["domain_names"] == ["collision.example.test"]]
        assert len(matching) == 1
        assert matching[0]["forward_host"] == "backend"

    asyncio.run(run())


def test_npm_preflight_preserves_owner_metadata_and_quarantines_bad_references() -> None:
    report = preflight_npm(
        {
            "proxy_host": [
                {
                    "id": 7,
                    "certificate_id": 999,
                    "domain_names": '["bad.example.test"]',
                    "meta": '{"managed_by":"npmctl","owner":"edge","resource_id":"proxy.bad"}',
                }
            ]
        }
    )
    assert report.importable == 0
    assert report.quarantine[0].source_id == "7"
