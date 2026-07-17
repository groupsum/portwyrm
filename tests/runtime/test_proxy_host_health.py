"""T1 acceptance coverage for proxy-host operational health."""

from __future__ import annotations

from pathlib import Path

from tigrbl.factories.engine import sqlitef

from portwyrm.api import create_app
from portwyrm.config import PortwyrmSettings
from portwyrm.health import (
    AdministrativeState,
    DeploymentState,
    ProbePhase,
    ReachabilityState,
    derive_host_summary,
)
from portwyrm.runtime import ProbeResult
from portwyrm.tables.routing import RoutingHostStore
from tests.support import TestClient


class _SequencedProber:
    def __init__(self) -> None:
        self.status = ReachabilityState.ONLINE

    async def probe(self, target: object) -> ProbeResult:
        return ProbeResult(
            status=self.status,
            phase=ProbePhase.HTTP
            if self.status == ReachabilityState.ONLINE
            else ProbePhase.CONNECT,
            checked_at=1_800_000_000,
            latency_ms=12,
            http_status=204 if self.status == ReachabilityState.ONLINE else None,
            error_code=None
            if self.status == ReachabilityState.ONLINE
            else "ConnectionRefusedError",
            error_detail=None if self.status == ReachabilityState.ONLINE else "connection refused",
        )


def _authorized_client(tmp_path: Path) -> tuple[TestClient, dict[str, str]]:
    database = tmp_path / "health.sqlite"
    client = TestClient(
        create_app(
            settings=PortwyrmSettings(backend="sqlite", data_root=tmp_path, sqlite_path=database),
            engine=sqlitef(str(database), async_=False),
        )
    )
    client.post(
        "/api/setup", json={"email": "health@example.test", "password": "a strong admin password"}
    )
    token = client.post(
        "/api/tokens", json={"identity": "health@example.test", "secret": "a strong admin password"}
    ).json()["result"]["token"]
    return client, {"Authorization": f"Bearer {token}"}


def test_summary_precedence_preserves_independent_state_dimensions() -> None:
    assert (
        derive_host_summary(
            AdministrativeState.DISABLED, DeploymentState.APPLIED, ReachabilityState.ONLINE
        )
        == "disabled"
    )
    assert (
        derive_host_summary(
            AdministrativeState.ENABLED, DeploymentState.FAILED, ReachabilityState.ONLINE
        )
        == "failed"
    )
    assert (
        derive_host_summary(
            AdministrativeState.ENABLED, DeploymentState.APPLIED, ReachabilityState.OFFLINE
        )
        == "offline"
    )


def test_probe_status_api_persists_observations_and_audits_transitions(tmp_path: Path) -> None:
    client, headers = _authorized_client(tmp_path)
    created = client.post(
        "/api/nginx/proxy-hosts",
        headers=headers,
        json={
            "domain_names": ["health.example.test"],
            "forward_scheme": "http",
            "forward_host": "upstream",
            "forward_port": 8080,
            "target_kind": "docker",
            "enabled": 1,
        },
    )
    assert created.status_code == 201, created.text
    host_id = created.json()["id"]
    prober = _SequencedProber()
    RoutingHostStore.configure_health_runtime(prober, freshness_seconds=60)

    initial = client.get(f"/api/v2/proxy-hosts/{host_id}/status", headers=headers)
    assert initial.status_code == 200, initial.text
    assert initial.json()["administrative_state"] == "enabled"
    assert initial.json()["reachability_state"] == "unknown"

    online = client.post(f"/api/v2/proxy-hosts/{host_id}/probe", headers=headers)
    assert online.status_code == 200, online.text
    assert online.json()["reachability_state"] == "online"
    assert online.json()["http_status"] == 204

    prober.status = ReachabilityState.OFFLINE
    offline = client.post(f"/api/v2/proxy-hosts/{host_id}/probe", headers=headers)
    assert offline.status_code == 200, offline.text
    assert offline.json()["reachability_state"] == "offline"
    assert offline.json()["error_code"] == "ConnectionRefusedError"
    listed = client.get("/api/v2/proxy-hosts/status", headers=headers).json()["items"]
    assert next(item for item in listed if item["id"] == host_id)["reachability_state"] == "offline"

    audit = client.get("/api/audit-log", headers=headers).json()
    assert any(
        event["action"] == "proxy_host.health.changed" and event["object_id"] == str(host_id)
        for event in audit
    )

    database = tmp_path / "health.sqlite"
    restarted = TestClient(
        create_app(
            settings=PortwyrmSettings(backend="sqlite", data_root=tmp_path, sqlite_path=database),
            engine=sqlitef(str(database), async_=False),
        )
    )
    after_restart = restarted.get(f"/api/v2/proxy-hosts/{host_id}/status", headers=headers)
    assert after_restart.status_code == 200, after_restart.text
    assert after_restart.json()["reachability_state"] == "offline"
