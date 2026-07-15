from __future__ import annotations

import importlib.util
from pathlib import Path

from portwyrm.application import PersistentControlPlane
from portwyrm.persistence import MemoryRepository

_ENTRYPOINT = Path(__file__).parents[2] / "deploy" / "entrypoint.py"
_SPEC = importlib.util.spec_from_file_location("portwyrm_deploy_entrypoint", _ENTRYPOINT)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
seed_demo_proxy_host = _MODULE.seed_demo_proxy_host


def test_demo_host_is_opt_in(monkeypatch) -> None:
    monkeypatch.delenv("PORTWYRM_DEMO_HOST", raising=False)
    control_plane = PersistentControlPlane(MemoryRepository())

    seed_demo_proxy_host(control_plane)

    assert control_plane.list("proxy-hosts") == []


def test_demo_host_uses_dns_free_localhost_and_repairs_existing(monkeypatch) -> None:
    monkeypatch.setenv("PORTWYRM_DEMO_HOST", "Demo.Portwyrm.Localhost")
    control_plane = PersistentControlPlane(MemoryRepository())

    seed_demo_proxy_host(control_plane)
    seed_demo_proxy_host(control_plane)

    hosts = control_plane.list("proxy-hosts")
    assert len(hosts) == 1
    assert hosts[0]["domain_names"] == ["demo.portwyrm.localhost"]
    assert hosts[0]["forward_host"] == "127.0.0.1"
    assert hosts[0]["forward_port"] == 81
    assert hosts[0]["allow_websocket_upgrade"] == 1
    assert hosts[0]["meta"]["managed_by"] == "portwyrm-demo"
