from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path
from types import SimpleNamespace

ENTRYPOINT = Path(__file__).parents[2] / "deploy" / "entrypoint.py"
spec = importlib.util.spec_from_file_location("portwyrm_deploy_entrypoint", ENTRYPOINT)
assert spec is not None and spec.loader is not None
entrypoint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entrypoint)


def test_prepare_runtime_migrates_persistent_schema_before_reconcile(monkeypatch) -> None:
    events: list[str] = []

    class Migrations:
        async def apply(self, _payload):
            events.append("migration")

    class Runtime:
        async def reconcile(self):
            events.append("reconcile")

    app = SimpleNamespace(
        core=SimpleNamespace(SchemaMigrationStore=Migrations()),
        state=SimpleNamespace(control_plane=object(), runtime=Runtime()),
    )
    settings = SimpleNamespace(backend="postgresql")

    async def seed(_resources):
        events.append("seed")

    monkeypatch.setattr(entrypoint.PortwyrmSettings, "from_environment", lambda: settings)
    monkeypatch.setattr(entrypoint, "replace", lambda value, **_changes: value)
    monkeypatch.setattr(entrypoint, "create_app", lambda **_kwargs: app)
    monkeypatch.setattr(entrypoint, "seed_demo_proxy_host", seed)

    asyncio.run(entrypoint.prepare_runtime())

    assert events == ["migration", "seed", "reconcile"]
