"""Current Tigrbl persistence profile assurance coverage."""

import asyncio
from pathlib import Path

import pytest

from portwyrm.api import create_app
from portwyrm.config import PortwyrmSettings


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_supported_local_backends_persist_canonical_setting_crud(
    backend: str, tmp_path: Path
) -> None:
    async def run() -> None:
        settings = PortwyrmSettings(
            backend=backend,
            data_root=tmp_path,
            sqlite_path=tmp_path / f"{backend}.sqlite",
        )
        app = create_app(settings=settings)
        created = await app.core.SettingStore.create(
            {"key": f"theme-{backend}", "value": {"mode": "dark"}}
        )
        updated = await app.core.SettingStore.update(
            {"id": created["id"], "value": {"mode": "light"}}
        )
        assert updated["value"] == {"mode": "light"}
        assert (await app.core.SettingStore.read({"id": created["id"]}))["key"] == (
            f"theme-{backend}"
        )

    asyncio.run(run())
