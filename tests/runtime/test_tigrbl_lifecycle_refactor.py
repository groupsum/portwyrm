from __future__ import annotations

import asyncio
import inspect

import pytest
from sqlalchemy.orm import InstrumentedAttribute
from tigrbl import HTTPException, TigrblApp
from tigrbl.factories.engine import sqlitef

from portwyrm.tables import PORTWYRM_TABLES
from portwyrm.tables.lifecycle import global_hooks
from portwyrm.tables.settings import SettingStore


def test_canonical_crud_persists_and_global_audit_is_atomic(tmp_path) -> None:
    async def run() -> None:
        tables = PORTWYRM_TABLES
        app = TigrblApp(
            engine=sqlitef(str(tmp_path / "lifecycle.sqlite"), async_=False),
            mount_system=False,
            router_hooks=global_hooks(),
        )
        app.include_tables(tables)
        initialized = app.initialize(tables=tables)
        if inspect.isawaitable(initialized):
            await initialized

        created = await app.core.SettingStore.create(
            {"key": "theme", "value": {"mode": "light"}},
        )
        assert isinstance(SettingStore.__dict__["value"], InstrumentedAttribute)

        updated = await app.core.SettingStore.update(
            {"id": created["id"], "value": {"mode": "dark"}},
        )
        assert updated["value"] == {"mode": "dark"}
        persisted = await app.core.SettingStore.read({"id": created["id"]})
        assert persisted["value"] == {"mode": "dark"}

        host = await app.core.RoutingHostStore.create(
            {
                "kind": "proxy",
                "domain_names": ["lifecycle.example.test"],
                "forward_scheme": "http",
                "forward_host": "backend",
                "forward_port": 8080,
                "target_kind": "dns",
                "enabled": True,
            }
        )
        disabled = await app.core.RoutingHostStore.disable({"id": host["id"]})
        assert disabled["enabled"] is False
        persisted_host = await app.core.RoutingHostStore.read({"id": host["id"]})
        assert bool(persisted_host["enabled"]) is False
        viewer = {
            "is_admin": False,
            "permissions": {"proxy_hosts": "view"},
            "visibility": "all",
        }
        assert (
            await app.core.RoutingHostStore.read(
                {"id": host["id"]}, ctx={"principal": viewer}
            )
        )["id"] == host["id"]
        with pytest.raises(HTTPException, match="permission denied"):
            await app.core.RoutingHostStore.enable(
                {"id": host["id"]}, ctx={"principal": viewer}
            )

        events = await app.core.AuditEventStore.list({})
        assert [(event["action"], event["actor_principal_id"]) for event in events] == [
            ("created", None),
            ("updated", None),
            ("created", None),
            ("disabled", None),
        ]

        with pytest.raises(HTTPException, match="FOREIGN KEY constraint failed"):
            await app.core.SettingStore.create(
                {"key": "must-roll-back", "value": {"enabled": True}},
                ctx={"principal": {"id": 999_999, "is_admin": True}},
            )
        remaining = await app.core.SettingStore.list({})
        assert all(row["key"] != "must-roll-back" for row in remaining)

    asyncio.run(run())
