from __future__ import annotations

import asyncio
import inspect
from pathlib import Path

import pytest
from sqlalchemy.orm import InstrumentedAttribute
from tigrbl import HTTPException, TigrblApp
from tigrbl.factories.engine import sqlitef

from portwyrm.api.compat.resources import TableResources
from portwyrm.tables import PORTWYRM_TABLES
from portwyrm.tables.access import AccessListStore
from portwyrm.tables.certificates import CertificateStore
from portwyrm.tables.credentials import CredentialStore
from portwyrm.tables.lifecycle import configure_lifecycle_runtime, global_hooks
from portwyrm.tables.mfa import MFARecoveryCodeStore
from portwyrm.tables.routing import RoutingHostStore, StreamRouteStore
from portwyrm.tables.settings import SettingStore


async def _app(path: Path) -> TigrblApp:
    app = TigrblApp(
        engine=sqlitef(str(path), async_=False),
        mount_system=False,
        router_hooks=global_hooks(),
    )
    app.include_tables(PORTWYRM_TABLES)
    initialized = app.initialize(tables=PORTWYRM_TABLES)
    if inspect.isawaitable(initialized):
        await initialized
    return app


def test_inline_lifecycle_hooks_are_declared_for_tigrbl_collection() -> None:
    hooks = {
        table.__name__: {getattr(hook, "__func__", hook).__name__ for hook in table.HOOKS}
        for table in (
            AccessListStore,
            CertificateStore,
            CredentialStore,
            RoutingHostStore,
            StreamRouteStore,
        )
    }
    assert hooks["AccessListStore"] == {
        "prepare_aggregate",
        "persist_aggregate",
        "project_aggregate",
        "delete_aggregate_children",
    }
    assert hooks["CertificateStore"] == hooks["AccessListStore"]
    assert hooks["CredentialStore"] == {
        "clear_password_change_requirement",
        "require_password_change_after_reset",
    }
    assert {"enable_payload", "disable_payload", "prepare_aggregate", "persist_aggregate"} <= hooks[
        "RoutingHostStore"
    ]
    assert hooks["StreamRouteStore"] == {"enable_payload", "disable_payload"}


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
            await app.core.RoutingHostStore.read({"id": host["id"]}, ctx={"principal": viewer})
        )["id"] == host["id"]
        with pytest.raises(HTTPException, match="permission denied"):
            await app.core.RoutingHostStore.enable({"id": host["id"]}, ctx={"principal": viewer})

        editor = {
            "is_admin": False,
            "permissions": {"proxy_hosts": "manage"},
            "visibility": "all",
        }
        with pytest.raises(HTTPException, match="advanced Nginx configuration requires"):
            await app.core.RoutingHostStore.update(
                {"id": host["id"], "advanced_config": "return 418;"},
                ctx={"principal": editor},
            )
        administrator = {"is_admin": True}
        configured = await app.core.RoutingHostStore.update(
            {"id": host["id"], "advanced_config": "client_max_body_size 32m;"},
            ctx={"principal": administrator},
        )
        assert configured["advanced_config"] == "client_max_body_size 32m;"

        events = await app.core.AuditEventStore.list({})
        assert [(event["action"], event["actor_principal_id"]) for event in events] == [
            ("created", None),
            ("updated", None),
            ("created", None),
            ("disabled", None),
            ("updated", None),
        ]

        with pytest.raises(HTTPException, match="FOREIGN KEY constraint failed"):
            await app.core.SettingStore.create(
                {"key": "must-roll-back", "value": {"enabled": True}},
                ctx={"principal": {"id": 999_999, "is_admin": True}},
            )
        remaining = await app.core.SettingStore.list({})
        assert all(row["key"] != "must-roll-back" for row in remaining)

    asyncio.run(run())


def test_collection_and_internal_operation_surfaces_are_exact(tmp_path: Path) -> None:
    async def run() -> None:
        app = await _app(tmp_path / "surfaces.sqlite")

        managed = {"create", "read", "update", "replace", "delete", "list"}
        assert set(app.core.SettingStore._model.ops.by_alias) == managed
        assert managed | {"runtime_list"} == set(app.core.AccessListStore._model.ops.by_alias)
        assert managed | {
            "enable",
            "disable",
            "validate",
            "runtime_read",
            "runtime_list",
        } == set(app.core.StreamRouteStore._model.ops.by_alias)
        assert managed | {
            "enable",
            "disable",
            "validate",
            "preview",
            "runtime_read",
            "runtime_list",
            "health_read",
            "health_list",
            "probe",
        } == set(app.core.RoutingHostStore._model.ops.by_alias)

        assert set(app.core.AuditEventStore._model.ops.by_alias) == {
            "read",
            "list",
            "record",
        }
        assert set(app.core.LeaseStore._model.ops.by_alias) == {"acquire", "renew", "release"}
        assert set(MFARecoveryCodeStore.ops.by_alias) == set()

        aliases = {
            alias
            for table in PORTWYRM_TABLES
            for alias in getattr(getattr(table, "ops", None), "by_alias", {})
        }
        assert not {alias for alias in aliases if alias.startswith("bulk_")}
        assert {
            "create_compat",
            "update_compat",
            "delete_compat",
            "compat_read",
            "compat_list",
        }.isdisjoint(aliases)

    asyncio.run(run())


def test_compatibility_transport_and_direct_core_share_canonical_state(tmp_path: Path) -> None:
    async def run() -> None:
        app = await _app(tmp_path / "carriers.sqlite")
        resources = TableResources(app)
        created = await resources.create_resource(
            "proxy_hosts",
            {
                "domain_names": ["carrier.example.test"],
                "forward_scheme": "http",
                "forward_host": "backend",
                "forward_port": 8080,
                "target_kind": "dns",
            },
        )
        direct = await app.core.RoutingHostStore.read({"id": created["id"]})
        assert direct["domain_names"] == created["domain_names"]
        assert direct["forward_host"] == created["forward_host"]
        assert direct["forward_port"] == created["forward_port"]
        assert created["allow_websocket_upgrade"] is False
        assert created["block_exploits"] is False

        updated = await app.core.RoutingHostStore.update(
            {"id": created["id"], "forward_port": 8181}
        )
        through_transport = await resources.get_resource("proxy_hosts", created["id"])
        assert updated["forward_port"] == 8181
        assert through_transport is not None
        assert through_transport["forward_port"] == 8181

        access_list = await app.core.AccessListStore.create(
            {
                "name": "Operators",
                "items": [{"username": "operator", "password": "secret"}],
                "clients": [{"address": "10.0.0.0/8", "directive": "allow"}],
            }
        )
        changed_access_list = await app.core.AccessListStore.update(
            {"id": access_list["id"], "name": "Platform operators"}
        )
        assert changed_access_list["items"] == [{"username": "operator"}]
        assert changed_access_list["clients"] == [{"address": "10.0.0.0/8", "directive": "allow"}]

        certificate = await app.core.CertificateStore.create(
            {
                "nice_name": "Carrier certificate",
                "domain_names": ["carrier.example.test"],
            }
        )
        changed_certificate = await app.core.CertificateStore.update(
            {"id": certificate["id"], "nice_name": "Renamed certificate"}
        )
        assert changed_certificate["domain_names"] == ["carrier.example.test"]

    asyncio.run(run())


def test_global_hooks_redact_secrets_and_reconcile_once_per_mutation(tmp_path: Path) -> None:
    class RuntimeProbe:
        def __init__(self) -> None:
            self.collections: list[str] = []

        async def changed(self, collection: str) -> None:
            self.collections.append(collection)

    async def run() -> None:
        runtime = RuntimeProbe()
        configure_lifecycle_runtime(lambda: runtime)
        try:
            app = await _app(tmp_path / "hooks.sqlite")
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
                    "domain_names": ["hooks.example.test"],
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
            assert runtime.collections == ["proxy_hosts", "proxy_hosts"]
        finally:
            configure_lifecycle_runtime(lambda: None)

    asyncio.run(run())


def test_post_commit_reconcile_failure_does_not_fail_durable_crud(tmp_path: Path) -> None:
    class FailingRuntime:
        async def changed(self, _collection: str) -> None:
            raise RuntimeError("nginx candidate rejected")

    async def run() -> None:
        configure_lifecycle_runtime(lambda: FailingRuntime())
        try:
            app = await _app(tmp_path / "post-commit.sqlite")
            created = await app.core.RoutingHostStore.create(
                {
                    "kind": "proxy",
                    "domain_names": ["post-commit.example.test"],
                    "forward_scheme": "http",
                    "forward_host": "backend",
                    "forward_port": 8080,
                    "target_kind": "dns",
                }
            )
            persisted = await app.core.RoutingHostStore.read({"id": created["id"]})
            assert persisted["domain_names"] == ["post-commit.example.test"]
        finally:
            configure_lifecycle_runtime(lambda: None)

    asyncio.run(run())


def test_table_modules_do_not_reimplement_kernel_persistence() -> None:
    table_root = Path(__file__).parents[2] / "src" / "portwyrm" / "tables"
    source = "\n".join(path.read_text(encoding="utf-8") for path in table_root.glob("*.py"))
    assert ".flush(" not in source
    assert ".commit(" not in source
    assert ".rollback(" not in source
    assert "def create_compat" not in source
    assert "def update_compat" not in source
    assert "def delete_compat" not in source

def test_routing_host_delete_removes_config_revisions_before_root(tmp_path: Path) -> None:
    async def run() -> None:
        app = await _app(tmp_path / "delete-revisions.sqlite")
        host = await app.core.RoutingHostStore.create(
            {
                "kind": "proxy",
                "domain_names": ["delete-revision.example.test"],
                "forward_scheme": "http",
                "forward_host": "backend",
                "forward_port": 8080,
                "target_kind": "dns",
            }
        )
        await app.core.HostConfigRevisionStore.record(
            {
                "routing_host_id": host["id"],
                "generation": "delete-test-generation",
                "config_text": "server {}",
                "config_digest": "digest",
                "applied": True,
                "applied_at": 1,
            }
        )

        resources = TableResources(app)
        assert await resources.delete_resource("proxy_hosts", host["id"])
        with pytest.raises(HTTPException, match="Resource not found"):
            await app.core.RoutingHostStore.read({"id": host["id"]})
        assert not any(
            row["routing_host_id"] == host["id"]
            for row in await app.core.HostConfigRevisionStore.list({})
        )

    asyncio.run(run())