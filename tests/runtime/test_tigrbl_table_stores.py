from __future__ import annotations

import asyncio
import inspect
import os
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from tigrbl import TigrblApp
from tigrbl.factories.engine import sqlitef

from portwyrm.api.compat.resources import TableResources
from portwyrm.identity.mfa import totp_code
from portwyrm.tables import (
    PORTWYRM_TABLES,
    GenerationStore,
    MFAEnrollmentStore,
    PATIssueRequest,
    PATIssueResult,
    PATStore,
    ReconcileResult,
    RoutingHostStore,
    RuntimeAccessList,
    StreamRouteStore,
)
from portwyrm.tables.lifecycle import global_hooks

_SHARED_APP: TigrblApp | None = None
_TEST_ROOT = Path(f".pytest-tmp-table-stores-{os.getpid()}").resolve()
_TEST_ROOT.mkdir(exist_ok=True)
_TEST_DATABASE = _TEST_ROOT / "tables.sqlite"


async def _app() -> TigrblApp:
    global _SHARED_APP
    if _SHARED_APP is not None:
        return _SHARED_APP
    app = TigrblApp(
        engine=sqlitef(str(_TEST_DATABASE), async_=False),
        mount_system=False,
        router_hooks=global_hooks(),
    )
    app.include_tables(PORTWYRM_TABLES)
    initialized = app.initialize(tables=PORTWYRM_TABLES)
    if inspect.isawaitable(initialized):
        await initialized
    app.state.mfa_cipher = Fernet(Fernet.generate_key())
    MFAEnrollmentStore.configure_cipher(app.state.mfa_cipher)
    _SHARED_APP = app
    return app


def test_table_inventory_covers_normalized_and_runtime_state() -> None:
    names = {table.__name__ for table in PORTWYRM_TABLES}
    assert {
        "PrincipalStore",
        "PATStore",
        "RoutingHostStore",
        "RoutingLocationStore",
        "CertificateChallengeStore",
        "GenerationStore",
        "ReconcileStore",
        "LeaseStore",
        "SchemaMigrationStore",
    } <= names
    assert "unit_of_work" not in getattr(PATStore, "__tigrbl_ops__", ())


def test_custom_schema_exports_are_owned_by_tables() -> None:
    assert PATIssueRequest is PATStore.IssueRequest
    assert PATIssueResult is PATStore.IssueResult
    assert ReconcileResult.__qualname__.endswith("ReconcileStore.ReconcileResult")
    assert RuntimeAccessList is not None
    assert RoutingHostStore.RuntimeHost.__qualname__.endswith("RoutingHostStore.RuntimeHost")
    assert StreamRouteStore.RuntimeStream.__qualname__.endswith("StreamRouteStore.RuntimeStream")


def test_routing_tables_expose_runtime_and_validation_operations() -> None:
    expected = {"runtime_list", "runtime_read", "validate"}
    assert expected <= {spec.alias for spec in RoutingHostStore.__tigrbl_ops__}
    assert expected <= {spec.alias for spec in StreamRouteStore.__tigrbl_ops__}


async def _routing_validation_contracts() -> None:
    app = await _app()
    resources = TableResources(app)
    await resources.create_resource(
        "proxy_hosts",
        {
            "domain_names": ["validation.example.test"],
            "forward_host": "backend",
            "forward_port": 8080,
            "target_kind": "docker",
        },
    )
    with pytest.raises(Exception, match="CollisionError"):
        await app.core.RoutingHostStore.validate(
            {
                "kind": "dead",
                "domain_names": ["VALIDATION.EXAMPLE.TEST"],
            }
        )
    with pytest.raises(Exception, match="IPv4 or IPv6"):
        await app.core.RoutingHostStore.validate(
            {
                "kind": "proxy",
                "domain_names": ["invalid-target.example.test"],
                "forward_host": "not-an-ip",
                "forward_port": 80,
                "target_kind": "ip",
            }
        )
    with pytest.raises(Exception, match="forced HTTPS requires"):
        await app.core.RoutingHostStore.validate(
            {
                "kind": "dead",
                "domain_names": ["invalid-tls.example.test"],
                "ssl_forced": True,
            }
        )
    with pytest.raises(Exception, match="301, 302, 307, or 308"):
        await app.core.RoutingHostStore.validate(
            {
                "kind": "redirect",
                "domain_names": ["invalid-redirect.example.test"],
                "forward_domain_name": "destination.example.test",
                "forward_http_code": 306,
            }
        )
    await app.core.StreamRouteStore.create(
        {
            "protocol": "tcp",
            "incoming_port": 15432,
            "target_kind": "dns",
            "target": "database",
            "target_port": 5432,
            "enabled": True,
        }
    )
    with pytest.raises(Exception, match="CollisionError"):
        await app.core.StreamRouteStore.validate(
            {
                "protocol": "tcp+udp",
                "incoming_port": 15432,
                "target_kind": "dns",
                "target": "database",
                "target_port": 5432,
            }
        )


def test_routing_validation_is_owned_by_table_operations() -> None:
    asyncio.run(_routing_validation_contracts())


async def _principal_lifecycle() -> None:
    app = await _app()
    registered = await app.core.PrincipalStore.register(
        {
            "email": "admin@example.com",
            "password": "correct horse battery staple",
            "display_name": "Admin",
            "is_admin": True,
        }
    )
    assert registered["email"] == "admin@example.com"
    principal = await app.core.CredentialStore.authenticate(
        {"email": "ADMIN@example.com", "password": "correct horse battery staple"}
    )
    assert principal["principal_id"] == registered["id"]
    changed = await app.core.CredentialStore.change_password(
        {
            "principal_id": registered["id"],
            "old_password": "correct horse battery staple",
            "new_password": "a different strong password",
        }
    )
    assert changed["changed"] is True
    session = await app.core.BrowserSessionStore.issue(
        {"principal": principal, "expires_at": 4_102_444_800}
    )
    verified = await app.core.BrowserSessionStore.verify({"token": session["token"]})
    assert verified["email"] == "admin@example.com"
    assert await app.core.BrowserSessionStore.revoke({"token": session["token"]}) == {
        "revoked": True
    }


def test_principal_password_and_session_ops_are_table_native() -> None:
    asyncio.run(_principal_lifecycle())


async def _authorization_lifecycle() -> None:
    app = await _app()
    resources = TableResources(app)
    user = await resources.create_resource(
        "users",
        {
            "email": "permissions@example.test",
            "password": "a strong initial password",
            "name": "Permissions",
            "roles": ["operator"],
            "permissions": {
                "proxy_hosts": {"read": True, "update": False},
                "certificates": "view",
            },
        },
    )
    assert user["roles"] == ["operator"]
    assert user["permissions"]["proxy_hosts"] == {"read": True, "update": False}
    assert len(await app.core.PrincipalRoleStore.list({})) >= 1
    assert len(await app.core.PrincipalPermissionStore.list({})) >= 3

    authenticated = await resources.authenticate(
        "permissions@example.test", "a strong initial password"
    )
    assert authenticated is not None
    assert authenticated.permissions["certificates"]["view"] is True

    changed = await resources.update_resource(
        "users",
        user["id"],
        {"roles": ["auditor"], "permissions": {"audit": {"read": True}}},
    )
    assert changed is not None
    assert changed["roles"] == ["auditor"]
    assert changed["permissions"] == {"audit": {"read": True}}


def test_roles_and_fine_grained_permissions_are_normalized_and_mutable() -> None:
    asyncio.run(_authorization_lifecycle())


async def _pat_lifecycle() -> None:
    app = await _app()
    principal = await app.core.PrincipalStore.create(
        {
            "email": "operator@example.com",
            "display_name": "Operator",
            "nickname": "operator",
            "is_admin": True,
            "is_disabled": False,
            "is_deleted": False,
            "visibility": "all",
            "metadata_json": {},
        }
    )
    issued = await app.core.PATStore.issue(
        {"principal_id": principal["id"], "name": "automation", "scopes": ["user"]}
    )
    assert issued["token"].startswith(f"pwyrm_{issued['token_prefix']}_")
    verified = await app.core.PATStore.verify({"token": issued["token"]})
    assert verified["email"] == "operator@example.com"

    refreshed = await app.core.PATStore.refresh(
        {"token_prefix": issued["token_prefix"], "expires_at": 4_102_444_800}
    )
    assert refreshed["expires_at"] == 4_102_444_800

    rotated = await app.core.PATStore.rotate({"token_prefix": issued["token_prefix"]})
    assert rotated["replaced_token_prefix"] == issued["token_prefix"]
    assert rotated["token_prefix"] != issued["token_prefix"]

    revoked = await app.core.PATStore.revoke({"token_prefix": rotated["token_prefix"]})
    assert revoked["revoked"] is True


def test_pat_issue_verify_refresh_rotate_and_revoke_use_tigrbl_transactions() -> None:
    asyncio.run(_pat_lifecycle())


async def _generation_lifecycle() -> None:
    app = await _app()
    first = await app.core.GenerationStore.create(
        {
            "generation": "gen-a",
            "files": {"nginx.conf": "events {}"},
            "state": "validated",
            "is_active": False,
            "metadata_json": {},
        }
    )
    assert first["generation"] == "gen-a"
    activated = await app.core.GenerationStore.activate({"generation": "gen-a"})
    assert activated == {"generation": "gen-a", "previous_generation": None}
    cleared = await app.core.GenerationStore.clear_active({})
    assert cleared == {"cleared": True, "previous_generation": "gen-a"}


def test_generation_activation_and_clear_active_are_durable_table_ops() -> None:
    asyncio.run(_generation_lifecycle())


def test_generation_store_exposes_requested_custom_operations() -> None:
    aliases = set(GenerationStore.ops.by_alias)
    assert {
        "activate",
        "clear_active",
        "diff",
        "reconcile",
        "reload",
        "render",
        "stage",
        "validate",
    } <= aliases


async def _lease_and_active_generation_invariants() -> None:
    app = await _app()
    first = await app.core.LeaseStore.acquire(
        {"name": "test-reconcile", "holder": "node-a", "ttl_seconds": 60}
    )
    blocked = await app.core.LeaseStore.acquire(
        {"name": "test-reconcile", "holder": "node-b", "ttl_seconds": 60}
    )
    assert first["acquired"] is True
    assert blocked == {**blocked, "acquired": False, "holder": "node-a"}
    renewed = await app.core.LeaseStore.renew(
        {"name": "test-reconcile", "holder": "node-a", "ttl_seconds": 120}
    )
    assert renewed["renewed"] is True
    assert await app.core.LeaseStore.release({"name": "test-reconcile", "holder": "node-b"}) == {
        "released": False
    }
    assert await app.core.LeaseStore.release({"name": "test-reconcile", "holder": "node-a"}) == {
        "released": True
    }

    for generation in ("gen-one", "gen-two"):
        if not any(
            row["generation"] == generation for row in await app.core.GenerationStore.list({})
        ):
            await app.core.GenerationStore.create(
                {"generation": generation, "files": {}, "state": "staged", "is_active": False}
            )
        await app.core.GenerationStore.activate({"generation": generation})
    active = [row for row in await app.core.GenerationStore.list({}) if row["is_active"]]
    assert [row["generation"] for row in active] == ["gen-two"]


def test_runtime_lease_and_single_active_generation_are_durable_invariants() -> None:
    asyncio.run(_lease_and_active_generation_invariants())


async def _compatibility_projection_lifecycle() -> None:
    app = await _app()
    resources = TableResources(app)
    audit_count = len(await resources.list_audit())
    admin = await resources.bootstrap_admin("compat-admin@example.com", "a strong admin password")
    assert admin["email"] == "compat-admin@example.com"
    access = await resources.create_resource(
        "access_lists",
        {
            "name": "private",
            "clients": [{"address": "10.0.0.0/8", "directive": "allow"}],
            "identity_ids": [admin["id"]],
        },
    )
    certificate = await resources.create_resource(
        "certificates",
        {
            "nice_name": "example",
            "provider": "letsencrypt",
            "domain_names": ["one.example.test", "two.example.test"],
        },
    )

    host = await resources.create_resource(
        "proxy_hosts",
        {
            "domain_names": ["one.example.test", "two.example.test"],
            "forward_scheme": "http",
            "forward_host": "upstream",
            "forward_port": 8080,
            "target_kind": "docker",
            "access_list_ids": [access["id"]],
            "certificate_id": certificate["id"],
            "enabled": 1,
        },
    )
    assert host["kind"] == "proxy"
    sources = await app.core.RoutingSourceStore.list({})
    assert any(
        row["routing_host_id"] == host["id"] and row["domain_name"] == "one.example.test"
        for row in sources
    )
    upstreams = await app.core.RoutingUpstreamStore.list({})
    assert any(
        row["routing_host_id"] == host["id"] and row["target"] == "upstream" for row in upstreams
    )
    assert (await app.core.AccessRuleStore.list({}))[0]["address"] == "10.0.0.0/8"
    assert (await app.core.AccessPrincipalStore.list({}))[0]["principal_id"] == admin["id"]
    domains = await app.core.CertificateDomainStore.list({})
    assert any(row["domain_name"] == "one.example.test" for row in domains)

    changed = await resources.update_resource("proxy_hosts", host["id"], {"forward_port": 9090})
    assert changed is not None and changed["forward_port"] == 9090
    upstreams = await app.core.RoutingUpstreamStore.list({})
    assert any(row["routing_host_id"] == host["id"] and row["port"] == 9090 for row in upstreams)
    assert await resources.delete_resource("proxy_hosts", host["id"])
    new_events = (await resources.list_audit())[audit_count:]
    root_events = {(event["object_type"], event["action"]) for event in new_events}
    assert {
        ("principals", "register"),
        ("access_lists", "created"),
        ("certificates", "created"),
        ("proxy_hosts", "created"),
        ("proxy_hosts", "updated"),
        ("proxy_hosts", "deleted"),
    } <= root_events


def test_npm_projection_is_an_api_adapter_over_table_owned_operations() -> None:
    asyncio.run(_compatibility_projection_lifecycle())


async def _mfa_lifecycle() -> None:
    app = await _app()
    principal = await app.core.PrincipalStore.create(
        {
            "email": "mfa@example.test",
            "display_name": "MFA",
            "nickname": "mfa",
            "is_admin": False,
            "is_disabled": False,
            "is_deleted": False,
            "visibility": "user",
            "metadata_json": {},
        }
    )
    enrollment = await app.core.MFAEnrollmentStore.begin({"principal_id": principal["id"]})
    assert len(enrollment["backup_codes"]) == 8
    code = totp_code(enrollment["secret"])
    assert await app.core.MFAEnrollmentStore.confirm(
        {"principal_id": principal["id"], "code": code}
    ) == {"confirmed": True}
    assert await app.core.MFAEnrollmentStore.enabled({"principal_id": principal["id"]}) == {
        "enabled": True
    }
    assert await app.core.MFAEnrollmentStore.verify(
        {"principal_id": principal["id"], "code": enrollment["backup_codes"][0]}
    ) == {"verified": True}


def test_mfa_enrollment_and_recovery_are_table_native() -> None:
    asyncio.run(_mfa_lifecycle())
