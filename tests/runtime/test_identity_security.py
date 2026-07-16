from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

from tigrbl import HTTPException

from portwyrm.api.compat.resources import TableResources
from portwyrm.api.security import TableIdentity
from portwyrm.tables import PORTWYRM_TABLES, PATRecord, SecurityPrincipal


class _SessionOps:
    async def verify(self, payload: dict[str, Any]) -> dict[str, Any]:
        assert payload["token"].startswith("pws_")
        return {"principal_id": 7, "scopes": ["user"]}


class _PrincipalOps:
    def __init__(self) -> None:
        self.permissions: dict[str, Any] = {"proxy_hosts": {"read": True}}

    async def resolve(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "user_id": payload["principal_id"],
            "identity": "security@example.test",
            "display_name": "Security",
            "is_admin": False,
            "permissions": self.permissions,
            "visibility": "user",
            "scopes": payload["scopes"],
            "owner": None,
        }


def test_identity_models_are_canonical_table_schemas() -> None:
    assert SecurityPrincipal.__qualname__.endswith("PrincipalStore.SecurityPrincipal")
    assert PATRecord.__qualname__.endswith("PATStore.TokenRecord")
    assert {table.__name__ for table in PORTWYRM_TABLES} >= {"PrincipalStore", "PATStore"}


async def _security_lifecycle() -> None:
    principal_ops = _PrincipalOps()
    app = SimpleNamespace(
        core=SimpleNamespace(BrowserSessionStore=_SessionOps(), PrincipalStore=principal_ops)
    )
    identity = TableIdentity(app)

    first = await identity.verify("pws_session_token")
    assert first.may("proxy-hosts", action="read")

    principal_ops.permissions = {"audit": {"read": True}}
    refreshed = await identity.verify("pws_session_token")
    assert not refreshed.may("proxy-hosts", action="read")
    assert refreshed.may("audit", action="read")

    record = TableIdentity._pat(
        {
            "token_prefix": "prefix",
            "name": "automation",
            "created_at": 1,
            "expires_at": None,
        },
        refreshed,
    )
    assert isinstance(record, PATRecord)
    assert "token" not in record.public()
    assert "token_hash" not in record.model_dump()


def test_identity_verification_resolves_current_table_authorization() -> None:
    asyncio.run(_security_lifecycle())


def test_authentication_redacts_wrapped_credential_failures() -> None:
    class _CredentialOps:
        async def authenticate(self, _payload: dict[str, Any]) -> dict[str, Any]:
            raise HTTPException(status_code=400, detail="invalid credentials")

    resources = TableResources(
        SimpleNamespace(core=SimpleNamespace(CredentialStore=_CredentialOps()))
    )
    assert asyncio.run(resources.authenticate("admin@example.test", "wrong")) is None
