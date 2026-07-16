"""Tigrbl-native identity workflow assurance coverage."""

import asyncio

from portwyrm.api import create_app
from portwyrm.config import PortwyrmSettings


def test_identity_authentication_and_personal_token_lifecycle_use_table_ops() -> None:
    async def run() -> None:
        app = create_app(settings=PortwyrmSettings(backend="memory"))
        registered = await app.core.PrincipalStore.register(
            {
                "email": "identity@example.test",
                "password": "correct horse battery staple",
                "display_name": "Identity",
                "is_admin": True,
            }
        )
        authenticated = await app.core.CredentialStore.authenticate(
            {"email": "IDENTITY@example.test", "password": "correct horse battery staple"}
        )
        assert authenticated["principal_id"] == registered["id"]

        issued = await app.core.PATStore.issue(
            {"principal_id": registered["id"], "name": "automation", "scopes": ["user"]}
        )
        verified = await app.core.PATStore.verify({"token": issued["token"]})
        assert verified["email"] == "identity@example.test"
        revoked = await app.core.PATStore.revoke({"token_prefix": issued["token_prefix"]})
        assert revoked["revoked"] is True
        assert revoked["token_prefix"] == issued["token_prefix"]

    asyncio.run(run())


def test_password_change_requirement_is_owned_by_credential_operation_hooks() -> None:
    async def run() -> None:
        app = create_app(settings=PortwyrmSettings(backend="memory"))
        registered = await app.core.PrincipalStore.register(
            {
                "email": "bootstrap@example.test",
                "password": "temporary-password",
                "display_name": "Bootstrap Administrator",
                "is_admin": True,
                "must_change_password": True,
            }
        )
        authenticated = await app.core.CredentialStore.authenticate(
            {"email": "bootstrap@example.test", "password": "temporary-password"}
        )
        assert authenticated["must_change_password"] is True

        await app.core.CredentialStore.change_password(
            {
                "principal_id": registered["id"],
                "old_password": "temporary-password",
                "new_password": "private-administrator-password",
            }
        )
        changed = await app.core.CredentialStore.authenticate(
            {
                "email": "bootstrap@example.test",
                "password": "private-administrator-password",
            }
        )
        assert changed["must_change_password"] is False

        await app.core.CredentialStore.set_password(
            {"principal_id": registered["id"], "new_password": "reset-password"}
        )
        reset = await app.core.CredentialStore.authenticate(
            {"email": "bootstrap@example.test", "password": "reset-password"}
        )
        assert reset["must_change_password"] is True

    asyncio.run(run())
