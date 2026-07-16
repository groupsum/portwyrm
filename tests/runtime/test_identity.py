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
