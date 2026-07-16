import asyncio

import pytest

from portwyrm.api.app import create_app
from portwyrm.identity import KernelTokenStore, Principal
from portwyrm.persistence import MemoryRepository
from portwyrm.tables import KernelUnitOfWork
from portwyrm.tables.models import Principal as PrincipalRow


def _principal() -> Principal:
    return Principal(user_id=1, identity="owner@example.com", is_admin=True)


def test_kernel_token_store_session_and_pat_lifecycles() -> None:
    app = create_app(MemoryRepository())
    store = KernelTokenStore(app)

    async def exercise() -> None:
        async def seed(db):
            db.add(
                PrincipalRow(
                    id=1,
                    email="owner@example.com",
                    display_name="Owner",
                    is_admin=True,
                )
            )

        await KernelUnitOfWork(app).run(seed)
        session, _ = await store.issue_session(_principal(), now=100)
        assert (await store.verify(session, now=101)).identity == "owner@example.com"
        assert await store.revoke_session(session)
        with pytest.raises(ValueError, match="invalid token"):
            await store.verify(session, now=102)

        pat, plaintext = await store.create_pat(name="automation", principal=_principal(), now=200)
        assert (await store.verify(plaintext, now=201)).is_admin
        assert [item.id for item in await store.list_pats(_principal())] == [pat.id]
        replacement, replacement_plaintext = await store.rotate_pat(pat.id, now=202)
        assert replacement.id != pat.id
        with pytest.raises(ValueError, match="invalid token"):
            await store.verify(plaintext, now=203)
        assert (await store.verify(replacement_plaintext, now=203)).is_admin

    asyncio.run(exercise())
