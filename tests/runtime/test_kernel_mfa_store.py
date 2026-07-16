import asyncio

import pyotp
from cryptography.fernet import Fernet

from portwyrm.api.app import create_app
from portwyrm.application import KernelMFAStore
from portwyrm.persistence import MemoryRepository
from portwyrm.tables import KernelUnitOfWork
from portwyrm.tables.models import Principal


def test_kernel_mfa_enrollment_recovery_and_disable() -> None:
    app = create_app(MemoryRepository())
    store = KernelMFAStore(app, Fernet.generate_key())

    async def exercise() -> None:
        async def seed(db):
            db.add(
                Principal(
                    id=1,
                    email="owner@example.com",
                    display_name="Owner",
                    is_admin=True,
                )
            )

        await KernelUnitOfWork(app).run(seed)
        enrollment = await store.begin(1)
        assert not await store.enabled(1)
        assert await store.confirm(1, pyotp.TOTP(enrollment["secret"]).now())
        assert await store.enabled(1)
        backup = enrollment["backup_codes"][0]
        assert await store.verify(1, backup)
        assert not await store.verify(1, backup)
        assert await store.disable(1, pyotp.TOTP(enrollment["secret"]).now())
        assert not await store.enabled(1)

    asyncio.run(exercise())
