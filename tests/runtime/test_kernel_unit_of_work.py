import asyncio

import pytest
from sqlalchemy import select

from portwyrm.api.app import create_app
from portwyrm.persistence import MemoryRepository
from portwyrm.tables import KernelUnitOfWork
from portwyrm.tables.models import Setting


def test_kernel_unit_of_work_commits_once() -> None:
    app = create_app(MemoryRepository())
    uow = KernelUnitOfWork(app)

    async def create(db):
        db.add(Setting(key="kernel-test", value={"ok": True}))
        return "created"

    assert asyncio.run(uow.run(create)) == "created"

    async def read(db):
        result = db.execute(select(Setting).where(Setting.key == "kernel-test"))
        return result.scalar_one().value

    assert asyncio.run(uow.run(read)) == {"ok": True}


def test_kernel_unit_of_work_rolls_back_on_failure() -> None:
    app = create_app(MemoryRepository())
    uow = KernelUnitOfWork(app)

    async def fail(db):
        db.add(Setting(key="rolled-back", value={"bad": True}))
        raise RuntimeError("stop")

    with pytest.raises(Exception, match="stop"):
        asyncio.run(uow.run(fail))

    async def absent(db):
        result = db.execute(select(Setting).where(Setting.key == "rolled-back"))
        return result.scalar_one_or_none()

    assert asyncio.run(uow.run(absent)) is None
