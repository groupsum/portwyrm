from __future__ import annotations

import asyncio
from pathlib import Path

from cryptography.fernet import Fernet

from portwyrm.api.app import create_app
from portwyrm.application import KernelMFAStore
from portwyrm.persistence import SQLiteRepository
from portwyrm.tables import KernelUnitOfWork
from portwyrm.tables.models import MFAEnrollment, PersonalAccessToken


def test_control_plane_write_preserves_kernel_identity_state(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("PORTWYRM_DATA_ROOT", str(tmp_path / "data"))
    app = create_app(SQLiteRepository(tmp_path / "state.sqlite"))
    service = app.state.control_plane
    user = service.bootstrap_admin("admin@example.test", "correct-password")
    principal = service.authenticate("admin@example.test", "correct-password")
    assert principal is not None

    token, _plaintext = asyncio.run(
        app.state.token_store.create_pat(name="automation", principal=principal)
    )
    asyncio.run(KernelMFAStore(app, Fernet.generate_key()).begin(user["id"]))

    service.create(
        "proxy-hosts",
        {
            "domain_names": ["app.example.test"],
            "forward_scheme": "http",
            "forward_host": "upstream",
            "forward_port": 8080,
        },
    )

    def counts(db):
        return (
            db.query(PersonalAccessToken).count(),
            db.query(MFAEnrollment).count(),
        )

    assert KernelUnitOfWork(app).run_sync(counts) == (1, 1)
    assert asyncio.run(app.state.token_store.get_pat(token.id)) is not None
