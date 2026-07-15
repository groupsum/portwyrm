"""Composition root for the all-in-one Portwyrm control plane."""

from __future__ import annotations

import asyncio
import contextlib
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from tigrbl import TigrblApp

from portwyrm.api.compat import create_compat_app
from portwyrm.api.dependencies import create_default_repository
from portwyrm.api.native import create_native_router
from portwyrm.application import MFAStore, PersistentControlPlane
from portwyrm.certificates import CertbotIssuer, CertificateManager, CertificateMaterialStore
from portwyrm.identity import TokenStore
from portwyrm.operations import HealthService, NginxStatusClient, UpgradeManager, default_upgrades
from portwyrm.persistence import Repository
from portwyrm.runtime.coordinator import RuntimeCoordinator
from portwyrm.tables import PORTWYRM_TABLES
from portwyrm.tables.engine import engine_for_repository
from portwyrm.tables.legacy import LegacyProjector
from portwyrm.uix import mount_uix


def create_app(repository: Repository | None = None) -> TigrblApp:
    """Construct the packaged API, runtime coordinator, and UIX."""

    email = os.getenv("PORTWYRM_INITIAL_ADMIN_EMAIL") or os.getenv("INITIAL_ADMIN_EMAIL")
    password = os.getenv("PORTWYRM_INITIAL_ADMIN_PASSWORD") or os.getenv("INITIAL_ADMIN_PASSWORD")
    repository = repository or create_default_repository()
    UpgradeManager(repository, default_upgrades()).run()
    control_plane = PersistentControlPlane(repository)
    certificate_root = Path(
        os.getenv("PORTWYRM_CERTIFICATE_ROOT", str(Path.cwd() / ".portwyrm" / "certificates"))
    )
    certificate_manager = CertificateManager(
        control_plane,
        CertificateMaterialStore(certificate_root),
        issuer=CertbotIssuer(
            webroot=os.getenv("PORTWYRM_ACME_WEBROOT", "/data/acme-challenge"),
            server=os.getenv("PORTWYRM_ACME_SERVER") or None,
            staging=os.getenv("PORTWYRM_ACME_STAGING", "0").lower() in {"1", "true", "yes"},
        ),
    )
    mfa_store = MFAStore(repository, _load_mfa_key())
    token_store = TokenStore(repository=repository)
    runtime: RuntimeCoordinator | None = None
    if os.getenv("PORTWYRM_NGINX_RUNTIME", "0").lower() in {"1", "true", "yes"}:
        root = os.getenv("PORTWYRM_NGINX_ROOT", "/data/nginx")
        runtime = RuntimeCoordinator(control_plane, root)
        control_plane.on_change = runtime.changed
    if email and password and not control_plane.list("users"):
        control_plane.bootstrap_admin(email, password)

    async def renewal_loop() -> None:
        interval = max(300, int(os.getenv("PORTWYRM_CERTIFICATE_RENEW_INTERVAL", "43200")))
        while True:
            await asyncio.sleep(interval)
            await asyncio.to_thread(certificate_manager.renew_due)

    @asynccontextmanager
    async def lifespan(_app: TigrblApp):
        renewal_task: asyncio.Task[None] | None = None
        if os.getenv("PORTWYRM_CERTIFICATE_AUTO_RENEW", "1").lower() in {"1", "true", "yes"}:
            renewal_task = asyncio.create_task(renewal_loop())
        try:
            yield
        finally:
            if renewal_task is not None:
                renewal_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await renewal_task

    health = HealthService(
        repository,
        {
            "nginx": lambda: {
                "status": "ok"
                if runtime is None or (runtime.current / "nginx.conf").is_file()
                else "failed",
                "configured": runtime is not None,
            },
            "certificate_scheduler": lambda: {
                "status": "ok",
                "enabled": os.getenv("PORTWYRM_CERTIFICATE_AUTO_RENEW", "1").lower()
                in {"1", "true", "yes"},
            },
        },
    )
    nginx_status_client = NginxStatusClient(
        os.getenv("PORTWYRM_NGINX_STATUS_URL", "http://127.0.0.1:8081/nginx-status")
    )

    def system_status() -> dict[str, Any]:
        payload = health.ready()
        nginx = dict(payload["components"].get("nginx", {}))
        nginx["active_generation"] = runtime.active_generation if runtime is not None else None
        try:
            nginx["connections"] = nginx_status_client.collect() if runtime is not None else None
            nginx["telemetry_status"] = "ok" if runtime is not None else "unavailable"
        except (OSError, TimeoutError, ValueError):
            nginx["connections"] = None
            nginx["telemetry_status"] = "unavailable"
        payload["components"]["nginx"] = nginx
        return payload

    app = create_compat_app(
        control_plane,
        tokens=token_store,
        certificates=certificate_manager,
        lifespan=lifespan,
        repository=repository,
        mfa=mfa_store,
        system_status=system_status,
        engine=engine_for_repository(repository),
    )
    app.state.repository = repository
    app.state.runtime = runtime
    app.state.tigrbl_tables = PORTWYRM_TABLES

    for table in PORTWYRM_TABLES:
        app.include_table(table, mount_router=False)
    app.include_router(create_native_router(control_plane, health))
    mount_uix(app)

    # Tigrbl freezes the composed ASGI router during initialization. Register
    # every compatibility, native, and UI route before this boundary so the
    # Uvicorn application exposes the complete packaged surface.
    app.initialize(tables=PORTWYRM_TABLES)
    projector = LegacyProjector(app, repository)
    projector.rebuild()
    app.state.legacy_projector = projector

    def after_legacy_change(collection: str) -> Any:
        projector.rebuild()
        return runtime.changed(collection) if runtime is not None else None

    control_plane.on_change = after_legacy_change
    token_store.on_change = projector.rebuild
    mfa_store.on_change = projector.rebuild

    return app


def _load_mfa_key() -> bytes:
    configured = os.getenv("PORTWYRM_MFA_ENCRYPTION_KEY")
    if configured:
        return configured.encode()
    data_root = Path(os.getenv("PORTWYRM_DATA_ROOT", str(Path.cwd() / ".portwyrm")))
    path = Path(os.getenv("PORTWYRM_MFA_KEY_PATH", str(data_root / "mfa.key")))
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_bytes().strip()
    key = Fernet.generate_key()
    path.write_bytes(key + b"\n")
    with contextlib.suppress(OSError):
        path.chmod(0o600)
    return key
