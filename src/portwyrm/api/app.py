"""Terse Tigrbl composition root for the Portwyrm control plane."""

from __future__ import annotations

import contextlib
import os
import tempfile
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from tigrbl import TigrblApp

from portwyrm.api.compat import create_compat_app
from portwyrm.api.compat.resources import TableResources
from portwyrm.api.native import create_native_router
from portwyrm.certificates import CertbotIssuer, CertificateMaterialStore, TableCertificateManager
from portwyrm.config import PortwyrmSettings, engine_from_settings
from portwyrm.runtime import TableRuntimeController
from portwyrm.runtime.telemetry import NginxStatusClient
from portwyrm.tables import (
    PORTWYRM_TABLES,
    GenerationStore,
    MFAEnrollmentStore,
)
from portwyrm.uix import mount_uix


def create_app(*, settings: PortwyrmSettings | None = None, engine: Any | None = None) -> TigrblApp:
    """Compose tables, frozen compatibility routes, native routes, and UIX."""

    settings = settings or PortwyrmSettings.from_environment()
    configured_engine = engine or engine_from_settings(settings)
    resources: TableResources | None = None
    runtime: TableRuntimeController | None = None

    @asynccontextmanager
    async def lifespan(_app: TigrblApp):
        if settings.backend == "sqlite":
            try:
                await _app.core.SchemaMigrationStore.apply({})
            except Exception as exc:
                await _app.core.SchemaMigrationStore.record_failure(
                    {"diagnostic": f"{type(exc).__name__}: {exc}"}
                )
                raise
        email = os.getenv("PORTWYRM_INITIAL_ADMIN_EMAIL") or os.getenv("INITIAL_ADMIN_EMAIL")
        password = os.getenv("PORTWYRM_INITIAL_ADMIN_PASSWORD") or os.getenv(
            "INITIAL_ADMIN_PASSWORD"
        )
        if (
            email
            and password
            and resources is not None
            and not await resources.list_resources("users")
        ):
            await resources.bootstrap_admin(email, password)
        if runtime is not None:
            await runtime.reconcile()
        yield

    default_certificate_root = (
        Path(tempfile.mkdtemp(prefix="portwyrm-certificates-"))
        if settings.backend in {"memory", "in-memory", "in_memory"}
        else (
            settings.sqlite_path.parent / "certificates"
            if settings.backend == "sqlite"
            else settings.data_root / "certificates"
        )
    )
    certificate_root = Path(os.getenv("PORTWYRM_CERTIFICATE_ROOT", str(default_certificate_root)))
    app = create_compat_app(
        engine=configured_engine,
        lifespan=lifespan,
        backend=settings.backend,
        certificate_factory=lambda _app, service: TableCertificateManager(
            service,
            CertificateMaterialStore(certificate_root),
            issuer=CertbotIssuer(
                webroot=os.getenv("PORTWYRM_ACME_WEBROOT", "/data/acme-challenge"),
                server=os.getenv("PORTWYRM_ACME_SERVER") or None,
                staging=os.getenv("PORTWYRM_ACME_STAGING", "0").lower() in {"1", "true", "yes"},
            ),
        ),
        system_status=lambda: status_payload(settings.backend, runtime),
    )
    resources = app.state.control_plane
    app.state.tigrbl_tables = PORTWYRM_TABLES
    app.state.persistence_backend = settings.backend
    app.state.mfa_cipher = _load_mfa_cipher(settings)
    MFAEnrollmentStore.configure_cipher(app.state.mfa_cipher)

    app.include_tables(PORTWYRM_TABLES, mount_router=False)
    if settings.nginx_runtime:
        runtime = TableRuntimeController(
            resources,
            settings.nginx_root,
            validate=settings.nginx_validate,
            reload=settings.nginx_reload,
        )
        resources.after_change = runtime.changed
    GenerationStore.configure_runtime(runtime)
    app.state.runtime = runtime
    app.include_router(create_native_router(resources, settings.backend))
    mount_uix(app)
    app.initialize(tables=PORTWYRM_TABLES)
    return app


def status_payload(backend: str, runtime: TableRuntimeController | None = None) -> dict[str, Any]:
    """Return dependency-neutral status for surfaces that require a sync callback."""

    nginx: dict[str, Any] = {
        "status": "disabled" if runtime is None else "degraded",
        "active_generation": runtime.active_generation if runtime is not None else None,
        "connections": {},
    }
    if runtime is not None:
        try:
            nginx.update(status="ok", connections=NginxStatusClient().collect())
        except (OSError, ValueError) as exc:
            nginx["diagnostic"] = str(exc)
    overall = "ok" if nginx["status"] in {"ok", "disabled"} else "degraded"
    return {
        "status": overall,
        "components": {
            "database": {"status": "ok", "backend": backend},
            "nginx": nginx,
            "certificate_scheduler": {"enabled": False, "status": "idle"},
        },
        "checked_at": datetime.now(UTC).isoformat(),
    }


def _load_mfa_cipher(settings: PortwyrmSettings) -> Fernet:
    configured = os.getenv("PORTWYRM_MFA_ENCRYPTION_KEY")
    if configured:
        return Fernet(configured.encode())
    if settings.backend in {"memory", "in-memory", "in_memory"}:
        return Fernet(Fernet.generate_key())
    default_path = (
        settings.sqlite_path.with_name("mfa.key")
        if settings.backend == "sqlite"
        else settings.data_root / "mfa.key"
    )
    path = Path(os.getenv("PORTWYRM_MFA_KEY_PATH", str(default_path)))
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return Fernet(path.read_bytes().strip())
    key = Fernet.generate_key()
    path.write_bytes(key + b"\n")
    with contextlib.suppress(OSError):
        path.chmod(0o600)
    return Fernet(key)


__all__ = ["create_app", "status_payload"]
