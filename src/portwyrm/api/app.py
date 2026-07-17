"""Terse Tigrbl composition root for the Portwyrm control plane."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import secrets
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
from portwyrm.runtime import ProxyHostHealthScheduler, TableRuntimeController, UpstreamProber
from portwyrm.runtime.telemetry import NginxStatusClient
from portwyrm.tables import (
    PORTWYRM_TABLES,
    GenerationStore,
    MFAEnrollmentStore,
    RoutingHostStore,
)
from portwyrm.tables.lifecycle import configure_lifecycle_runtime
from portwyrm.uix import mount_uix

logger = logging.getLogger(__name__)


def create_app(*, settings: PortwyrmSettings | None = None, engine: Any | None = None) -> TigrblApp:
    """Compose tables, frozen compatibility routes, native routes, and UIX."""

    settings = settings or PortwyrmSettings.from_environment()
    configured_engine = engine or engine_from_settings(settings)
    resources: TableResources | None = None
    runtime: TableRuntimeController | None = None
    health_scheduler: ProxyHostHealthScheduler | None = None

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
        if resources is not None and not await resources.list_resources("users"):
            email = os.getenv("PORTWYRM_INITIAL_ADMIN_EMAIL") or os.getenv("INITIAL_ADMIN_EMAIL")
            password = os.getenv("PORTWYRM_INITIAL_ADMIN_PASSWORD") or os.getenv(
                "INITIAL_ADMIN_PASSWORD"
            )
            auto_bootstrap = os.getenv("PORTWYRM_AUTO_BOOTSTRAP_ADMIN", "0").casefold() in {
                "1",
                "true",
                "yes",
                "on",
            }
            if auto_bootstrap and not (email and password):
                email, password = _load_or_create_bootstrap_credentials(settings, email=email)
            if email and password:
                require_change = os.getenv(
                    "PORTWYRM_INITIAL_ADMIN_REQUIRE_PASSWORD_CHANGE", "1"
                ).casefold() in {"1", "true", "yes", "on"}
                await resources.bootstrap_admin(
                    email,
                    password,
                    must_change_password=require_change,
                )
        if runtime is not None:
            await runtime.reconcile()
        if health_scheduler is not None:
            health_scheduler.start()
        try:
            yield
        finally:
            if health_scheduler is not None:
                await health_scheduler.stop()

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
    GenerationStore.configure_runtime(runtime)
    app.state.runtime = runtime
    prober = UpstreamProber(
        dns_timeout=settings.host_probe_dns_timeout_seconds,
        connect_timeout=settings.host_probe_connect_timeout_seconds,
        tls_timeout=settings.host_probe_tls_timeout_seconds,
        http_timeout=settings.host_probe_http_timeout_seconds,
    )
    if settings.host_probes:
        health_scheduler = ProxyHostHealthScheduler(
            app,
            interval_seconds=settings.host_probe_interval_seconds,
            concurrency=settings.host_probe_concurrency,
        )
    app.state.health_scheduler = health_scheduler
    RoutingHostStore.configure_health_runtime(
        prober,
        freshness_seconds=settings.host_probe_freshness_seconds,
        runtime_provider=lambda: app.state.runtime,
        app_provider=lambda: app,
    )
    configure_lifecycle_runtime(lambda: app.state.runtime)
    app.include_router(create_native_router(resources, settings.backend))
    mount_uix(app)
    app.initialize(tables=PORTWYRM_TABLES)
    return app


def _load_or_create_bootstrap_credentials(
    settings: PortwyrmSettings,
    *,
    email: str | None = None,
) -> tuple[str, str]:
    """Create deployment-specific first-login credentials and reveal them once."""

    path = Path(
        os.getenv(
            "PORTWYRM_BOOTSTRAP_CREDENTIAL_FILE",
            str(settings.data_root / "bootstrap-admin.json"),
        )
    )
    if path.exists():
        payload = json.loads(path.read_text(encoding="utf-8"))
        return str(payload["email"]), str(payload["password"])
    resolved_email = str(email or "admin@example.com").strip().casefold()
    password = secrets.token_urlsafe(24)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"email": resolved_email, "password": password}) + "\n",
        encoding="utf-8",
    )
    with contextlib.suppress(OSError):
        path.chmod(0o600)
    logger.warning(
        "Portwyrm one-time administrator credentials: email=%s password=%s; "
        "a password change is required at first login",
        resolved_email,
        password,
    )
    return resolved_email, password


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
