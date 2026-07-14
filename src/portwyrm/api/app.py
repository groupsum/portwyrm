"""Composition root for the all-in-one Portwyrm control plane."""

from __future__ import annotations

import asyncio
import contextlib
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse

from portwyrm.api.compat import create_compat_app
from portwyrm.api.dependencies import create_default_repository
from portwyrm.certificates import CertbotIssuer, CertificateManager, CertificateMaterialStore
from portwyrm.identity import TokenStore
from portwyrm.mfa import MFAStore
from portwyrm.operations import HealthService, UpgradeManager, default_upgrades
from portwyrm.persistence import Repository
from portwyrm.persistent import PersistentControlPlane
from portwyrm.runtime.coordinator import RuntimeCoordinator
from portwyrm.service import ControlPlaneError
from portwyrm.ui import mount_ui


def create_app(repository: Repository | None = None) -> FastAPI:
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
    async def lifespan(_app: FastAPI):
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

    app = create_compat_app(
        control_plane,
        tokens=TokenStore(repository=repository),
        certificates=certificate_manager,
        lifespan=lifespan,
        repository=repository,
        mfa=mfa_store,
    )
    app.state.repository = repository
    app.state.runtime = runtime

    @app.exception_handler(ControlPlaneError)
    async def control_plane_error(_request: Request, exc: ControlPlaneError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": str(exc)})

    @app.get("/api/setup")
    async def setup_status() -> dict[str, bool]:
        return {"setup": bool(control_plane.list("users"))}

    @app.post("/api/setup", status_code=status.HTTP_201_CREATED)
    async def initial_setup(payload: dict[str, Any]) -> dict[str, Any]:
        if control_plane.list("users"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="initial setup is already complete",
            )
        email_value = payload.get("email")
        password_value = payload.get("password")
        if not isinstance(email_value, str) or not isinstance(password_value, str):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="email and password are required",
            )
        return control_plane.bootstrap_admin(email_value, password_value)

    health = HealthService(repository)

    @app.get("/health/live", include_in_schema=False)
    async def live() -> dict[str, Any]:
        return health.live()

    @app.get("/health/ready", include_in_schema=False)
    async def ready() -> JSONResponse:
        payload = health.ready()
        return JSONResponse(payload, status_code=200 if payload["status"] == "ok" else 503)

    @app.get("/version", include_in_schema=False)
    async def version() -> dict[str, str]:
        from portwyrm import __version__

        return {"version": __version__}

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> PlainTextResponse:
        lines = ["# TYPE portwyrm_resources gauge"]
        for collection in sorted(
            ("proxy-hosts", "redirection-hosts", "dead-hosts", "streams", "certificates")
        ):
            count = len(control_plane.list(collection))
            lines.append(f'portwyrm_resources{{collection="{collection}"}} {count}')
        readiness = health.ready()
        lines.extend(
            [
                "# TYPE portwyrm_ready gauge",
                f"portwyrm_ready {1 if readiness['status'] == 'ok' else 0}",
            ]
        )
        return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")

    mount_ui(app)
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
