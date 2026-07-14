"""Composition root for the all-in-one Portwyrm control plane."""

from __future__ import annotations

import asyncio
import contextlib
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from portwyrm.api.compat import create_compat_app
from portwyrm.api.dependencies import create_default_repository
from portwyrm.certificates import CertbotIssuer, CertificateManager, CertificateMaterialStore
from portwyrm.identity import TokenStore
from portwyrm.operations.health import HealthService
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

    mount_ui(app)
    return app
