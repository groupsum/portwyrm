"""HTTP API factories and the packaged server application."""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from portwyrm.api.compat import CompatibilityService, create_compat_app
from portwyrm.operations.health import HealthService
from portwyrm.operations.runtime import repository_config_from_environment
from portwyrm.persistence import MemoryRepository, Repository, create_repository
from portwyrm.persistent import PersistentControlPlane
from portwyrm.runtime.coordinator import RuntimeCoordinator
from portwyrm.service import ControlPlaneError
from portwyrm.ui import mount_ui

__all__ = ["CompatibilityService", "create_app", "create_compat_app"]


def create_app(repository: Repository | None = None) -> FastAPI:
    """Construct the default all-in-one control plane used by the CLI factory."""

    email = os.getenv("PORTWYRM_INITIAL_ADMIN_EMAIL") or os.getenv("INITIAL_ADMIN_EMAIL")
    password = os.getenv("PORTWYRM_INITIAL_ADMIN_PASSWORD") or os.getenv("INITIAL_ADMIN_PASSWORD")
    if repository is None:
        repository = (
            create_repository(repository_config_from_environment())
            if os.getenv("PORTWYRM_DB_BACKEND")
            else MemoryRepository()
        )
    control_plane = PersistentControlPlane(repository)
    runtime: RuntimeCoordinator | None = None
    if os.getenv("PORTWYRM_NGINX_RUNTIME", "0").lower() in {"1", "true", "yes"}:
        root = os.getenv("PORTWYRM_NGINX_ROOT", "/data/nginx")
        runtime = RuntimeCoordinator(control_plane, root)
        control_plane.on_change = runtime.changed
    if email and password and not control_plane.list("users"):
        control_plane.bootstrap_admin(email, password)

    app = create_compat_app(control_plane)
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
