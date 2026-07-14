"""HTTP API factories and the packaged server application."""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, HTTPException, status

from portwyrm.api.compat import CompatibilityService, create_compat_app
from portwyrm.service import ControlPlane
from portwyrm.ui import mount_ui

__all__ = ["CompatibilityService", "create_app", "create_compat_app"]


def create_app() -> FastAPI:
    """Construct the default all-in-one control plane used by the CLI factory."""

    email = os.getenv("PORTWYRM_INITIAL_ADMIN_EMAIL") or os.getenv("INITIAL_ADMIN_EMAIL")
    password = os.getenv("PORTWYRM_INITIAL_ADMIN_PASSWORD") or os.getenv("INITIAL_ADMIN_PASSWORD")
    control_plane = ControlPlane()
    if email and password:
        control_plane.bootstrap_admin(email, password)

    app = create_compat_app(control_plane)

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

    mount_ui(app)
    return app
