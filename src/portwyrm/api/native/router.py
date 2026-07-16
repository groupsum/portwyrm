"""Native operational endpoints shared by every deployment profile."""

from __future__ import annotations

import asyncio
from http import HTTPStatus
from typing import Any

from tigrbl import HTTPException, JSONResponse, PlainTextResponse

from portwyrm.api.compat.transport import CompatibilityTigrblRouter
from portwyrm.application import ControlPlane
from portwyrm.operations import HealthService


def create_native_router(
    control_plane: ControlPlane,
    health: HealthService,
) -> CompatibilityTigrblRouter:
    """Build setup, observability, and product metadata routes."""
    router = CompatibilityTigrblRouter(prefix="")

    @router.get("/api/setup")
    async def setup_status() -> dict[str, bool]:
        return {"setup": bool(control_plane.list("users"))}

    @router.post("/api/setup", status_code=HTTPStatus.CREATED)
    async def initial_setup(payload: dict[str, Any]) -> dict[str, Any]:
        if control_plane.list("users"):
            raise HTTPException(
                status_code=HTTPStatus.FORBIDDEN,
                detail="initial setup is already complete",
            )
        email = payload.get("email")
        password = payload.get("password")
        if not isinstance(email, str) or not isinstance(password, str):
            raise HTTPException(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                detail="email and password are required",
            )
        return await asyncio.to_thread(control_plane.bootstrap_admin, email, password)

    @router.get("/health/live", include_in_schema=False)
    async def live() -> dict[str, Any]:
        return health.live()

    @router.get("/health/ready", include_in_schema=False)
    async def ready() -> JSONResponse:
        payload = health.ready()
        return JSONResponse(payload, status_code=200 if payload["status"] == "ok" else 503)

    @router.get("/version", include_in_schema=False)
    async def version() -> dict[str, str]:
        from portwyrm import __version__

        return {"version": __version__}

    @router.get("/metrics", include_in_schema=False)
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
        return PlainTextResponse(
            "\n".join(lines) + "\n",
            headers={"content-type": "text/plain; version=0.0.4; charset=utf-8"},
        )

    return router
