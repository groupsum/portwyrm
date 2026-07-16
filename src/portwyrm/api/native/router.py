"""Native setup, observability, and product endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from http import HTTPStatus
from typing import Any

from tigrbl import HTTPException, PlainTextResponse

from portwyrm.api.compat.resources import TableResources
from portwyrm.api.compat.transport import CompatibilityTigrblRouter

PortwyrmNativeRouter = CompatibilityTigrblRouter


def create_native_router(resources: TableResources, backend: str) -> PortwyrmNativeRouter:
    router = PortwyrmNativeRouter()

    @router.get("/api/setup")
    async def setup_status() -> dict[str, bool]:
        return {"setup": bool(await resources.list_resources("users"))}

    @router.post("/api/setup", status_code=HTTPStatus.CREATED)
    async def initial_setup(payload: dict[str, Any]) -> dict[str, Any]:
        if await resources.list_resources("users"):
            raise HTTPException(
                status_code=HTTPStatus.FORBIDDEN,
                detail="initial setup is already complete",
            )
        email, password = payload.get("email"), payload.get("password")
        if not isinstance(email, str) or not isinstance(password, str):
            raise HTTPException(
                status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
                detail="email and password are required",
            )
        return await resources.bootstrap_admin(email, password)

    @router.get("/health/live", include_in_schema=False)
    async def live() -> dict[str, Any]:
        return {"status": "ok", "checked_at": datetime.now(UTC).isoformat()}

    @router.get("/health/ready", include_in_schema=False)
    async def ready() -> dict[str, Any]:
        await resources.list_resources("settings")
        return {
            "status": "ok",
            "components": {"database": {"status": "ok", "backend": backend}},
            "checked_at": datetime.now(UTC).isoformat(),
        }

    @router.get("/version", include_in_schema=False)
    async def version() -> dict[str, str]:
        from portwyrm import __version__

        return {"version": __version__}

    @router.get("/metrics", include_in_schema=False)
    async def metrics() -> PlainTextResponse:
        lines = ["# TYPE portwyrm_resources gauge"]
        for collection in (
            "proxy_hosts",
            "redirection_hosts",
            "dead_hosts",
            "streams",
            "certificates",
        ):
            count = len(await resources.list_resources(collection))
            lines.append(f'portwyrm_resources{{collection="{collection}"}} {count}')
        return PlainTextResponse(
            "\n".join(lines) + "\n",
            headers={"content-type": "text/plain; version=0.0.4; charset=utf-8"},
        )

    return router


__all__ = ["PortwyrmNativeRouter", "create_native_router"]
