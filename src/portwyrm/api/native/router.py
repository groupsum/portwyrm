"""Native setup, observability, and product endpoints."""

# ruff: noqa: B008 - Tigrbl dependencies are declared in function defaults by design.

from __future__ import annotations

from datetime import UTC, datetime
from http import HTTPStatus
from typing import Any

from tigrbl import Depends, HTTPException, PlainTextResponse

from portwyrm.api.compat.resources import TableResources
from portwyrm.api.compat.transport import CompatibilityTigrblRouter
from portwyrm.api.security import TableSecurityDependencies

PortwyrmNativeRouter = CompatibilityTigrblRouter


def _quic_payload(payload: dict[str, Any], *, resource_id: int | None = None) -> dict[str, Any]:
    candidate = {key: value for key, value in payload.items() if key != "meta"}
    meta = payload.get("meta")
    if isinstance(meta, dict):
        candidate["metadata_json"] = {"extensions": {"meta": meta}}
    if resource_id is not None:
        candidate["id"] = resource_id
    return candidate


def create_native_router(resources: TableResources, backend: str) -> PortwyrmNativeRouter:
    router = PortwyrmNativeRouter()
    principal_dependency = TableSecurityDependencies(resources.app.state.token_store).principal

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

    @router.get("/api/v2/capabilities")
    async def capabilities() -> dict[str, Any]:
        return {
            "provider": "portwyrm",
            "capability_version": 1,
            "quic_sni_passthrough": {
                "supported": True,
                "quic_versions": ["v1", "v2"],
                "hostname_routing": True,
                "tls_termination": False,
                "connection_affinity": "client-address",
            },
        }

    @router.get("/api/v2/quic-passthrough-hosts")
    async def list_quic_routes(
        principal: Any = Depends(principal_dependency),
    ) -> list[dict[str, Any]]:
        return await resources.app.core.QuicPassthroughRouteStore.list(
            {}, ctx={"principal": principal}
        )

    @router.post("/api/v2/quic-passthrough-hosts", status_code=HTTPStatus.CREATED)
    async def create_quic_route(
        payload: dict[str, Any], principal: Any = Depends(principal_dependency)
    ) -> dict[str, Any]:
        await resources.app.core.QuicPassthroughRouteStore.validate(payload)
        return await resources.app.core.QuicPassthroughRouteStore.create(
            _quic_payload(payload), ctx={"principal": principal}
        )

    @router.get("/api/v2/quic-passthrough-hosts/{resource_id}")
    async def read_quic_route(
        resource_id: int, principal: Any = Depends(principal_dependency)
    ) -> dict[str, Any]:
        return await resources.app.core.QuicPassthroughRouteStore.read(
            {"id": resource_id}, ctx={"principal": principal}
        )

    @router.put("/api/v2/quic-passthrough-hosts/{resource_id}")
    async def update_quic_route(
        resource_id: int,
        payload: dict[str, Any],
        principal: Any = Depends(principal_dependency),
    ) -> dict[str, Any]:
        candidate = _quic_payload(payload, resource_id=resource_id)
        await resources.app.core.QuicPassthroughRouteStore.validate(candidate)
        return await resources.app.core.QuicPassthroughRouteStore.update(
            candidate, ctx={"principal": principal}
        )

    @router.delete("/api/v2/quic-passthrough-hosts/{resource_id}")
    async def delete_quic_route(
        resource_id: int, principal: Any = Depends(principal_dependency)
    ) -> dict[str, bool]:
        await resources.app.core.QuicPassthroughRouteStore.delete(
            {"id": resource_id}, ctx={"principal": principal}
        )
        return {"deleted": True}

    @router.get("/api/v2/proxy-hosts/status")
    async def proxy_host_statuses(principal: Any = Depends(principal_dependency)) -> dict[str, Any]:
        return await resources.app.core.RoutingHostStore.health_list(
            {}, ctx={"principal": principal}
        )

    @router.get("/api/v2/proxy-hosts/{resource_id}/status")
    async def proxy_host_status(
        resource_id: int, principal: Any = Depends(principal_dependency)
    ) -> dict[str, Any]:
        return await resources.app.core.RoutingHostStore.health_read(
            {"id": resource_id}, ctx={"principal": principal}
        )

    @router.post("/api/v2/proxy-hosts/{resource_id}/probe")
    async def probe_proxy_host(
        resource_id: int, principal: Any = Depends(principal_dependency)
    ) -> dict[str, Any]:
        return await resources.app.core.RoutingHostStore.probe(
            {"id": resource_id}, ctx={"principal": principal}
        )

    return router


__all__ = ["PortwyrmNativeRouter", "create_native_router"]
