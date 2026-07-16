"""Async table-backed desired-state reconciliation."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from uuid import uuid4

from portwyrm.api.compat.resources import TableResources
from portwyrm.tables.access import RuntimeAccessList
from portwyrm.tables.routing import RoutingHostStore, StreamRouteStore

from .nginx import NginxRenderer, RenderedConfiguration
from .publisher import build_reconciler
from .reconcile import ReconcileResult

ROUTING_COLLECTIONS = {
    "proxy-hosts",
    "redirection-hosts",
    "dead-hosts",
    "streams",
    "access-lists",
    "certificates",
    "settings",
}


class TableRuntimeController:
    """Render table projections and persist each immutable runtime generation."""

    def __init__(
        self,
        resources: TableResources,
        root: str | Path,
        *,
        validate: bool = True,
        reload: bool = True,
    ) -> None:
        self.resources = resources
        self.root = Path(root)
        self.current = self.root / "current"
        self._lock = asyncio.Lock()
        self._holder = uuid4().hex
        self.reconciler = build_reconciler(self.root, validate=validate, reload=reload)

    @property
    def active_generation(self) -> str | None:
        return self.reconciler.store.active_id()

    async def changed(self, collection: str) -> ReconcileResult | None:
        if collection.replace("_", "-") not in ROUTING_COLLECTIONS:
            return None
        return await self.reconcile()

    async def reconcile(self) -> ReconcileResult:
        rendered = await self.render()
        return await self.reconcile_files(dict(rendered.files))

    async def render(self) -> RenderedConfiguration:
        """Compile the canonical table state without filesystem or Nginx side effects."""
        hosts = await self.resources.app.core.RoutingHostStore.runtime_list({})
        streams = await self.resources.app.core.StreamRouteStore.runtime_list({})
        access_lists = await self.resources.app.core.AccessListStore.runtime_list({})
        runtime_hosts = [RoutingHostStore.RuntimeHost.model_validate(row) for row in hosts["items"]]
        return NginxRenderer().render(
            proxy_hosts=[host for host in runtime_hosts if host.kind == "proxy"],
            redirection_hosts=[host for host in runtime_hosts if host.kind == "redirect"],
            dead_hosts=[host for host in runtime_hosts if host.kind == "dead"],
            streams=[
                StreamRouteStore.RuntimeStream.model_validate(row) for row in streams["items"]
            ],
            access_lists=[RuntimeAccessList.model_validate(row) for row in access_lists["items"]],
        )

    async def stage(self, files: dict[str, str]) -> dict[str, Any]:
        generation = self.reconciler.store.generation_id(files)
        _path, created = await asyncio.to_thread(self.reconciler.store.stage, generation, files)
        return {"generation": generation, "created": created}

    async def reconcile_files(self, files: dict[str, str]) -> ReconcileResult:
        async with self._lock:
            lease = await self.resources.app.core.LeaseStore.acquire(
                {"name": "nginx-reconcile", "holder": self._holder, "ttl_seconds": 120}
            )
            if not lease["acquired"]:
                raise RuntimeError(f"reconciliation lease is held by {lease['holder']}")
            try:
                try:
                    result = await asyncio.to_thread(self.reconciler.reconcile, files)
                except BaseException as exc:
                    generation = self.reconciler.store.generation_id(files)
                    await self._persist(
                        generation,
                        files,
                        ReconcileResult(
                            generation=generation,
                            previous_generation=self.active_generation,
                            changed=True,
                            applied=False,
                            diagnostic=str(exc),
                        ),
                    )
                    raise
                await self._persist(result.generation, files, result)
                return result
            finally:
                await self.resources.app.core.LeaseStore.release(
                    {"name": "nginx-reconcile", "holder": self._holder}
                )

    async def validate(self, payload: dict[str, Any]) -> dict[str, Any]:
        generation = str(payload.get("generation") or "")
        path = self.reconciler.store.generations / generation
        if not generation or not path.is_dir():
            raise ValueError("staged generation does not exist")
        await asyncio.to_thread(self.reconciler.validator, path)
        return {"generation": generation, "valid": True}

    async def reload(self, payload: dict[str, Any]) -> dict[str, Any]:
        generation = str(payload.get("generation") or self.active_generation or "")
        path = self.reconciler.store.generations / generation
        if not generation or not path.is_dir():
            raise ValueError("generation does not exist")
        await asyncio.to_thread(self.reconciler.reloader, path)
        return {"generation": generation, "reloaded": True}

    async def _persist(
        self, generation: str, files: dict[str, str], result: ReconcileResult
    ) -> None:
        values = {
            "generation": generation,
            "previous_generation": result.previous_generation,
            "files": files,
            "state": "active" if result.applied else "failed",
            "is_active": False,
            "diagnostic": result.diagnostic,
        }
        generation_row = await self.resources.app.core.GenerationStore.record(values)
        if result.applied:
            await self.resources.app.core.GenerationStore.activate({"generation": generation})
        await self.resources.app.core.ReconcileStore.create(
            {
                "generation_id": generation_row["id"],
                "previous_generation": result.previous_generation,
                "changed": result.changed,
                "applied": result.applied,
                "status": "applied" if result.applied else "failed",
                "diagnostic": result.diagnostic,
            }
        )


__all__ = ["TableRuntimeController"]
