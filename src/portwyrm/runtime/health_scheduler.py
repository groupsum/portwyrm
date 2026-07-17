"""Recurring proxy-host health checks through the public Tigrbl operation."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

logger = logging.getLogger(__name__)


class ProxyHostHealthScheduler:
    def __init__(self, app: Any, *, interval_seconds: int = 30, concurrency: int = 20) -> None:
        self.app = app
        self.interval_seconds = max(1, interval_seconds)
        self._semaphore = asyncio.Semaphore(max(1, concurrency))
        self._task: asyncio.Task[None] | None = None
        self._wake = asyncio.Event()

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="portwyrm-host-health")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    def wake(self) -> None:
        self._wake.set()

    async def sweep(self) -> None:
        result = await self.app.core.RoutingHostStore.health_list({})
        host_ids = [
            int(item["id"])
            for item in result.get("items", [])
            if item.get("administrative_state") == "enabled"
        ]
        await asyncio.gather(*(self._probe(host_id) for host_id in host_ids))

    async def _probe(self, host_id: int) -> None:
        async with self._semaphore:
            try:
                await self.app.core.RoutingHostStore.probe({"id": host_id})
            except Exception:
                logger.exception("scheduled proxy-host probe failed for %s", host_id)

    async def _run(self) -> None:
        while True:
            await self.sweep()
            self._wake.clear()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), timeout=self.interval_seconds)


__all__ = ["ProxyHostHealthScheduler"]
