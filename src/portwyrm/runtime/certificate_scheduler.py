"""Periodic renewal for active Namecheap DNS-01 certificates."""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from typing import Any

logger = logging.getLogger(__name__)


class CertificateRenewalScheduler:
    def __init__(self, app: Any, *, interval_seconds: int = 3600) -> None:
        self.app = app
        self.interval_seconds = interval_seconds
        self.status = "idle"
        self._task: asyncio.Task[None] | None = None
        self._stopping = asyncio.Event()

    def start(self) -> None:
        self._stopping.clear()
        self._task = asyncio.create_task(self._run(), name="portwyrm-certificate-renewal")

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None:
            await self._task
            self._task = None

    async def sweep(self) -> None:
        certificates = self.app.core.CertificateStore
        self.status = "ok"
        for record in await certificates.list({}):
            if self._stopping.is_set():
                return
            meta = record.get("meta") or {}
            if (
                record.get("status") != "active"
                or record.get("provider") != "letsencrypt"
                or (record.get("dns_provider") or meta.get("dns_provider")) != "namecheap"
                or (record.get("challenge_type") or meta.get("challenge_type")) != "dns-01"
            ):
                continue
            try:
                await certificates.renew({"id": record["id"]})
            except Exception:
                self.status = "degraded"
                logger.error("Scheduled Namecheap renewal failed for certificate %s", record["id"])

    async def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                await self.sweep()
            except Exception:
                self.status = "degraded"
                logger.error("Unable to enumerate certificates for scheduled renewal")
            with suppress(TimeoutError):
                await asyncio.wait_for(self._stopping.wait(), timeout=self.interval_seconds)
