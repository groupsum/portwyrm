"""Programmatic table work executed by Tigrbl's transaction kernel."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

from .models import BrowserSession

T = TypeVar("T")
Work = Callable[[Any], T | Awaitable[T]]


class KernelUnitOfWork:
    def __init__(self, app: Any) -> None:
        self.app = app

    async def run(self, work: Work[T]) -> T:
        holder: dict[str, Any] = {}

        async def capture(db: Any) -> None:
            try:
                value = work(db)
                holder["value"] = await value if isinstance(value, Awaitable) else value
            except BaseException as error:
                holder["error"] = error
                raise

        proxy = getattr(self.app.core_raw, BrowserSession.__name__)
        try:
            result = await proxy.unit_of_work({}, ctx={"app": self.app, "kernel_work": capture})
        except Exception as exc:
            error = holder.get("error")
            if isinstance(error, BaseException):
                raise error from exc
            raise
        if not isinstance(result, dict) or result.get("kernel_unit_of_work") is not True:
            raise RuntimeError("Tigrbl kernel returned an invalid unit-of-work result")
        return holder["value"]
