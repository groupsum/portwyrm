"""Liveness, readiness, and dependency health reporting."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from portwyrm.persistence import Repository

HealthCheck = Callable[[], bool | Mapping[str, Any]]


class HealthService:
    def __init__(
        self, repository: Repository, checks: Mapping[str, HealthCheck] | None = None
    ) -> None:
        self.repository = repository
        self.checks = dict(checks or {})

    def live(self) -> dict[str, Any]:
        return {"status": "ok", "checked_at": datetime.now(UTC).isoformat()}

    def ready(self) -> dict[str, Any]:
        components: dict[str, Any] = {}
        try:
            with self.repository.transaction() as tx:
                tx.collections()
            components["database"] = {"status": "ok", "backend": self.repository.backend_name}
        except Exception as error:  # readiness must report, not crash
            components["database"] = {"status": "failed", "error": type(error).__name__}
        for name, check in self.checks.items():
            try:
                value = check()
                if isinstance(value, Mapping):
                    components[name] = dict(value)
                    components[name].setdefault("status", "ok")
                else:
                    components[name] = {"status": "ok" if value else "failed"}
            except Exception as error:  # readiness must isolate dependencies
                components[name] = {"status": "failed", "error": type(error).__name__}
        overall = (
            "ok" if all(item.get("status") == "ok" for item in components.values()) else "degraded"
        )
        return {
            "status": overall,
            "components": components,
            "checked_at": datetime.now(UTC).isoformat(),
        }
