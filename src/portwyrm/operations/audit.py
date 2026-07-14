"""Append-only, redacted operator audit events."""

from __future__ import annotations

import re
import time
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from portwyrm.persistence import Repository

_SENSITIVE = re.compile(r"password|secret|token|credential|private[_-]?key|totp", re.IGNORECASE)


def redact(value: Any, *, key: str = "") -> Any:
    if _SENSITIVE.search(key):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {
            str(item_key): redact(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [redact(item, key=key) for item in value]
    return value


class AuditLog:
    def __init__(self, repository: Repository) -> None:
        self.repository = repository

    def append(
        self,
        action: str,
        *,
        actor: str,
        target: str | None = None,
        details: Mapping[str, Any] | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        event = {
            "id": f"{time.time_ns():020d}-{uuid.uuid4().hex}",
            "created_on": now.isoformat(),
            "action": action,
            "actor": actor,
            "target": target,
            "correlation_id": correlation_id or uuid.uuid4().hex,
            "details": redact(dict(details or {})),
        }
        with self.repository.transaction() as tx:
            tx.upsert("audit_log", event)
        return event

    def list(self, *, since: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with self.repository.transaction() as tx:
            events = tx.list("audit_log")
        if since:
            events = [event for event in events if str(event.get("created_on", "")) >= since]
        return events[-max(0, limit) :]
