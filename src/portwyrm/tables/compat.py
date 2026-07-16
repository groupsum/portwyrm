"""Small helpers for frozen NPM wire projections."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def iso(value: Any) -> str:
    if value is None:
        return datetime.now(UTC).isoformat()
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    return str(value)


def extension_metadata(payload: dict[str, Any], known: set[str]) -> dict[str, Any]:
    """Retain only fields that are not represented by normalized columns/children."""

    extensions = {key: value for key, value in payload.items() if key not in known}
    return {"extensions": extensions} if extensions else {}


def extensions(row: Any) -> dict[str, Any]:
    metadata = dict(getattr(row, "metadata_json", None) or {})
    # Read old snapshots only as an upgrade bridge for unknown extension fields.
    return dict(metadata.get("extensions") or {})


async def add_audit(
    db: Any,
    *,
    action: str,
    object_type: str,
    object_id: int | str,
    details: dict[str, Any] | None = None,
    actor_principal_id: int | None = None,
) -> None:
    from .audit import AuditEventStore

    db.add(
        AuditEventStore(
            actor_principal_id=actor_principal_id,
            action=action,
            object_type=object_type,
            object_id=str(object_id),
            details=details or {},
        )
    )


__all__ = ["add_audit", "extension_metadata", "extensions", "iso"]
