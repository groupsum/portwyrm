"""Durable, append-oriented audit events."""

from typing import Any

from tigrbl import op_ctx
from tigrbl.types import JSON, ForeignKey, Integer, String

from .base import READ_ONLY_PROFILE, PortwyrmTable, acol


class AuditEventStore(PortwyrmTable):
    __tablename__ = "audit_events"
    TABLE_PROFILE = READ_ONLY_PROFILE
    actor_principal_id = acol(Integer, ForeignKey("principals.id"), nullable=True, index=True)
    action = acol(String(255), nullable=False, index=True)
    object_type = acol(String(128), nullable=False, index=True)
    object_id = acol(String(255), nullable=False)
    details = acol(JSON, nullable=False, default=dict)

    @op_ctx(alias="record", target="custom", arity="collection")
    async def record(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        row = cls(
            actor_principal_id=payload.get("actor_principal_id"),
            action=str(payload["action"]),
            object_type=str(payload["object_type"]),
            object_id=str(payload["object_id"]),
            details=dict(payload.get("details") or {}),
        )
        ctx["db"].add(row)
        return {
            "id": row.id,
            "action": row.action,
            "object_type": row.object_type,
            "object_id": row.object_id,
            "details": row.details,
        }


AuditEvent = AuditEventStore

__all__ = ["AuditEvent", "AuditEventStore"]
