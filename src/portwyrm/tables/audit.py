"""Durable, append-oriented audit events."""

import inspect
from typing import Any

from tigrbl import op_ctx
from tigrbl.factories.table import defineTableSpec
from tigrbl.types import JSON, Column, ForeignKey, Integer, String

from .base import PortwyrmTable


class AuditEventStore(PortwyrmTable, defineTableSpec(ops=("read", "list", "delete"))):
    __tablename__ = "audit_events"
    actor_principal_id = Column(Integer, ForeignKey("principals.id"), nullable=True, index=True)
    action = Column(String(255), nullable=False, index=True)
    object_type = Column(String(128), nullable=False, index=True)
    object_id = Column(String(255), nullable=False)
    details = Column(JSON, nullable=False, default=dict)

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
        flushed = ctx["db"].flush()
        if inspect.isawaitable(flushed):
            await flushed
        return {
            "id": row.id,
            "action": row.action,
            "object_type": row.object_type,
            "object_id": row.object_id,
            "details": row.details,
        }


AuditEvent = AuditEventStore

__all__ = ["AuditEvent", "AuditEventStore"]
