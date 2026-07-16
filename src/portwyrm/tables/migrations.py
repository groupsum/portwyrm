"""Current-schema lifecycle records; legacy record-store imports are intentionally unsupported."""

from __future__ import annotations

import time
from typing import Any

from tigrbl import op_ctx
from tigrbl.types import Integer, String, Text, UniqueConstraint

from .base import READ_ONLY_PROFILE, PortwyrmTable, acol


class SchemaMigrationStore(PortwyrmTable):
    """Read-only migration history with explicit operational recording."""

    __tablename__ = "system_migrations"
    TABLE_PROFILE = READ_ONLY_PROFILE
    __table_args__ = (UniqueConstraint("name", name="uq_system_migration_name"),)

    name = acol(String(255), nullable=False, index=True)
    checksum = acol(String(64), nullable=False)
    source_version = acol(String(64), nullable=True)
    status = acol(String(32), nullable=False, index=True)
    started_at = acol(Integer, nullable=False)
    applied_at = acol(Integer, nullable=True)
    diagnostic = acol(Text, nullable=True)

    @op_ctx(alias="plan", target="custom", arity="collection", persist="skip")
    async def plan(cls, ctx: Any) -> dict[str, Any]:
        del ctx
        return {
            "name": "tigrbl-current-schema",
            "required": False,
            "records": 0,
            "checksum": "current",
        }

    @op_ctx(alias="apply", target="custom", arity="collection")
    async def apply(cls, ctx: Any) -> dict[str, Any]:
        del ctx
        return {
            "name": "tigrbl-current-schema",
            "required": False,
            "records": 0,
            "checksum": "current",
            "applied": False,
        }

    @op_ctx(alias="record_failure", target="custom", arity="collection")
    async def record_failure(cls, ctx: Any) -> Any:
        payload = dict(ctx.get("payload") or {})
        row = cls(
            name=str(payload.get("name") or f"schema-failed-{int(time.time())}"),
            checksum=str(payload.get("checksum") or "current"),
            source_version="tigrbl",
            status="failed",
            started_at=int(time.time()),
            diagnostic=str(payload.get("diagnostic") or "schema initialization failed")[:4000],
        )
        ctx["db"].add(row)
        return row


SchemaMigration = SchemaMigrationStore

__all__ = ["SchemaMigration", "SchemaMigrationStore"]
