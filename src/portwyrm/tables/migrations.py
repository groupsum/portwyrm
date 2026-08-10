"""Current-schema lifecycle records; legacy record-store imports are intentionally unsupported."""

from __future__ import annotations

import inspect
import time
from typing import Any

from sqlalchemy import text
from tigrbl import op_ctx
from tigrbl.types import Integer, String, Text, UniqueConstraint

from .base import READ_ONLY_PROFILE, PortwyrmTable, acol

_CERTIFICATE_OWNER_MIGRATION = "certificate-owner-principal-v1"
_CERTIFICATE_OWNER_CHECKSUM = "sha256:certificate-owner-principal-v1"


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


async def _certificate_owner_required(db: Any) -> bool:
    bind = db.get_bind()
    dialect = str(bind.dialect.name)
    if dialect == "sqlite":
        rows = await _await(db.execute(text("PRAGMA table_info(certificates)")))
        columns = {str(row[1]) for row in rows}
    elif dialect == "postgresql":
        rows = await _await(
            db.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = current_schema() AND table_name = 'certificates'"
                )
            )
        )
        columns = {str(row[0]) for row in rows}
    elif dialect == "mysql":
        rows = await _await(
            db.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = DATABASE() AND table_name = 'certificates'"
                )
            )
        )
        columns = {str(row[0]) for row in rows}
    else:
        raise RuntimeError(f"schema migration does not support {dialect!r}")
    return "owner_principal_id" not in columns


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
        required = await _certificate_owner_required(ctx["db"])
        return {
            "name": _CERTIFICATE_OWNER_MIGRATION,
            "required": required,
            "records": 1 if required else 0,
            "checksum": _CERTIFICATE_OWNER_CHECKSUM,
        }

    @op_ctx(alias="apply", target="custom", arity="collection")
    async def apply(cls, ctx: Any) -> dict[str, Any]:
        required = await _certificate_owner_required(ctx["db"])
        if required:
            dialect = str(ctx["db"].get_bind().dialect.name)
            column_sql = "INTEGER REFERENCES principals(id)"
            if dialect == "mysql":
                column_sql = "INTEGER NULL"
            await _await(
                ctx["db"].execute(
                    text("ALTER TABLE certificates ADD COLUMN owner_principal_id " + column_sql)
                )
            )
            if dialect == "mysql":
                index_sql = (
                    "CREATE INDEX ix_certificates_owner_principal_id "
                    "ON certificates (owner_principal_id)"
                )
            else:
                index_sql = (
                    "CREATE INDEX IF NOT EXISTS ix_certificates_owner_principal_id "
                    "ON certificates (owner_principal_id)"
                )
            await _await(ctx["db"].execute(text(index_sql)))
            ctx["db"].add(
                cls(
                    name=_CERTIFICATE_OWNER_MIGRATION,
                    checksum=_CERTIFICATE_OWNER_CHECKSUM,
                    source_version="0.1.0a10",
                    status="applied",
                    started_at=int(time.time()),
                    applied_at=int(time.time()),
                )
            )
        return {
            "name": _CERTIFICATE_OWNER_MIGRATION,
            "required": required,
            "records": 1 if required else 0,
            "checksum": _CERTIFICATE_OWNER_CHECKSUM,
            "applied": required,
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
