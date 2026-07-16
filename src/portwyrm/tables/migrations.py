"""Idempotent upgrade of the pre-Tigrbl Portwyrm SQLite record store."""

from __future__ import annotations

import hashlib
import inspect
import json
import time
from typing import Any

from sqlalchemy import select, text
from tigrbl import op_ctx, schema_ctx
from tigrbl.factories.table import defineTableSpec
from tigrbl.types import BaseModel, Column, Integer, String, Text, UniqueConstraint

from .base import PortwyrmTable

MIGRATION_NAME = "legacy-records-v1"


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class SchemaMigrationStore(PortwyrmTable, defineTableSpec(ops=("read", "list"))):
    __tablename__ = "system_migrations"
    __table_args__ = (UniqueConstraint("name", name="uq_system_migration_name"),)
    name = Column(String(255), nullable=False, index=True)
    checksum = Column(String(64), nullable=False)
    source_version = Column(String(64), nullable=True)
    status = Column(String(32), nullable=False, index=True)
    started_at = Column(Integer, nullable=False)
    applied_at = Column(Integer, nullable=True)
    diagnostic = Column(Text, nullable=True)

    @schema_ctx(alias="plan", kind="out")
    class PlanResult(BaseModel):
        name: str
        required: bool
        records: int
        checksum: str

    @schema_ctx(alias="apply", kind="out")
    class ApplyResult(PlanResult):
        applied: bool

    @op_ctx(alias="plan", target="custom", arity="collection")
    async def plan(cls, ctx: Any) -> dict[str, Any]:
        return await cls._plan(ctx["db"])

    @classmethod
    async def _plan(cls, db: Any) -> dict[str, Any]:
        rows = await cls._legacy_rows(db)
        checksum = cls._checksum(rows)
        existing = (
            await _await(db.execute(select(cls).where(cls.name == MIGRATION_NAME)))
        ).scalar_one_or_none()
        if existing is not None and existing.checksum != checksum:
            raise ValueError("legacy migration checksum changed after it was recorded")
        return {
            "name": MIGRATION_NAME,
            "required": bool(rows) and existing is None,
            "records": len(rows),
            "checksum": checksum,
        }

    @op_ctx(alias="apply", target="custom", arity="collection")
    async def apply(cls, ctx: Any) -> dict[str, Any]:
        plan = await cls._plan(ctx["db"])
        if not plan["required"]:
            return {**plan, "applied": False}
        for collection, _resource_id, payload_text in await cls._legacy_rows(ctx["db"]):
            await cls._import_record(ctx["db"], collection, json.loads(payload_text))
        now = int(time.time())
        ctx["db"].add(
            cls(
                name=MIGRATION_NAME,
                checksum=plan["checksum"],
                source_version="records-v1",
                status="applied",
                started_at=now,
                applied_at=now,
            )
        )
        return {**plan, "required": False, "applied": True}

    @op_ctx(alias="record_failure", target="custom", arity="collection")
    async def record_failure(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        row = cls(
            name=str(payload.get("name") or f"{MIGRATION_NAME}-failed-{int(time.time())}"),
            checksum=str(payload.get("checksum") or "0" * 64),
            source_version="records-v1",
            status="failed",
            started_at=int(time.time()),
            diagnostic=str(payload.get("diagnostic") or "migration failed")[:4000],
        )
        ctx["db"].add(row)
        await _await(ctx["db"].flush())
        return {"id": row.id, "status": row.status}

    @staticmethod
    async def _legacy_rows(db: Any) -> list[tuple[str, str, str]]:
        exists = await _await(
            db.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='records'"))
        )
        if exists.first() is None:
            return []
        result = await _await(
            db.execute(
                text(
                    "SELECT collection, resource_id, payload FROM records "
                    "ORDER BY collection, resource_id"
                )
            )
        )
        return [(str(row[0]), str(row[1]), str(row[2])) for row in result]

    @staticmethod
    def _checksum(rows: list[tuple[str, str, str]]) -> str:
        encoded = json.dumps(rows, separators=(",", ":"), ensure_ascii=True).encode()
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    async def _import_record(db: Any, collection: str, payload: dict[str, Any]) -> None:
        from .access import AccessListStore
        from .certificates import CertificateStore
        from .principals import CredentialStore, PrincipalStore
        from .routing import RoutingHostStore, StreamRouteStore
        from .settings import SettingStore

        resource_id = int(payload["id"]) if str(payload.get("id", "")).isdigit() else None
        if collection in {"proxy_hosts", "redirection_hosts", "dead_hosts"}:
            payload["kind"] = {
                "proxy_hosts": "proxy",
                "redirection_hosts": "redirect",
                "dead_hosts": "dead",
            }[collection]
            row = RoutingHostStore(id=resource_id, **RoutingHostStore._host_values(payload))
            db.add(row)
            await _await(db.flush())
            await RoutingHostStore._replace_children(db, row.id, payload)
        elif collection == "access_lists":
            row = AccessListStore(id=resource_id, **AccessListStore._values(payload))
            db.add(row)
            await _await(db.flush())
            await AccessListStore._replace_children(db, row.id, payload)
        elif collection == "certificates":
            row = CertificateStore(id=resource_id, **CertificateStore._values(payload))
            db.add(row)
            await _await(db.flush())
            await CertificateStore._replace_domains(db, row.id, payload)
        elif collection == "streams":
            protocol = (
                "tcp+udp"
                if payload.get("tcp_forwarding") and payload.get("udp_forwarding")
                else ("udp" if payload.get("udp_forwarding") else "tcp")
            )
            db.add(
                StreamRouteStore(
                    id=resource_id,
                    owner_principal_id=payload.get("owner_user_id"),
                    protocol=protocol,
                    incoming_port=int(payload.get("incoming_port") or 0),
                    target_kind=str(payload.get("target_kind") or "dns"),
                    target=str(payload.get("forwarding_host") or ""),
                    target_port=int(payload.get("forwarding_port") or 0),
                    enabled=bool(payload.get("enabled", True)),
                )
            )
        elif collection == "settings":
            db.add(
                SettingStore(
                    id=resource_id,
                    key=str(payload.get("key", payload.get("id"))),
                    value=payload.get("value"),
                    metadata_json={},
                )
            )
        elif collection == "users":
            row = PrincipalStore(
                id=resource_id,
                email=str(payload["email"]).casefold(),
                display_name=str(payload.get("name") or ""),
                nickname=str(payload.get("nickname") or ""),
                is_admin=bool(payload.get("is_admin")),
                is_disabled=bool(payload.get("is_disabled")),
                is_deleted=bool(payload.get("is_deleted")),
                visibility=str(payload.get("visibility") or "user"),
                metadata_json={},
            )
            db.add(row)
            await _await(db.flush())
            if payload.get("password_hash"):
                db.add(
                    CredentialStore(
                        principal_id=row.id, password_hash=str(payload["password_hash"])
                    )
                )
            await PrincipalStore._replace_authorization(db, row, payload)


__all__ = ["MIGRATION_NAME", "SchemaMigrationStore"]
