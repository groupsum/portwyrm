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
LEGACY_CREDENTIAL_MIGRATION = "legacy-credentials-v2"
ROUTING_CONTRACT_MIGRATION = "routing-contracts-v2"
_ROUTING_COLUMNS = (
    ("routing_hosts", "http2_enabled", "BOOLEAN NOT NULL DEFAULT FALSE"),
    ("routing_hosts", "trust_forwarded_proto", "BOOLEAN NOT NULL DEFAULT FALSE"),
    ("stream_routes", "certificate_id", "INTEGER NULL"),
)


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
        await cls._upgrade_routing_contracts(ctx["db"])
        await cls._upgrade_legacy_credentials(ctx["db"])
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

    @classmethod
    async def _upgrade_legacy_credentials(cls, db: Any) -> bool:
        """Restore write-only password hashes omitted by the first normalized import."""
        from .credentials import CredentialStore
        from .identities import PrincipalStore

        rows = [row for row in await cls._legacy_rows(db) if row[0] == "_credentials"]
        checksum = cls._checksum(rows)
        existing = (
            await _await(
                db.execute(select(cls).where(cls.name == LEGACY_CREDENTIAL_MIGRATION))
            )
        ).scalar_one_or_none()
        if existing is not None:
            if existing.checksum != checksum:
                raise ValueError(
                    "legacy credential migration checksum changed after it was recorded"
                )
            return False

        restored = False
        for _collection, resource_id, payload_text in rows:
            payload = json.loads(payload_text)
            identity = str(payload.get("id") or resource_id).strip().casefold()
            password_hash = str(payload.get("password_hash") or "")
            if not identity or not password_hash:
                continue
            principal = (
                await _await(
                    db.execute(select(PrincipalStore).where(PrincipalStore.email == identity))
                )
            ).scalar_one_or_none()
            if principal is None:
                continue
            credential = (
                await _await(
                    db.execute(
                        select(CredentialStore).where(
                            CredentialStore.principal_id == principal.id
                        )
                    )
                )
            ).scalar_one_or_none()
            if credential is None:
                db.add(
                    CredentialStore(
                        principal_id=principal.id,
                        password_hash=password_hash,
                    )
                )
                restored = True

        now = int(time.time())
        db.add(
            cls(
                name=LEGACY_CREDENTIAL_MIGRATION,
                checksum=checksum,
                source_version="records-v1",
                status="applied",
                started_at=now,
                applied_at=now,
                diagnostic="restored legacy credential rows" if restored else None,
            )
        )
        await _await(db.flush())
        return restored

    @classmethod
    async def _upgrade_routing_contracts(cls, db: Any) -> bool:
        existing = (
            await _await(db.execute(select(cls).where(cls.name == ROUTING_CONTRACT_MIGRATION)))
        ).scalar_one_or_none()
        if existing is not None:
            if existing.checksum != cls._routing_contract_checksum():
                raise ValueError(
                    "routing contract migration checksum changed after it was recorded"
                )
            return False

        changed = False
        for table_name, column_name, definition in _ROUTING_COLUMNS:
            columns = await cls._table_columns(db, table_name)
            if not columns or column_name in columns:
                continue
            await _await(
                db.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"))
            )
            changed = True

        await cls._validate_routing_contracts(db)
        now = int(time.time())
        db.add(
            cls(
                name=ROUTING_CONTRACT_MIGRATION,
                checksum=cls._routing_contract_checksum(),
                source_version="normalized-v1",
                status="applied",
                started_at=now,
                applied_at=now,
            )
        )
        await _await(db.flush())
        return changed

    @staticmethod
    async def _table_columns(db: Any, table_name: str) -> set[str]:
        try:
            result = await _await(db.execute(text(f"SELECT * FROM {table_name} WHERE 1 = 0")))
        except Exception:
            return set()
        return set(map(str, result.keys()))

    @classmethod
    async def _validate_routing_contracts(cls, db: Any) -> None:
        validations = (
            (
                "routing_hosts",
                "kind NOT IN ('proxy','redirect','dead') "
                "OR (redirect_code IS NOT NULL AND redirect_code NOT IN (301,302,307,308)) "
                "OR (hsts_enabled = TRUE AND (force_ssl = FALSE OR certificate_id IS NULL)) "
                "OR (hsts_subdomains = TRUE AND hsts_enabled = FALSE)",
                "routing host rows violate the normalized routing contract",
            ),
            (
                "routing_sources",
                "domain_name <> lower(domain_name)",
                "routing source domains must be canonical lowercase values",
            ),
            (
                "routing_upstreams",
                "protocol NOT IN ('http','https') OR target_kind NOT IN ('ip','dns','docker') "
                "OR port < 1 OR port > 65535 OR weight < 1",
                "routing upstream rows violate protocol, target, port, or weight constraints",
            ),
            (
                "routing_locations",
                "protocol NOT IN ('http','https') OR target_kind NOT IN ('ip','dns','docker') "
                "OR port < 1 OR port > 65535",
                "routing location rows violate protocol, target, or port constraints",
            ),
            (
                "stream_routes",
                "protocol NOT IN ('tcp','udp','tcp+udp') "
                "OR target_kind NOT IN ('ip','dns','docker') "
                "OR incoming_port < 1 OR incoming_port > 65535 "
                "OR target_port < 1 OR target_port > 65535 "
                "OR (certificate_id IS NOT NULL AND protocol = 'udp')",
                "stream rows violate protocol, target, port, or TLS constraints",
            ),
            (
                "access_list_rules",
                "directive NOT IN ('allow','deny')",
                "access rules contain an unsupported directive",
            ),
        )
        for table_name, predicate, diagnostic in validations:
            if not await cls._table_columns(db, table_name):
                continue
            result = await _await(
                db.execute(text(f"SELECT COUNT(*) FROM {table_name} WHERE {predicate}"))
            )
            if int(result.scalar_one()) > 0:
                raise ValueError(diagnostic)

        if await cls._table_columns(db, "routing_sources"):
            duplicates = await _await(
                db.execute(
                    text(
                        "SELECT COUNT(*) FROM ("
                        "SELECT lower(domain_name) FROM routing_sources "
                        "GROUP BY lower(domain_name) HAVING COUNT(*) > 1"
                        ") AS duplicate_domains"
                    )
                )
            )
            if int(duplicates.scalar_one()) > 0:
                raise ValueError("routing source domains must be globally unique")

        if await cls._table_columns(db, "stream_routes"):
            collisions = await _await(
                db.execute(
                    text(
                        "SELECT COUNT(*) FROM stream_routes AS left_route "
                        "JOIN stream_routes AS right_route "
                        "ON left_route.id < right_route.id "
                        "AND left_route.incoming_port = right_route.incoming_port "
                        "WHERE left_route.protocol = 'tcp+udp' "
                        "OR right_route.protocol = 'tcp+udp' "
                        "OR left_route.protocol = right_route.protocol"
                    )
                )
            )
            if int(collisions.scalar_one()) > 0:
                raise ValueError("stream routes contain overlapping port/protocol claims")

    @staticmethod
    def _routing_contract_checksum() -> str:
        encoded = json.dumps(_ROUTING_COLUMNS, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

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
        bind = db.get_bind()
        if bind.dialect.name != "sqlite":
            return []
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
        from .routing import RoutingHostStore, RoutingSourceStore, StreamRouteStore
        from .settings import SettingStore

        resource_id = int(payload["id"]) if str(payload.get("id", "")).isdigit() else None
        target_table = {
            "access_lists": AccessListStore,
            "certificates": CertificateStore,
            "dead_hosts": RoutingHostStore,
            "proxy_hosts": RoutingHostStore,
            "redirection_hosts": RoutingHostStore,
            "settings": SettingStore,
            "streams": StreamRouteStore,
            "users": PrincipalStore,
        }.get(collection)
        if (
            resource_id is not None
            and target_table is not None
            and await _await(db.get(target_table, resource_id)) is not None
        ):
            return
        if collection in {"proxy_hosts", "redirection_hosts", "dead_hosts"}:
            domains = {
                str(domain).strip().casefold()
                for domain in payload.get("domain_names") or []
                if str(domain).strip()
            }
            if domains:
                collision = await _await(
                    db.execute(
                        select(RoutingSourceStore.id).where(
                            RoutingSourceStore.domain_name.in_(domains)
                        )
                    )
                )
                if collision.first() is not None:
                    return
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
                    certificate_id=int(payload.get("certificate_id") or 0) or None,
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


__all__ = [
    "LEGACY_CREDENTIAL_MIGRATION",
    "MIGRATION_NAME",
    "ROUTING_CONTRACT_MIGRATION",
    "SchemaMigrationStore",
]
