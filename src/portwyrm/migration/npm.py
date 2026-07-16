"""Nginx Proxy Manager discovery, validation, and import."""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from collections.abc import Iterable, Mapping
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

MIGRATION_VERSION = "portwyrm.npm-import.v1"

TABLE_COLLECTIONS = {
    "user": "users",
    "certificate": "certificates",
    "access_list": "access_lists",
    "proxy_host": "proxy_hosts",
    "redirection_host": "redirection_hosts",
    "dead_host": "dead_hosts",
    "stream": "streams",
    "setting": "settings",
    "audit_log": "audit_log",
    "_credentials": "_credentials",
}

RELATED_TABLES = {"auth", "user_permission", "access_list_auth", "access_list_client"}

JSON_FIELDS = {
    "domain_names",
    "meta",
    "roles",
    "permissions",
    "items",
    "clients",
    "locations",
}


@dataclass(frozen=True)
class QuarantinedRecord:
    collection: str
    source_id: str
    reason: str
    resource: dict[str, Any]


@dataclass
class PreflightReport:
    schema_version: str = MIGRATION_VERSION
    source_kind: str = "mapping"
    counts: dict[str, int] = field(default_factory=dict)
    records: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    quarantine: list[QuarantinedRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def importable(self) -> int:
        return sum(len(records) for records in self.records.values())

    def to_dict(self, *, include_records: bool = False) -> dict[str, Any]:
        result = {
            "schema_version": self.schema_version,
            "source_kind": self.source_kind,
            "counts": self.counts,
            "importable": self.importable,
            "quarantine": [asdict(item) for item in self.quarantine],
            "warnings": self.warnings,
        }
        if include_records:
            result["records"] = self.records
        return result


def _decode_row(row: Mapping[str, Any]) -> dict[str, Any]:
    resource = dict(row)
    for field_name in JSON_FIELDS.intersection(resource):
        value = resource[field_name]
        if isinstance(value, str) and value:
            with suppress(json.JSONDecodeError):
                resource[field_name] = json.loads(value)
    return resource


def load_npm_sqlite(path: str | Path) -> dict[str, list[dict[str, Any]]]:
    """Read supported NPM tables without mutating the source database."""

    connection = sqlite3.connect(f"file:{Path(path).resolve()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        available = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        result: dict[str, list[dict[str, Any]]] = {}
        for table in TABLE_COLLECTIONS.keys() | RELATED_TABLES:
            if table not in available:
                continue
            rows = connection.execute(f'SELECT * FROM "{table}" ORDER BY id').fetchall()
            result[table] = [dict(row) for row in rows]
        return result
    finally:
        connection.close()


def preflight_npm(
    source: Mapping[str, Iterable[Mapping[str, Any]]], *, source_kind: str = "mapping"
) -> PreflightReport:
    report = PreflightReport(source_kind=source_kind)
    source = _normalize_related_tables(source, report)
    seen: dict[str, set[str]] = {}
    for table, rows in source.items():
        collection = TABLE_COLLECTIONS.get(
            table, table if table in TABLE_COLLECTIONS.values() else None
        )
        if collection is None:
            report.warnings.append(f"unsupported source table ignored: {table}")
            continue
        bucket: list[dict[str, Any]] = []
        seen.setdefault(collection, set())
        for raw in rows:
            resource = _decode_row(raw)
            source_id = str(resource.get("id", ""))
            reason = None
            if not source_id:
                reason = "missing id"
            elif source_id in seen[collection]:
                reason = "duplicate id"
            elif resource.get("is_deleted") in (1, True, "1"):
                reason = "soft-deleted source record"
            if reason:
                report.quarantine.append(
                    QuarantinedRecord(collection, source_id or "unknown", reason, resource)
                )
                continue
            seen[collection].add(source_id)
            bucket.append(resource)
        report.records.setdefault(collection, []).extend(bucket)

    _quarantine_broken_references(report)
    report.counts = dict(
        sorted(Counter({key: len(value) for key, value in report.records.items()}).items())
    )
    return report


def _normalize_related_tables(
    source: Mapping[str, Iterable[Mapping[str, Any]]], report: PreflightReport
) -> dict[str, list[dict[str, Any]]]:
    normalized = {table: [dict(row) for row in rows] for table, rows in source.items()}
    users = {str(row.get("id")): row for row in normalized.get("user", [])}
    access_lists = {str(row.get("id")): row for row in normalized.get("access_list", [])}

    permission_fields = (
        "proxy_hosts",
        "redirection_hosts",
        "dead_hosts",
        "streams",
        "access_lists",
        "certificates",
    )
    for permission in normalized.pop("user_permission", []):
        user = users.get(str(permission.get("user_id")))
        if user is None:
            report.warnings.append(
                f"orphan user_permission ignored: user_id={permission.get('user_id')}"
            )
            continue
        user["visibility"] = permission.get("visibility", "user")
        user["permissions"] = {
            field: permission.get(field, "hidden") for field in permission_fields
        }

    credentials: list[dict[str, Any]] = []
    for auth in normalized.pop("auth", []):
        if auth.get("type", "password") != "password":
            report.warnings.append(f"unsupported auth type ignored: {auth.get('type')}")
            continue
        user = users.get(str(auth.get("user_id")))
        if user is None or not user.get("email") or not auth.get("secret"):
            report.warnings.append(f"orphan auth record ignored: id={auth.get('id')}")
            continue
        credentials.append(
            {
                "id": str(user["email"]).strip().casefold(),
                "password_hash": str(auth["secret"]),
            }
        )
    if credentials:
        normalized["_credentials"] = credentials

    for related, target_field in (
        ("access_list_auth", "items"),
        ("access_list_client", "clients"),
    ):
        for item in normalized.pop(related, []):
            access_list = access_lists.get(str(item.get("access_list_id")))
            if access_list is None:
                report.warnings.append(
                    f"orphan {related} ignored: access_list_id={item.get('access_list_id')}"
                )
                continue
            child = {
                key: value
                for key, value in item.items()
                if key not in {"id", "access_list_id", "created_on", "modified_on"}
            }
            access_list.setdefault(target_field, []).append(child)
    return normalized


def preflight_npm_sqlite(path: str | Path) -> PreflightReport:
    return preflight_npm(load_npm_sqlite(path), source_kind="sqlite")


def _quarantine_broken_references(report: PreflightReport) -> None:
    existing = {
        collection: {str(resource["id"]) for resource in resources}
        for collection, resources in report.records.items()
    }
    reference_rules = {
        "certificate_id": "certificates",
        "access_list_id": "access_lists",
        "owner_user_id": "users",
    }
    for collection in ("proxy_hosts", "redirection_hosts", "dead_hosts", "streams"):
        accepted: list[dict[str, Any]] = []
        for resource in report.records.get(collection, []):
            broken = []
            for field_name, target in reference_rules.items():
                value = resource.get(field_name)
                if value not in (None, 0, "0", "") and str(value) not in existing.get(
                    target, set()
                ):
                    broken.append(f"{field_name}={value} does not resolve in {target}")
            if broken:
                report.quarantine.append(
                    QuarantinedRecord(collection, str(resource["id"]), "; ".join(broken), resource)
                )
            else:
                accepted.append(resource)
        report.records[collection] = accepted
