"""Versioned, checksummed export and import bundles."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from .base import ConflictError, Repository, checksum, iter_records

BUNDLE_VERSION = "portwyrm.export.v1"
TRANSIENT_COLLECTIONS = {"_sessions", "_personal_access_tokens", "_mfa"}


def export_bundle(repository: Repository) -> dict[str, Any]:
    with repository.transaction() as tx:
        records = [
            {"collection": collection, "resource": resource}
            for collection, resource in iter_records(tx)
            if collection not in TRANSIENT_COLLECTIONS
        ]
    content = {
        "schema_version": BUNDLE_VERSION,
        "created_at": datetime.now(UTC).isoformat(),
        "source_backend": repository.backend_name,
        "records": records,
    }
    return {**content, "checksum": checksum(content)}


def validate_bundle(bundle: Mapping[str, Any]) -> None:
    if bundle.get("schema_version") != BUNDLE_VERSION:
        raise ValueError("unsupported export bundle version")
    content = {key: value for key, value in bundle.items() if key != "checksum"}
    if checksum(content) != bundle.get("checksum"):
        raise ValueError("export bundle checksum mismatch")
    for entry in bundle.get("records", []):
        if not isinstance(entry, Mapping) or "collection" not in entry or "resource" not in entry:
            raise ValueError("invalid export record")


def _apply_import(
    repository: Repository,
    bundle: Mapping[str, Any],
    *,
    replace: bool,
    commit: bool,
) -> dict[str, int]:
    validate_bundle(bundle)
    summary = {"created": 0, "replaced": 0, "unchanged": 0}
    with repository.transaction() as tx:
        for entry in bundle["records"]:
            collection = str(entry["collection"])
            resource = dict(entry["resource"])
            existing = tx.get(collection, resource["id"])
            if existing == resource:
                summary["unchanged"] += 1
                continue
            if existing is not None and not replace:
                raise ConflictError(f"{collection}/{resource['id']} already exists")
            summary["replaced" if existing is not None else "created"] += 1
            if commit:
                tx.upsert(collection, resource)
    return summary


def import_bundle(
    repository: Repository, bundle: Mapping[str, Any], *, replace: bool = False
) -> dict[str, int]:
    return _apply_import(repository, bundle, replace=replace, commit=True)


def preview_import(
    repository: Repository, bundle: Mapping[str, Any], *, replace: bool = False
) -> dict[str, int]:
    return _apply_import(repository, bundle, replace=replace, commit=False)
