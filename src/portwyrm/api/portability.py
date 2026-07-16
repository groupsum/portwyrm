"""Portable state bundles over the public table-backed compatibility boundary."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from portwyrm.api.compat.resources import TableResources

BUNDLE_VERSION = "portwyrm.export.v2"
PORTABLE_COLLECTIONS = (
    "users",
    "settings",
    "access_lists",
    "certificates",
    "proxy_hosts",
    "redirection_hosts",
    "dead_hosts",
    "streams",
)


def _checksum(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def _comparable_resource(resource: Mapping[str, Any]) -> dict[str, Any]:
    """Ignore absent optional fields synthesized as null by list projections."""

    return {key: value for key, value in resource.items() if value is not None}


class TablePortability:
    def __init__(self, resources: TableResources, backend: str) -> None:
        self.resources = resources
        self.backend = backend

    async def export(self) -> dict[str, Any]:
        records = []
        for collection in PORTABLE_COLLECTIONS:
            records.extend(
                {"collection": collection, "resource": row}
                for row in await self.resources.list_resources(collection)
            )
        content = {
            "schema_version": BUNDLE_VERSION,
            "created_at": datetime.now(UTC).isoformat(),
            "source_backend": self.backend,
            "records": records,
        }
        return {**content, "checksum": _checksum(content)}

    async def preview(self, bundle: Mapping[str, Any], *, replace: bool = False) -> dict[str, int]:
        return await self._apply(bundle, replace=replace, commit=False)

    async def import_(self, bundle: Mapping[str, Any], *, replace: bool = False) -> dict[str, int]:
        return await self._apply(bundle, replace=replace, commit=True)

    async def _apply(
        self, bundle: Mapping[str, Any], *, replace: bool, commit: bool
    ) -> dict[str, int]:
        self._validate(bundle)
        summary = {"created": 0, "replaced": 0, "unchanged": 0}
        for entry in bundle["records"]:
            collection = str(entry["collection"])
            if collection not in PORTABLE_COLLECTIONS:
                raise ValueError(f"unsupported portable collection {collection!r}")
            resource = dict(entry["resource"])
            existing = await self.resources.get_resource(collection, resource["id"])
            if existing is not None and _comparable_resource(existing) == _comparable_resource(
                resource
            ):
                summary["unchanged"] += 1
                continue
            if existing is not None and not replace:
                raise ValueError(f"{collection}/{resource['id']} already exists")
            key = "replaced" if existing is not None else "created"
            summary[key] += 1
            if not commit:
                continue
            if existing is None:
                await self.resources.create_resource(collection, resource)
            else:
                await self.resources.update_resource(collection, resource["id"], resource)
        return summary

    @staticmethod
    def _validate(bundle: Mapping[str, Any]) -> None:
        if bundle.get("schema_version") != BUNDLE_VERSION:
            raise ValueError("unsupported export bundle version")
        content = {key: value for key, value in bundle.items() if key != "checksum"}
        if _checksum(content) != bundle.get("checksum"):
            raise ValueError("export bundle checksum mismatch")
        if not isinstance(bundle.get("records"), list):
            raise ValueError("export records must be an array")
        for entry in bundle["records"]:
            if not isinstance(entry, Mapping) or not {"collection", "resource"} <= set(entry):
                raise ValueError("invalid export record")


__all__ = ["BUNDLE_VERSION", "PORTABLE_COLLECTIONS", "TablePortability"]
