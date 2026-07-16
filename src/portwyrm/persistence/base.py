"""Backend-neutral persistence contracts."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Iterator, Mapping, MutableMapping
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

Resource = dict[str, Any]


class PersistenceError(RuntimeError):
    """Base persistence failure."""


class ConflictError(PersistenceError):
    """A write would replace existing state without explicit permission."""


class ConfigurationError(PersistenceError):
    """A backend is missing required configuration or an optional driver."""


def canonical_json(value: object) -> str:
    """Return stable JSON suitable for checksums and durable records."""

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def checksum(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def clone(value: Resource) -> Resource:
    return copy.deepcopy(value)


def resource_key(resource: Mapping[str, Any]) -> str:
    if "id" not in resource or resource["id"] in (None, ""):
        raise PersistenceError("resource must have a non-empty id")
    return str(resource["id"])


@runtime_checkable
class Transaction(Protocol):
    """Atomic collection-oriented unit of work."""

    def collections(self) -> tuple[str, ...]: ...

    def list(self, collection: str) -> list[Resource]: ...

    def get(self, collection: str, resource_id: str | int) -> Resource | None: ...

    def upsert(self, collection: str, resource: Mapping[str, Any]) -> Resource: ...

    def delete(self, collection: str, resource_id: str | int) -> bool: ...


@runtime_checkable
class Repository(Protocol):
    """Repository implemented by every metadata adapter."""

    backend_name: str

    def transaction(self) -> AbstractContextManager[Transaction]: ...


class RepositoryProxy:
    """Mutable composition-root indirection used during authority cutover."""

    def __init__(self, target: Repository | None = None) -> None:
        self.target = target

    def bind(self, target: Repository) -> None:
        self.target = target

    def _bound(self) -> Repository:
        if self.target is None:
            raise RuntimeError("repository proxy is not bound")
        return self.target

    @property
    def backend_name(self) -> str:
        return self._bound().backend_name

    def transaction(self) -> AbstractContextManager[Transaction]:
        return self._bound().transaction()


@runtime_checkable
class BlobStore(Protocol):
    def put(self, name: str, data: bytes) -> str: ...

    def get(self, name: str) -> bytes: ...

    def delete(self, name: str) -> bool: ...

    def exists(self, name: str) -> bool: ...


def validate_collection_name(value: str) -> str:
    if not value or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789_-." for char in value):
        raise PersistenceError(f"invalid collection name: {value!r}")
    return value


def safe_blob_path(root: Path, name: str) -> Path:
    normalized = name.replace("\\", "/").strip("/")
    if not normalized or any(part in ("", ".", "..") for part in normalized.split("/")):
        raise PersistenceError(f"invalid blob name: {name!r}")
    target = (root / normalized).resolve()
    if root.resolve() not in target.parents:
        raise PersistenceError(f"blob escapes store root: {name!r}")
    return target


class MappingTransaction:
    """Transaction implementation shared by memory and filesystem adapters."""

    def __init__(self, state: MutableMapping[str, MutableMapping[str, Resource]]) -> None:
        self.state = state

    def collections(self) -> tuple[str, ...]:
        return tuple(sorted(self.state))

    def list(self, collection: str) -> list[Resource]:
        validate_collection_name(collection)
        return [clone(value) for _, value in sorted(self.state.get(collection, {}).items())]

    def get(self, collection: str, resource_id: str | int) -> Resource | None:
        validate_collection_name(collection)
        value = self.state.get(collection, {}).get(str(resource_id))
        return clone(value) if value is not None else None

    def upsert(self, collection: str, resource: Mapping[str, Any]) -> Resource:
        validate_collection_name(collection)
        value = copy.deepcopy(dict(resource))
        self.state.setdefault(collection, {})[resource_key(value)] = value
        return clone(value)

    def delete(self, collection: str, resource_id: str | int) -> bool:
        validate_collection_name(collection)
        bucket = self.state.get(collection)
        if bucket is None or str(resource_id) not in bucket:
            return False
        del bucket[str(resource_id)]
        if not bucket:
            del self.state[collection]
        return True


def iter_records(tx: Transaction) -> Iterator[tuple[str, Resource]]:
    for collection in tx.collections():
        for record in tx.list(collection):
            yield collection, record
