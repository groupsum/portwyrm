"""Single-writer filesystem repository and durable blob store."""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

from .base import (
    MappingTransaction,
    PersistenceError,
    Resource,
    canonical_json,
    checksum,
    safe_blob_path,
)


class FilesystemRepository:
    """Atomic snapshot repository intended for one application writer."""

    backend_name = "filesystem"
    schema_version = "portwyrm.filesystem.v1"

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.snapshot_path = self.root / "repository.json"
        self._lock = threading.RLock()

    def _load(self) -> tuple[int, dict[str, dict[str, Resource]]]:
        if not self.snapshot_path.exists():
            return 0, {}
        envelope = json.loads(self.snapshot_path.read_text(encoding="utf-8"))
        if envelope.get("schema_version") != self.schema_version:
            raise PersistenceError("unsupported filesystem repository version")
        content = {"generation": envelope["generation"], "records": envelope["records"]}
        if checksum(content) != envelope.get("checksum"):
            raise PersistenceError("filesystem repository checksum mismatch")
        return int(envelope["generation"]), envelope["records"]

    def _save(self, generation: int, records: dict[str, dict[str, Resource]]) -> None:
        content = {"generation": generation, "records": records}
        envelope = {"schema_version": self.schema_version, **content, "checksum": checksum(content)}
        temporary = self.snapshot_path.with_suffix(".tmp")
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(canonical_json(envelope))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.snapshot_path)

    @contextmanager
    def transaction(self) -> Iterator[MappingTransaction]:
        with self._lock:
            generation, state = self._load()
            tx = MappingTransaction(state)
            yield tx
            self._save(generation + 1, state)


class FileBlobStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, name: str, data: bytes) -> str:
        target = safe_blob_path(self.root, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        with temporary.open("wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        with suppress(OSError):
            target.chmod(0o600)
        return name

    def get(self, name: str) -> bytes:
        return safe_blob_path(self.root, name).read_bytes()

    def delete(self, name: str) -> bool:
        target = safe_blob_path(self.root, name)
        if not target.exists():
            return False
        target.unlink()
        return True

    def exists(self, name: str) -> bool:
        return safe_blob_path(self.root, name).is_file()
