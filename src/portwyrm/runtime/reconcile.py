"""Atomic immutable-generation reconciliation with last-known-good rollback."""

from __future__ import annotations

import hashlib
import os
import shutil
import threading
import uuid
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol


class ReconcileError(RuntimeError):
    """A candidate generation failed validation, activation, or reload."""


class Validator(Protocol):
    def __call__(self, generation: Path) -> None: ...


class Reloader(Protocol):
    def __call__(self, generation: Path) -> None: ...


LeaseFactory = Callable[[], AbstractContextManager[object]]


@dataclass(frozen=True, slots=True)
class ReconcileResult:
    generation: str
    previous_generation: str | None
    changed: bool
    applied: bool
    diagnostic: str | None = None


class GenerationStore:
    """Filesystem store for immutable config generations and an atomic active manifest."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.generations = self.root / "generations"
        self.active_manifest = self.root / "ACTIVE"
        self.failed = self.root / "failed"
        self.generations.mkdir(parents=True, exist_ok=True)
        self.failed.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def generation_id(files: Mapping[str, str]) -> str:
        digest = hashlib.sha256()
        for name, contents in sorted(files.items()):
            GenerationStore._safe_relative(name)
            digest.update(name.encode())
            digest.update(b"\0")
            digest.update(contents.encode())
            digest.update(b"\0")
        return digest.hexdigest()[:20]

    @staticmethod
    def _safe_relative(name: str) -> PurePosixPath:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ReconcileError(f"unsafe generated path: {name!r}")
        return path

    def stage(self, generation_id: str, files: Mapping[str, str]) -> tuple[Path, bool]:
        final = self.generations / generation_id
        if final.exists():
            return final, False
        temporary = self.generations / f".{generation_id}-{uuid.uuid4().hex}.tmp"
        temporary.mkdir()
        try:
            for name, contents in sorted(files.items()):
                relative = self._safe_relative(name)
                target = temporary.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(contents, encoding="utf-8", newline="\n")
            os.replace(temporary, final)
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        return final, True

    def active_id(self) -> str | None:
        if not self.active_manifest.exists():
            return None
        value = self.active_manifest.read_text(encoding="utf-8").strip()
        return value or None

    def active_path(self) -> Path | None:
        active = self.active_id()
        return self.generations / active if active else None

    def activate(self, generation_id: str) -> None:
        target = self.generations / generation_id
        if not target.is_dir():
            raise ReconcileError(f"generation does not exist: {generation_id}")
        temporary = self.root / f".ACTIVE-{uuid.uuid4().hex}.tmp"
        temporary.write_text(f"{generation_id}\n", encoding="utf-8", newline="\n")
        os.replace(temporary, self.active_manifest)

    def clear_active(self) -> None:
        self.active_manifest.unlink(missing_ok=True)

    def record_failure(self, generation_id: str, diagnostic: str) -> None:
        target = self.failed / f"{generation_id}.txt"
        target.write_text(diagnostic.rstrip() + "\n", encoding="utf-8", newline="\n")


class Reconciler:
    """Serialize, validate, atomically activate, reload, and roll back generations."""

    def __init__(
        self,
        store: GenerationStore,
        *,
        validator: Validator,
        reloader: Reloader,
        lease_factory: LeaseFactory | None = None,
    ) -> None:
        self.store = store
        self.validator = validator
        self.reloader = reloader
        self.lease_factory = lease_factory or nullcontext
        self._lock = threading.Lock()

    def reconcile(self, files: Mapping[str, str]) -> ReconcileResult:
        generation_id = self.store.generation_id(files)
        with self._lock, self.lease_factory():
            previous = self.store.active_id()
            if previous == generation_id:
                return ReconcileResult(generation_id, previous, changed=False, applied=True)

            candidate, _created = self.store.stage(generation_id, files)
            try:
                self.validator(candidate)
            except Exception as exc:
                diagnostic = f"validation failed: {exc}"
                self.store.record_failure(generation_id, diagnostic)
                raise ReconcileError(diagnostic) from exc

            self.store.activate(generation_id)
            try:
                self.reloader(candidate)
            except Exception as exc:
                diagnostic = f"reload failed: {exc}"
                if previous is None:
                    self.store.clear_active()
                else:
                    self.store.activate(previous)
                    try:
                        self.reloader(self.store.generations / previous)
                    except Exception as rollback_exc:
                        diagnostic += f"; rollback reload failed: {rollback_exc}"
                self.store.record_failure(generation_id, diagnostic)
                raise ReconcileError(diagnostic) from exc

            return ReconcileResult(generation_id, previous, changed=True, applied=True)
