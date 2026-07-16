"""Filesystem publication helpers with no control-plane state."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from .hooks import NginxCommandHooks
from .reconcile import GenerationStore, Reconciler


def build_reconciler(root: Path, *, validate: bool, reload: bool) -> Reconciler:
    hooks = NginxCommandHooks()
    validator = hooks.validate if validate else (lambda _path: None)

    def publish(generation: Path) -> None:
        current = root / "current"
        if os.name != "nt":
            temporary = root / f".current-{os.getpid()}"
            temporary.unlink(missing_ok=True)
            temporary.symlink_to(generation.resolve(), target_is_directory=True)
            if current.is_dir() and not current.is_symlink():
                shutil.rmtree(current)
            os.replace(temporary, current)
        else:
            temporary = root / f".current-{os.getpid()}"
            if temporary.exists():
                shutil.rmtree(temporary)
            shutil.copytree(generation, temporary)
            if current.exists():
                shutil.rmtree(current)
            os.replace(temporary, current)

    def reload_generation(generation: Path) -> None:
        publish(generation)
        hooks.reload(root / "current")

    return Reconciler(
        GenerationStore(root),
        validator=validator,
        reloader=reload_generation if reload else publish,
    )


__all__ = ["build_reconciler"]
