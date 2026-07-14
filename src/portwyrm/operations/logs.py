"""Bounded local log rotation."""

from __future__ import annotations

from pathlib import Path


class LogRotator:
    def __init__(self, path: str | Path, *, max_bytes: int = 10_000_000, backups: int = 5) -> None:
        if max_bytes <= 0 or backups < 0:
            raise ValueError("max_bytes must be positive and backups non-negative")
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.backups = backups

    def rotate_if_needed(self) -> bool:
        if not self.path.exists() or self.path.stat().st_size < self.max_bytes:
            return False
        if self.backups == 0:
            self.path.unlink()
            return True
        oldest = self.path.with_name(f"{self.path.name}.{self.backups}")
        if oldest.exists():
            oldest.unlink()
        for index in range(self.backups - 1, 0, -1):
            source = self.path.with_name(f"{self.path.name}.{index}")
            if source.exists():
                source.replace(self.path.with_name(f"{self.path.name}.{index + 1}"))
        self.path.replace(self.path.with_name(f"{self.path.name}.1"))
        return True
