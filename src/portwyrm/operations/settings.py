"""Typed settings stored through the active repository."""

from __future__ import annotations

from typing import Any

from portwyrm.persistence import Repository


class Settings:
    def __init__(self, repository: Repository) -> None:
        self.repository = repository

    def get(self, setting_id: str, default: Any = None) -> Any:
        with self.repository.transaction() as tx:
            record = tx.get("settings", setting_id)
        return default if record is None else record.get("value")

    def set(self, setting_id: str, value: Any, *, description: str | None = None) -> dict[str, Any]:
        record = {"id": setting_id, "value": value}
        if description is not None:
            record["description"] = description
        with self.repository.transaction() as tx:
            return tx.upsert("settings", record)

    def all(self) -> list[dict[str, Any]]:
        with self.repository.transaction() as tx:
            return tx.list("settings")
