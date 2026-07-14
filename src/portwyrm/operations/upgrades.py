"""Ordered, transactional application data upgrades."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from portwyrm.persistence import Repository


@dataclass(frozen=True, order=True)
class Upgrade:
    version: int
    name: str
    apply: Callable[[object], None]


class UpgradeManager:
    def __init__(self, repository: Repository, upgrades: Iterable[Upgrade]) -> None:
        self.repository = repository
        self.upgrades = sorted(upgrades)
        versions = [item.version for item in self.upgrades]
        if len(versions) != len(set(versions)):
            raise ValueError("upgrade versions must be unique")

    def pending(self) -> list[Upgrade]:
        with self.repository.transaction() as tx:
            applied = {int(record["id"]) for record in tx.list("system_migrations")}
        return [upgrade for upgrade in self.upgrades if upgrade.version not in applied]

    def run(self) -> list[int]:
        applied: list[int] = []
        for upgrade in self.pending():
            with self.repository.transaction() as tx:
                upgrade.apply(tx)
                tx.upsert(
                    "system_migrations",
                    {"id": upgrade.version, "name": upgrade.name},
                )
            applied.append(upgrade.version)
        return applied
