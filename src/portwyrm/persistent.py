"""Repository-backed control-plane service."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from portwyrm.persistence import Repository
from portwyrm.service import COLLECTIONS, Actor, ControlPlane

ChangeHook = Callable[[str], None]


class PersistentControlPlane(ControlPlane):
    """ControlPlane with durable records and post-commit change notification."""

    def __init__(self, repository: Repository, *, on_change: ChangeHook | None = None) -> None:
        super().__init__()
        self.repository = repository
        self.on_change = on_change
        self._hydrate()

    @staticmethod
    def _storage_collection(collection: str) -> str:
        return collection.replace("-", "_")

    def _hydrate(self) -> None:
        with self.repository.transaction() as tx:
            for collection in COLLECTIONS:
                for row in tx.list(self._storage_collection(collection)):
                    resource_id = row["id"]
                    self.resources[collection][resource_id] = row
                    if isinstance(resource_id, int):
                        self._next_ids[collection] = max(
                            self._next_ids[collection], resource_id + 1
                        )
            self.audit_events = tx.list("_audit")
            self.audit_events.sort(key=lambda item: int(item["id"]))
            self._passwords = {
                str(row["id"]): str(row["password_hash"]) for row in tx.list("_credentials")
            }

    def _persist_resource(self, collection: str, resource_id: int | str) -> None:
        with self.repository.transaction() as tx:
            tx.upsert(self._storage_collection(collection), self.resources[collection][resource_id])
            if self.audit_events:
                tx.upsert("_audit", self.audit_events[-1])
        if self.on_change is not None:
            self.on_change(collection)

    def create(
        self,
        collection: str,
        payload: dict[str, Any],
        *,
        actor: Actor | None = None,
        preserve_id: bool = False,
    ) -> dict[str, Any]:
        if collection == "settings" and isinstance(payload.get("id"), str):
            preserve_id = True
        row = super().create(collection, payload, actor=actor, preserve_id=preserve_id)
        self._persist_resource(collection, row["id"])
        return row

    def update(
        self,
        collection: str,
        resource_id: int | str,
        payload: dict[str, Any],
        *,
        actor: Actor | None = None,
        adopt: bool = False,
    ) -> dict[str, Any]:
        row = super().update(collection, resource_id, payload, actor=actor, adopt=adopt)
        self._persist_resource(collection, resource_id)
        return row

    def delete(
        self,
        collection: str,
        resource_id: int | str,
        *,
        actor: Actor | None = None,
        prune: bool = False,
    ) -> bool:
        result = super().delete(collection, resource_id, actor=actor, prune=prune)
        self._persist_resource(collection, resource_id)
        return result

    def bootstrap_admin(self, email: str, password: str) -> dict[str, Any]:
        user = super().bootstrap_admin(email, password)
        normalized = email.strip().casefold()
        with self.repository.transaction() as tx:
            tx.upsert(
                "_credentials",
                {"id": normalized, "password_hash": self._passwords[normalized]},
            )
        return user
