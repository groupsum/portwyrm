"""Repository-backed control-plane service."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from portwyrm.persistence import Repository

from .control_plane import COLLECTIONS, Actor, ControlPlane

ChangeHook = Callable[[str], Any]


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

    def reload(self) -> None:
        """Replace the in-memory projection after an external import transaction."""
        with self._lock:
            self.resources = {name: {} for name in COLLECTIONS}
            self._next_ids = {name: 1 for name in COLLECTIONS}
            self.audit_events = []
            self._passwords = {}
            self._hydrate()
        if self.on_change is not None:
            self.on_change("settings")

    def _persist_resource(
        self, collection: str, resource_id: int | str, actor: Actor | None = None
    ) -> None:
        with self.repository.transaction() as tx:
            tx.upsert(self._storage_collection(collection), self.resources[collection][resource_id])
            if self.audit_events:
                tx.upsert("_audit", self.audit_events[-1])
        if self.on_change is not None:
            result = self.on_change(collection)
            generation = getattr(result, "generation", None)
            if generation is not None:
                self.record_event(
                    "configuration.applied",
                    collection,
                    resource_id,
                    details={
                        "snapshot": self.resources[collection][resource_id],
                        "generation": str(generation),
                    },
                    actor=actor,
                )

    def _persist_credentials(self) -> None:
        with self.repository.transaction() as tx:
            stored = {str(row["id"]) for row in tx.list("_credentials")}
            for identity, password_hash in self._passwords.items():
                tx.upsert("_credentials", {"id": identity, "password_hash": password_hash})
            for identity in stored - self._passwords.keys():
                tx.delete("_credentials", identity)

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
        self._persist_resource(collection, row["id"], actor)
        if collection == "users":
            self._persist_credentials()
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
        self._persist_resource(collection, resource_id, actor)
        if collection == "users":
            self._persist_credentials()
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
        self._persist_resource(collection, resource_id, actor)
        if collection == "users":
            identity = str(self.resources[collection][resource_id].get("email", "")).casefold()
            self._passwords.pop(identity, None)
            self._persist_credentials()
        return result

    def set_password(self, user_id: int | str, password: str) -> None:
        super().set_password(user_id, password)
        self._persist_credentials()

    def record_event(
        self,
        action: str,
        object_type: str,
        object_id: int | str,
        *,
        details: dict[str, Any] | None = None,
        actor: Actor | None = None,
    ) -> None:
        super().record_event(action, object_type, object_id, details=details, actor=actor)
        with self.repository.transaction() as tx:
            tx.upsert("_audit", self.audit_events[-1])

    def bootstrap_admin(self, email: str, password: str) -> dict[str, Any]:
        user = super().bootstrap_admin(email, password)
        self._persist_credentials()
        return user
