"""Control-plane domain service persisted by Tigrbl kernel transactions."""

from __future__ import annotations

import copy
from typing import Any

from portwyrm.tables import KernelUnitOfWork
from portwyrm.tables.control_plane_store import (
    load_control_plane_state,
    persist_audit_event,
    persist_control_plane_resource,
)

from .control_plane import COLLECTIONS, Actor, ControlPlane


class KernelControlPlane(ControlPlane):
    """Preserve domain validation while the kernel owns every persistence transaction."""

    def __init__(self, app: Any, *, on_change: Any = None) -> None:
        super().__init__()
        self.app = app
        self.uow = KernelUnitOfWork(app)
        self.on_change = on_change
        self.reload()

    def reload(self) -> None:
        def read(db: Any) -> dict[str, dict[str, dict[str, Any]]]:
            return load_control_plane_state(db)

        state = self.uow.run_sync(read)
        with self._lock:
            self.resources = {name: {} for name in COLLECTIONS}
            self._next_ids = {name: 1 for name in COLLECTIONS}
            for collection in COLLECTIONS:
                storage = collection.replace("-", "_")
                for row in state.get(storage, {}).values():
                    resource_id = row["id"]
                    self.resources[collection][resource_id] = copy.deepcopy(row)
                    if isinstance(resource_id, int):
                        self._next_ids[collection] = max(
                            self._next_ids[collection], resource_id + 1
                        )
            self.audit_events = list(state.get("_audit", {}).values())
            self.audit_events.sort(key=lambda item: int(item["id"]))
            self._passwords = {
                str(row["id"]): str(row["password_hash"])
                for row in state.get("_credentials", {}).values()
            }

    def _persist_resource(self, collection: str, resource_id: int | str) -> None:
        def write(db: Any) -> None:
            persist_control_plane_resource(
                db,
                collection,
                self.resources[collection][resource_id],
                self._passwords,
            )
            if self.audit_events:
                persist_audit_event(db, self.audit_events[-1])

        self.uow.run_sync(write)

    def _persist_last_event(self) -> None:
        if not self.audit_events:
            return
        self.uow.run_sync(lambda db: persist_audit_event(db, self.audit_events[-1]))

    def create(
        self,
        collection: str,
        payload: dict[str, Any],
        *,
        actor: Actor | None = None,
        preserve_id: bool = False,
    ) -> dict[str, Any]:
        row = super().create(collection, payload, actor=actor, preserve_id=preserve_id)
        self._persist_resource(collection, row["id"])
        self._changed(collection)
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
        self._changed(collection)
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
        if collection == "users":
            email = str(self.resources[collection][resource_id].get("email", "")).casefold()
            self._passwords.pop(email, None)
        self._persist_resource(collection, resource_id)
        self._changed(collection)
        return result

    def set_password(self, user_id: int | str, password: str) -> None:
        super().set_password(user_id, password)
        self._persist_resource("users", user_id)

    def change_password(self, user_id: int | str, current: str, password: str) -> None:
        super().change_password(user_id, current, password)

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
        self._persist_last_event()

    def bootstrap_admin(self, email: str, password: str) -> dict[str, Any]:
        user = super().bootstrap_admin(email, password)
        self._persist_resource("users", user["id"])
        return user

    def _changed(self, collection: str) -> None:
        if self.on_change is not None:
            self.on_change(collection)
