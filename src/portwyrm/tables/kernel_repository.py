"""Compatibility-shaped state access backed by Tigrbl kernel transactions."""

from __future__ import annotations

import copy
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from threading import RLock
from typing import Any

from portwyrm.persistence.base import MappingTransaction, Resource

from .control_plane_store import (
    load_control_plane_state,
    persist_audit_event,
    persist_control_plane_resource,
)
from .models import (
    PORTWYRM_TABLES,
    BrowserSession,
    MFAEnrollment,
    MFARecoveryCode,
    PersonalAccessToken,
    Principal,
)
from .unit_of_work import KernelUnitOfWork

CONTROL_COLLECTIONS = {
    "users": "users",
    "access_lists": "access-lists",
    "certificates": "certificates",
    "proxy_hosts": "proxy-hosts",
    "redirection_hosts": "redirection-hosts",
    "dead_hosts": "dead-hosts",
    "streams": "streams",
    "settings": "settings",
}
READ_ONLY_COLLECTIONS = {
    "access_tokens",
    "_personal_access_tokens",
    "_sessions",
    "_mfa",
}


class _KernelMappingTransaction(MappingTransaction):
    def __init__(self, state: dict[str, dict[str, Resource]]) -> None:
        super().__init__(state)
        self.dirty_collections: set[str] = set()

    def upsert(self, collection: str, resource: Mapping[str, Any]) -> Resource:
        self.dirty_collections.add(collection)
        return super().upsert(collection, resource)

    def delete(self, collection: str, resource_id: str | int) -> bool:
        deleted = super().delete(collection, resource_id)
        if deleted:
            self.dirty_collections.add(collection)
        return deleted


class KernelRepository:
    """Narrow portability adapter; all database work is kernel-owned."""

    def __init__(self, app: Any, *, backend_name: str) -> None:
        self.backend_name = backend_name
        self.uow = KernelUnitOfWork(app)
        self._lock = RLock()

    def has_state(self) -> bool:
        return self.uow.run_sync(
            lambda db: any(db.query(model).first() is not None for model in PORTWYRM_TABLES)
        )

    @contextmanager
    def transaction(self) -> Iterator[_KernelMappingTransaction]:
        with self._lock:
            state = self.uow.run_sync(export_compatibility_state)
            transaction = _KernelMappingTransaction(copy.deepcopy(state))
            yield transaction
            if transaction.dirty_collections:
                self.uow.run_sync(
                    lambda db: apply_compatibility_changes(
                        db, transaction.state, transaction.dirty_collections
                    )
                )


def export_compatibility_state(session: Any) -> dict[str, dict[str, Resource]]:
    state = load_control_plane_state(session)
    principals = {row.id: row for row in session.query(Principal).all()}
    pats: list[dict[str, Any]] = []
    for pat in session.query(PersonalAccessToken).all():
        metadata = pat.metadata_json if isinstance(pat.metadata_json, dict) else {}
        compat = metadata.get("compat") if isinstance(metadata.get("compat"), dict) else {}
        row = copy.deepcopy(compat)
        principal = principals.get(pat.principal_id)
        row.update(
            id=pat.token_prefix,
            name=pat.name,
            token_hash=pat.token_digest,
            created_at=metadata.get("created_at", row.get("created_at", 0)),
            expires_at=pat.expires_at,
            last_used_at=pat.last_used_at,
            revoked_at=pat.revoked_at,
        )
        if "principal" not in row and principal is not None:
            principal_meta = (
                principal.metadata_json if isinstance(principal.metadata_json, dict) else {}
            )
            principal_compat = principal_meta.get("compat", {})
            row["principal"] = {
                "user_id": principal.id,
                "identity": principal.email,
                "is_admin": bool(principal.is_admin),
                "permissions": (
                    principal_compat.get("permissions", {})
                    if isinstance(principal_compat, dict)
                    else {}
                ),
                "visibility": principal.visibility,
                "scopes": list(pat.scopes or ["user"]),
                "owner": None,
            }
        pats.append(row)
    state["_personal_access_tokens"] = _bucket(pats)
    state["_sessions"] = _bucket(
        [
            {
                "id": item.token_id,
                "token_hash": item.token_digest,
                "principal": item.principal_snapshot,
                "expires": item.expires_at,
            }
            for item in session.query(BrowserSession).all()
        ]
    )
    enrollments = session.query(MFAEnrollment).all()
    recovery = session.query(MFARecoveryCode).all()
    state["_mfa"] = _bucket(
        [
            {
                "id": str(item.principal_id),
                "secret_ciphertext": item.encrypted_secret,
                "backup_hashes": [
                    code.code_digest
                    for code in recovery
                    if code.enrollment_id == item.id and code.used_at is None
                ],
                "active": bool(item.confirmed),
            }
            for item in enrollments
        ]
    )
    return state


def apply_compatibility_changes(
    session: Any,
    state: Mapping[str, Mapping[str, Resource]],
    dirty_collections: set[str],
) -> None:
    unsupported = dirty_collections - (
        set(CONTROL_COLLECTIONS)
        | {"_credentials", "_audit", "audit_log"}
        | READ_ONLY_COLLECTIONS
    )
    if unsupported:
        raise ValueError(f"unsupported compatibility collection: {sorted(unsupported)[0]}")
    forbidden = dirty_collections & READ_ONLY_COLLECTIONS
    if forbidden:
        raise ValueError(
            f"identity collection is managed by its Tigrbl service: {sorted(forbidden)[0]}"
        )

    passwords = {
        str(row["id"]).casefold(): str(row["password_hash"])
        for row in state.get("_credentials", {}).values()
    }
    collections = set(dirty_collections) & set(CONTROL_COLLECTIONS)
    if "_credentials" in dirty_collections:
        collections.add("users")
    ordered = (
        "users",
        "certificates",
        "access_lists",
        "proxy_hosts",
        "redirection_hosts",
        "dead_hosts",
        "streams",
        "settings",
    )
    for storage in ordered:
        if storage not in collections:
            continue
        collection = CONTROL_COLLECTIONS[storage]
        for row in state.get(storage, {}).values():
            persist_control_plane_resource(session, collection, row, passwords)
    for storage in ("_audit", "audit_log"):
        if storage in dirty_collections:
            for row in state.get(storage, {}).values():
                persist_audit_event(session, row)


def _bucket(rows: list[dict[str, Any]]) -> dict[str, Resource]:
    return {str(row["id"]): row for row in rows}
