"""Application service for NPM-shaped resources and ownership-safe mutations."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import RLock
from typing import Any

import bcrypt
from argon2 import PasswordHasher

from portwyrm.domain.routing import AccessClient, ProxyLocation, canonical_domains
from portwyrm.identity import PERMISSION_ACTIONS
from portwyrm.security import Principal

PERMISSION_SECTIONS = frozenset(
    {
        "proxy_hosts",
        "redirection_hosts",
        "dead_hosts",
        "streams",
        "access_lists",
        "certificates",
    }
)


class ControlPlaneError(Exception):
    """Base application error with an HTTP-compatible status."""

    status_code = 400


class NotFound(ControlPlaneError):
    status_code = 404


class Conflict(ControlPlaneError):
    status_code = 409


class Forbidden(ControlPlaneError):
    status_code = 403


HOST_COLLECTIONS = {"proxy-hosts", "redirection-hosts", "dead-hosts"}
COLLECTIONS = {
    *HOST_COLLECTIONS,
    "streams",
    "access-lists",
    "certificates",
    "users",
    "settings",
    "access-tokens",
}


def _domains(payload: dict[str, Any]) -> set[str]:
    return {str(value).strip().casefold() for value in payload.get("domain_names", [])}


def _managed_owner(payload: dict[str, Any]) -> tuple[str | None, str | None]:
    meta = payload.get("meta")
    if not isinstance(meta, dict):
        return None, None
    return meta.get("managed_by"), meta.get("owner")


@dataclass(slots=True)
class Actor:
    id: int
    email: str
    is_admin: bool = False
    owner: str | None = None


@dataclass
class ControlPlane:
    """Thread-safe desired-state service with stable IDs and immutable audit records."""

    resources: dict[str, dict[int | str, dict[str, Any]]] = field(
        default_factory=lambda: {name: {} for name in COLLECTIONS}
    )
    audit_events: list[dict[str, Any]] = field(default_factory=list)
    _next_ids: dict[str, int] = field(default_factory=lambda: {name: 1 for name in COLLECTIONS})
    _lock: RLock = field(default_factory=RLock)
    _passwords: dict[str, str] = field(default_factory=dict)
    _password_hasher: PasswordHasher = field(default_factory=PasswordHasher)

    def bootstrap_admin(self, email: str, password: str) -> dict[str, Any]:
        """Create the first administrator; later bootstrap attempts fail closed."""
        normalized = email.strip().casefold()
        if not normalized or not password:
            raise ControlPlaneError("email and password are required")
        with self._lock:
            if self.resources["users"]:
                raise Conflict("initial administrator already exists")
            user = self.create(
                "users",
                {
                    "email": normalized,
                    "name": "Administrator",
                    "nickname": "Admin",
                    "is_admin": 1,
                    "is_disabled": 0,
                    "permissions": {},
                    "visibility": "all",
                },
            )
            self._passwords[normalized] = self._password_hasher.hash(password)
            return user

    def authenticate(self, identity: str, secret: str) -> Principal | None:
        normalized = identity.strip().casefold()
        encoded = self._passwords.get(normalized)
        if encoded is None:
            return None
        try:
            if encoded.startswith(("$2a$", "$2b$", "$2y$")):
                if not bcrypt.checkpw(secret.encode(), encoded.encode()):
                    return None
            else:
                self._password_hasher.verify(encoded, secret)
        except Exception:  # argon2 deliberately has several mismatch subclasses
            return None
        user = next(
            (
                row
                for row in self.resources["users"].values()
                if row.get("email", "").casefold() == normalized
                and not row.get("is_deleted")
                and not row.get("is_disabled")
            ),
            None,
        )
        if user is None:
            return None
        return Principal(
            user_id=user["id"],
            identity=normalized,
            is_admin=bool(user.get("is_admin")),
            permissions=dict(user.get("permissions", {})),
            visibility="all" if user.get("visibility") == "all" else "user",
        )

    def set_password(self, user_id: int | str, password: str) -> None:
        """Set a user's password without ever placing it in a resource record."""
        if len(password) < 8:
            raise ControlPlaneError("password must contain at least 8 characters")
        user = self.get("users", user_id)
        email = str(user["email"]).strip().casefold()
        self._passwords[email] = self._password_hasher.hash(password)

    def change_password(self, user_id: int | str, current: str, password: str) -> None:
        user = self.get("users", user_id)
        if self.authenticate(str(user["email"]), current) is None:
            raise Forbidden("current password is invalid")
        self.set_password(user_id, password)

    def access_list_credential(self, user_id: int | str) -> tuple[str, str]:
        """Return an identity's Nginx credential internally without exposing it via the API."""
        user = self.get("users", user_id)
        email = str(user["email"]).strip().casefold()
        encoded = self._passwords.get(email)
        if encoded is None:
            raise Conflict(f"user {user_id!r} does not have an active password")
        username = str(user.get("nickname") or email.split("@", 1)[0]).lstrip("@")
        return username, encoded

    @staticmethod
    def _compat_collection(collection: str) -> str:
        return collection.replace("_", "-")

    def list_resources(self, collection: str) -> list[dict[str, Any]]:
        return self.list(self._compat_collection(collection))

    def get_resource(self, collection: str, resource_id: int | str) -> dict[str, Any] | None:
        try:
            return self.get(self._compat_collection(collection), resource_id)
        except NotFound:
            return None

    def create_resource(self, collection: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self.create(self._compat_collection(collection), payload)

    def update_resource(
        self, collection: str, resource_id: int | str, payload: dict[str, Any]
    ) -> dict[str, Any] | None:
        try:
            return self.update(self._compat_collection(collection), resource_id, payload)
        except NotFound:
            return None

    def delete_resource(self, collection: str, resource_id: int | str) -> bool:
        try:
            return self.delete(self._compat_collection(collection), resource_id)
        except NotFound:
            return False

    def list_audit(self, since: str | None = None) -> list[dict[str, Any]]:
        return self.audit_since(since)

    def list(self, collection: str, *, actor: Actor | None = None) -> list[dict[str, Any]]:
        with self._lock:
            rows = list(self._bucket(collection).values())
            visible = [row for row in rows if not row.get("is_deleted")]
            if actor and not actor.is_admin and actor.owner:
                visible = [row for row in visible if _managed_owner(row)[1] == actor.owner]
            return deepcopy(visible)

    def get(
        self, collection: str, resource_id: int | str, *, actor: Actor | None = None
    ) -> dict[str, Any]:
        with self._lock:
            row = self._bucket(collection).get(resource_id)
            if row is None or row.get("is_deleted"):
                raise NotFound(f"{collection} resource {resource_id!r} was not found")
            self._check_visible(row, actor)
            return deepcopy(row)

    def create(
        self,
        collection: str,
        payload: dict[str, Any],
        *,
        actor: Actor | None = None,
        preserve_id: bool = False,
    ) -> dict[str, Any]:
        password = payload.get("password") if collection == "users" else None
        clean_payload = deepcopy(payload)
        if collection == "users":
            clean_payload.pop("password", None)
            clean_payload.pop("secret", None)
            clean_payload["email"] = str(clean_payload.get("email", "")).strip().casefold()
        with self._lock:
            self._validate(collection, clean_payload)
            bucket = self._bucket(collection)
            requested = clean_payload.get("id") if preserve_id else None
            resource_id: int | str
            if collection == "settings" and isinstance(requested, str):
                resource_id = requested
            elif requested is not None:
                resource_id = int(requested)
                if resource_id <= 0:
                    raise Conflict("resource IDs must be positive")
            else:
                resource_id = self._next_ids[collection]
            if resource_id in bucket:
                raise Conflict(f"{collection} resource {resource_id!r} already exists")
            if collection == "users" and any(
                str(item.get("email", "")).casefold() == clean_payload["email"]
                and not item.get("is_deleted")
                for item in bucket.values()
            ):
                raise Conflict("email is already in use")
            self._assert_domains_available(collection, clean_payload)
            row = deepcopy(clean_payload)
            row["id"] = resource_id
            now = datetime.now(UTC).isoformat()
            row.setdefault("created_on", now)
            row["modified_on"] = now
            bucket[resource_id] = row
            if isinstance(resource_id, int):
                self._next_ids[collection] = max(self._next_ids[collection], resource_id + 1)
            self._audit("created", collection, row, actor)
            if isinstance(password, str) and password:
                self.set_password(resource_id, password)
            return deepcopy(row)

    def update(
        self,
        collection: str,
        resource_id: int | str,
        payload: dict[str, Any],
        *,
        actor: Actor | None = None,
        adopt: bool = False,
    ) -> dict[str, Any]:
        password = payload.get("password") if collection == "users" else None
        clean_payload = deepcopy(payload)
        clean_payload.pop("password", None)
        clean_payload.pop("secret", None)
        with self._lock:
            bucket = self._bucket(collection)
            current = bucket.get(resource_id)
            if current is None or current.get("is_deleted"):
                raise NotFound(f"{collection} resource {resource_id!r} was not found")
            self._check_visible(current, actor)
            self._check_ownership(current, clean_payload, actor, adopt)
            candidate = deepcopy(current)
            candidate.update(clean_payload)
            candidate["id"] = resource_id
            previous_email = str(current.get("email", "")).casefold()
            if collection == "users":
                candidate["email"] = str(candidate.get("email", "")).strip().casefold()
                if any(
                    other_id != resource_id
                    and str(item.get("email", "")).casefold() == candidate["email"]
                    and not item.get("is_deleted")
                    for other_id, item in bucket.items()
                ):
                    raise Conflict("email is already in use")
            self._validate(collection, candidate)
            self._assert_domains_available(collection, candidate, exclude=(collection, resource_id))
            candidate["modified_on"] = datetime.now(UTC).isoformat()
            bucket[resource_id] = candidate
            if collection == "users" and previous_email != candidate["email"]:
                encoded = self._passwords.pop(previous_email, None)
                if encoded is not None:
                    self._passwords[candidate["email"]] = encoded
            self._audit("updated", collection, candidate, actor)
            if isinstance(password, str) and password:
                self.set_password(resource_id, password)
            return deepcopy(candidate)

    def delete(
        self,
        collection: str,
        resource_id: int | str,
        *,
        actor: Actor | None = None,
        prune: bool = False,
    ) -> bool:
        with self._lock:
            bucket = self._bucket(collection)
            row = bucket.get(resource_id)
            if row is None or row.get("is_deleted"):
                raise NotFound(f"{collection} resource {resource_id!r} was not found")
            self._check_visible(row, actor)
            managed_by, owner = _managed_owner(row)
            if actor and actor.owner and (managed_by, owner) != ("npmctl", actor.owner):
                if prune:
                    raise Conflict("foreign-owned resources cannot be pruned")
                raise Forbidden("resource is owned by another controller")
            row["is_deleted"] = True
            row["modified_on"] = datetime.now(UTC).isoformat()
            self._audit("deleted", collection, row, actor)
            return True

    def toggle(
        self,
        collection: str,
        resource_id: int | str,
        enabled: bool,
        *,
        actor: Actor | None = None,
    ) -> dict[str, Any]:
        return self.update(collection, resource_id, {"enabled": int(enabled)}, actor=actor)

    def audit_since(self, since: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if since is None:
                return deepcopy(self.audit_events)
            return deepcopy([event for event in self.audit_events if event["created_on"] >= since])

    def record_event(
        self,
        action: str,
        object_type: str,
        object_id: int | str,
        *,
        details: dict[str, Any] | None = None,
        actor: Actor | None = None,
    ) -> None:
        self._audit(action, object_type, {"id": object_id, **(details or {})}, actor)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {name: self.list(name) for name in sorted(COLLECTIONS)}

    def _bucket(self, collection: str) -> dict[int | str, dict[str, Any]]:
        try:
            return self.resources[collection]
        except KeyError as exc:
            raise NotFound(f"unknown collection {collection!r}") from exc

    def _validate(self, collection: str, payload: dict[str, Any]) -> None:
        if not isinstance(payload, dict):
            raise ControlPlaneError("payload must be an object")
        if collection == "users":
            permissions = payload.get("permissions", {})
            if not isinstance(permissions, dict):
                raise ControlPlaneError("permissions must be an object")
            unknown_sections = set(permissions) - PERMISSION_SECTIONS
            if unknown_sections:
                raise ControlPlaneError(
                    f"unknown permission section: {sorted(unknown_sections)[0]}"
                )
            for section, grant in permissions.items():
                if isinstance(grant, str) and grant in {"hidden", "view", "manage"}:
                    continue
                if not isinstance(grant, dict):
                    raise ControlPlaneError(f"permission {section} must be a level or CRUD object")
                unknown_actions = set(grant) - set(PERMISSION_ACTIONS)
                if unknown_actions:
                    raise ControlPlaneError(
                        f"unknown permission action: {sorted(unknown_actions)[0]}"
                    )
                if any(type(value) is not bool for value in grant.values()):
                    raise ControlPlaneError(f"permission {section} actions must be booleans")
        if collection in HOST_COLLECTIONS:
            domains = payload.get("domain_names", [])
            if not isinstance(domains, list) or not 1 <= len(domains) <= 100:
                raise ControlPlaneError("domain_names must contain between 1 and 100 entries")
            if len(_domains(payload)) != len(domains):
                raise Conflict("domain_names must be unique")
            try:
                canonical_domains(domains)
            except ValueError as exc:
                raise ControlPlaneError(str(exc)) from exc
        if collection == "proxy-hosts":
            port = int(payload.get("forward_port", 0))
            if not 1 <= port <= 65535:
                raise ControlPlaneError("forward_port must be between 1 and 65535")
            if payload.get("forward_scheme") not in {"http", "https"}:
                raise ControlPlaneError("forward_scheme must be http or https")
            if not str(payload.get("forward_host", "")).strip():
                raise ControlPlaneError("forward_host is required")
            locations = payload.get("locations", payload.get("custom_locations", []))
            if not isinstance(locations, list):
                raise ControlPlaneError("locations must be an array")
            try:
                for item in locations:
                    if not isinstance(item, dict):
                        raise ValueError("locations must contain objects")
                    ProxyLocation(
                        str(item.get("path", "")),
                        str(item.get("forward_scheme", "http")),
                        str(item.get("forward_host", "")),
                        int(item.get("forward_port", 0)),
                        str(item.get("forward_path", "")),
                        str(item.get("advanced_config", "")),
                    )
            except (TypeError, ValueError) as exc:
                raise ControlPlaneError(str(exc)) from exc
        if collection == "redirection-hosts":
            if not str(payload.get("forward_domain_name", "")).strip():
                raise ControlPlaneError("forward_domain_name is required")
            if payload.get("forward_scheme", "auto") not in {"auto", "http", "https"}:
                raise ControlPlaneError("forward_scheme must be auto, http, or https")
            code = int(payload.get("forward_http_code", 301))
            if not 300 <= code <= 308:
                raise ControlPlaneError("forward_http_code must be between 300 and 308")
        if collection == "streams":
            for key in ("incoming_port", "forwarding_port"):
                if not 1 <= int(payload.get(key, 0)) <= 65535:
                    raise ControlPlaneError(f"{key} must be between 1 and 65535")
            if not str(payload.get("forwarding_host", "")).strip():
                raise ControlPlaneError("forwarding_host is required")
            if not payload.get("tcp_forwarding") and not payload.get("udp_forwarding"):
                raise ControlPlaneError("at least one stream protocol must be enabled")
            if payload.get("certificate_id") and not payload.get("tcp_forwarding"):
                raise ControlPlaneError("stream TLS is supported only for TCP")
        if collection == "access-lists":
            if not str(payload.get("name", "")).strip():
                raise ControlPlaneError("access-list name is required")
            clients = payload.get("clients", [])
            if not isinstance(clients, list):
                raise ControlPlaneError("access-list clients must be an array")
            try:
                for item in clients:
                    if not isinstance(item, dict):
                        raise ValueError("access-list clients must contain objects")
                    AccessClient(str(item.get("address", "")), str(item.get("directive", "")))
            except (TypeError, ValueError) as exc:
                raise ControlPlaneError(str(exc)) from exc
            raw_identity_ids = payload.get("identity_ids", [])
            if not isinstance(raw_identity_ids, list):
                raise ControlPlaneError("access-list identity_ids must be an array")
            try:
                identity_ids = [int(value) for value in raw_identity_ids]
            except (TypeError, ValueError) as exc:
                raise ControlPlaneError(
                    "access-list identity_ids must contain integer IDs"
                ) from exc
            if any(value <= 0 for value in identity_ids) or len(identity_ids) != len(
                set(identity_ids)
            ):
                raise ControlPlaneError("access-list identity_ids must contain unique positive IDs")
            for identity_id in identity_ids:
                if (
                    identity_id not in self.resources["users"]
                    or self.resources["users"][identity_id].get("is_deleted")
                    or self.resources["users"][identity_id].get("is_disabled")
                ):
                    raise Conflict(f"identity_ids contains inactive user {identity_id}")
        if collection in HOST_COLLECTIONS | {"streams"}:
            for field in ("certificate_id",):
                certificate_id = int(payload.get(field) or 0)
                if certificate_id and (
                    certificate_id not in self.resources["certificates"]
                    or self.resources["certificates"][certificate_id].get("is_deleted")
                ):
                    raise Conflict(f"{field} does not resolve to an active certificate")
        if collection == "proxy-hosts":
            raw_access_ids = payload.get("access_list_ids")
            if raw_access_ids is None:
                raw_access_ids = (
                    [payload.get("access_list_id")] if payload.get("access_list_id") else []
                )
            if not isinstance(raw_access_ids, list):
                raise ControlPlaneError("access_list_ids must be an array")
            try:
                access_ids = [int(value) for value in raw_access_ids]
            except (TypeError, ValueError) as exc:
                raise ControlPlaneError("access_list_ids must contain integer IDs") from exc
            if any(value <= 0 for value in access_ids) or len(access_ids) != len(set(access_ids)):
                raise ControlPlaneError("access_list_ids must contain unique positive IDs")
            for access_id in access_ids:
                if (
                    access_id not in self.resources["access-lists"]
                    or self.resources["access-lists"][access_id].get("is_deleted")
                ):
                    raise Conflict(
                        f"access_list_ids contains inactive access list {access_id}"
                    )
        if collection == "users" and not str(payload.get("email", "")).strip():
            raise ControlPlaneError("email is required")

    def _assert_domains_available(
        self,
        collection: str,
        payload: dict[str, Any],
        *,
        exclude: tuple[str, int | str] | None = None,
    ) -> None:
        if collection not in HOST_COLLECTIONS:
            return
        candidate = _domains(payload)
        for family in HOST_COLLECTIONS:
            for row_id, row in self.resources[family].items():
                if (
                    exclude == (family, row_id)
                    or row.get("is_deleted")
                    or not row.get("enabled", 1)
                ):
                    continue
                if candidate & _domains(row):
                    raise Conflict("domain already belongs to an active host")

    @staticmethod
    def _check_visible(row: dict[str, Any], actor: Actor | None) -> None:
        if not actor or actor.is_admin or not actor.owner:
            return
        if _managed_owner(row)[1] != actor.owner:
            raise NotFound("resource was not found")

    @staticmethod
    def _check_ownership(
        current: dict[str, Any],
        proposed: dict[str, Any],
        actor: Actor | None,
        adopt: bool,
    ) -> None:
        if not actor or not actor.owner:
            return
        managed_by, owner = _managed_owner(current)
        if (managed_by, owner) == ("npmctl", actor.owner):
            return
        proposed_owner = _managed_owner(proposed)
        if adopt and proposed_owner == ("npmctl", actor.owner):
            return
        raise Conflict("foreign or unmanaged resource requires explicit adoption")

    def _audit(
        self, action: str, collection: str, row: dict[str, Any], actor: Actor | None
    ) -> None:
        redacted = _redact(row)
        self.audit_events.append(
            {
                "id": len(self.audit_events) + 1,
                "created_on": datetime.now(UTC).isoformat(),
                "action": action,
                "object_type": collection,
                "object_id": row["id"],
                "user_id": actor.id if actor else None,
                "meta": redacted,
            }
        )


def _redact(value: Any, *, key: str = "") -> Any:
    if any(
        word in key.casefold()
        for word in ("secret", "password", "token", "credential", "private_key", "totp")
    ):
        return "[redacted]"
    if isinstance(value, dict):
        return {str(item_key): _redact(item, key=str(item_key)) for item_key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item, key=key) for item in value]
    return deepcopy(value)
