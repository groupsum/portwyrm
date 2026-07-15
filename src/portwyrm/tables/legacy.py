"""Idempotent projection from the v1 collection store into normalized Tigrbl tables."""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterable, Mapping
from hashlib import sha256
from typing import Any

from tigrbl.engine import resolver

from portwyrm.persistence import Repository

from .models import (
    PORTWYRM_TABLES,
    AccessList,
    AccessListCredential,
    AccessListPrincipal,
    AccessListRule,
    AuditEvent,
    BrowserSession,
    Certificate,
    CertificateDomain,
    ConfigRevision,
    Credential,
    MFAEnrollment,
    MFARecoveryCode,
    Permission,
    PersonalAccessToken,
    Principal,
    PrincipalPermission,
    PrincipalRole,
    Role,
    RoutingHost,
    RoutingHostAccessList,
    RoutingSource,
    RoutingUpstream,
    Setting,
    StreamRoute,
)


def _rows(repository: Repository, collection: str) -> list[dict[str, Any]]:
    with repository.transaction() as transaction:
        return transaction.list(collection)


def _integer(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _positive_integer(value: Any) -> int | None:
    normalized = _integer(value)
    return normalized if normalized is not None and normalized > 0 else None


def _target_kind(target: str, explicit: Any = None) -> str:
    if explicit in {"ip", "dns", "docker"}:
        return str(explicit)
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return "dns" if "." in target else "docker"
    return "ip"


def _iter_ids(value: Any) -> Iterable[int]:
    candidates = value if isinstance(value, list) else [value]
    for candidate in candidates:
        normalized = _integer(candidate)
        if normalized is not None and normalized > 0:
            yield normalized


class LegacyProjector:
    """Rebuild normalized tables from the compatibility repository atomically."""

    def __init__(self, app: Any, repository: Repository) -> None:
        self.app = app
        self.repository = repository
        self._source: dict[str, list[dict[str, Any]]] = {}

    def rebuild(self) -> None:
        collections = (
            "users",
            "_credentials",
            "_personal_access_tokens",
            "_sessions",
            "_mfa",
            "access_lists",
            "certificates",
            "proxy_hosts",
            "redirection_hosts",
            "dead_hosts",
            "streams",
            "settings",
            "_audit",
        )
        source = {
            collection: _rows(self.repository, collection) for collection in collections
        }
        session, release = resolver.acquire(
            router=self.app,
            model=Principal,
            require_ready=True,
        )
        try:
            self.replace_in_session(session, source)
            session.commit()
        except BaseException:
            session.rollback()
            raise
        finally:
            release()

    def replace_in_session(
        self,
        session: Any,
        source: Mapping[str, list[dict[str, Any]]],
    ) -> None:
        """Replace normalized state inside the caller's open transaction."""
        self._source = {collection: list(rows) for collection, rows in source.items()}
        for table in reversed(PORTWYRM_TABLES):
            session.query(table).delete(synchronize_session=False)
        self._project(session)

    def _rows(self, collection: str) -> list[dict[str, Any]]:
        return self._source.get(collection, [])

    def _project(self, session: Any) -> None:
        users = self._rows("users")
        credentials = {
            str(row["id"]).casefold(): row
            for row in self._rows("_credentials")
        }
        permission_ids: dict[str, int] = {}

        admin_role = Role(id=1, name="administrator", description="Full control", is_system=True)
        session.add(admin_role)
        session.flush()

        for row in users:
            user_id = _integer(row.get("id"))
            if user_id is None:
                continue
            email = str(row.get("email", "")).strip().casefold()
            principal = Principal(
                    id=user_id,
                    email=email,
                    display_name=str(row.get("name", "")),
                    nickname=str(row.get("nickname", "")),
                    is_admin=bool(row.get("is_admin")),
                    is_disabled=bool(row.get("is_disabled")),
                    is_deleted=bool(row.get("is_deleted")),
                    visibility=str(row.get("visibility", "user")),
                    metadata_json={"compat": dict(row)},
                )
            session.add(principal)
            session.flush()
            stored = credentials.get(email)
            if stored is not None:
                session.add(
                    Credential(
                        id=user_id,
                        principal_id=user_id,
                        password_hash=str(stored.get("password_hash", "")),
                    )
                )
            if row.get("is_admin"):
                session.add(PrincipalRole(principal_id=user_id, role_id=1))
            self._project_permissions(session, row, user_id, permission_ids)

        self._project_tokens(session)
        self._project_sessions(session)
        self._project_mfa(session)
        self._project_access_lists(session)
        self._project_certificates(session)
        self._project_routing(session)
        self._project_settings(session)
        self._project_audit(session)

    @staticmethod
    def _project_permissions(
        session: Any,
        row: Mapping[str, Any],
        principal_id: int,
        permission_ids: dict[str, int],
    ) -> None:
        permissions = row.get("permissions")
        if not isinstance(permissions, Mapping):
            return
        for section, grant in permissions.items():
            actions: list[str]
            if grant == "manage":
                actions = ["create", "read", "update", "delete"]
            elif grant == "view":
                actions = ["read"]
            elif isinstance(grant, Mapping):
                actions = [str(action) for action, allowed in grant.items() if allowed is True]
            else:
                actions = []
            for action in actions:
                key = f"{section}.{action}"
                permission_id = permission_ids.get(key)
                if permission_id is None:
                    permission_id = len(permission_ids) + 1
                    permission_ids[key] = permission_id
                    session.add(
                        Permission(
                            id=permission_id,
                            key=key,
                            section=str(section),
                            action=action,
                            description="Projected compatibility grant",
                        )
                    )
                    session.flush()
                session.add(
                    PrincipalPermission(
                        principal_id=principal_id,
                        permission_id=permission_id,
                        effect="allow",
                    )
                )

    def _project_tokens(self, session: Any) -> None:
        for row in self._rows("_personal_access_tokens"):
            principal = row.get("principal") if isinstance(row.get("principal"), Mapping) else {}
            principal_id = _integer(principal.get("user_id"))
            if principal_id is None:
                continue
            session.add(
                PersonalAccessToken(
                    principal_id=principal_id,
                    name=str(row.get("name", "Access token")),
                    token_prefix=str(row.get("id", "")),
                    token_digest=str(row.get("token_hash", "")),
                    scopes=list(principal.get("scopes", ["user"])),
                    expires_at=_integer(row.get("expires_at")),
                    last_used_at=_integer(row.get("last_used_at")),
                    revoked_at=_integer(row.get("revoked_at")),
                    metadata_json={"compat": dict(row)},
                )
            )

    def _project_sessions(self, session: Any) -> None:
        for row in self._rows("_sessions"):
            token_id = str(row.get("id", ""))
            token_digest = str(row.get("token_hash", ""))
            principal = row.get("principal")
            expires = _integer(row.get("expires"))
            if (
                not token_id
                or not token_digest
                or not isinstance(principal, Mapping)
                or expires is None
            ):
                continue
            session.add(
                BrowserSession(
                    token_id=token_id,
                    token_digest=token_digest,
                    principal_snapshot=dict(principal),
                    expires_at=expires,
                )
            )

    def _project_mfa(self, session: Any) -> None:
        for row in self._rows("_mfa"):
            principal_id = _integer(row.get("id"))
            if principal_id is None:
                continue
            enrollment = MFAEnrollment(
                principal_id=principal_id,
                encrypted_secret=str(row.get("secret_ciphertext", "")),
                confirmed=bool(row.get("active")),
                metadata_json={"compat_id": str(row.get("id", principal_id))},
            )
            session.add(enrollment)
            session.flush()
            for digest in row.get("backup_hashes", []):
                session.add(
                    MFARecoveryCode(enrollment_id=enrollment.id, code_digest=str(digest))
                )

    def _project_access_lists(self, session: Any) -> None:
        for row in self._rows("access_lists"):
            access_list_id = _integer(row.get("id"))
            if access_list_id is None:
                continue
            session.add(
                AccessList(
                    id=access_list_id,
                    name=str(row.get("name", f"Access list {access_list_id}")),
                    satisfy_any=bool(row.get("satisfy_any")),
                    pass_auth=bool(row.get("pass_auth")),
                    metadata_json={
                        "compat": {key: value for key, value in row.items() if key != "items"}
                    },
                )
            )
            session.flush()
            for position, rule in enumerate(row.get("clients", [])):
                if not isinstance(rule, Mapping):
                    continue
                session.add(
                    AccessListRule(
                        access_list_id=access_list_id,
                        position=position,
                        directive=str(rule.get("directive", "allow")),
                        address=str(rule.get("address", "")),
                    )
                )
            for item in row.get("items", []):
                if not isinstance(item, Mapping):
                    continue
                session.add(
                    AccessListCredential(
                        access_list_id=access_list_id,
                        username=str(item.get("username", "")),
                        password_hash=str(item.get("password", item.get("password_hash", ""))),
                    )
                )
            identity_ids = row.get("identity_ids", row.get("principal_ids", []))
            for principal_id in _iter_ids(identity_ids):
                session.add(
                    AccessListPrincipal(
                        access_list_id=access_list_id,
                        principal_id=principal_id,
                    )
                )

    def _project_certificates(self, session: Any) -> None:
        for row in self._rows("certificates"):
            certificate_id = _integer(row.get("id"))
            if certificate_id is None:
                continue
            session.add(
                Certificate(
                    id=certificate_id,
                    nice_name=str(row.get("nice_name", row.get("name", "Certificate"))),
                    provider=str(row.get("provider", "custom")),
                    challenge_type=(
                        str(row["challenge_type"]) if row.get("challenge_type") else None
                    ),
                    key_type=str(row.get("key_type", "rsa")),
                    material_ref=(str(row["material_ref"]) if row.get("material_ref") else None),
                    expires_at=_integer(row.get("expires_at")),
                    status=str(row.get("status", "active")),
                    metadata_json={"compat": dict(row)},
                )
            )
            session.flush()
            for domain in row.get("domain_names", []):
                session.add(
                    CertificateDomain(
                        certificate_id=certificate_id,
                        domain_name=str(domain).casefold(),
                    )
                )

    def _project_routing(self, session: Any) -> None:
        collections = (
            ("proxy_hosts", "proxy"),
            ("redirection_hosts", "redirect"),
            ("dead_hosts", "dead"),
        )
        for collection, kind in collections:
            for row in self._rows(collection):
                host_id = _integer(row.get("id"))
                if host_id is None:
                    continue
                routing_id = {"proxy": 0, "redirect": 1_000_000, "dead": 2_000_000}[kind] + host_id
                session.add(
                    RoutingHost(
                        id=routing_id,
                        kind=kind,
                        owner_principal_id=_positive_integer(row.get("owner_user_id")),
                        enabled=bool(row.get("enabled", True)),
                        certificate_id=_positive_integer(row.get("certificate_id")),
                        force_ssl=bool(row.get("ssl_forced", row.get("force_ssl", False))),
                        hsts_enabled=bool(row.get("hsts_enabled")),
                        hsts_subdomains=bool(row.get("hsts_subdomains")),
                        websocket_enabled=bool(row.get("allow_websocket_upgrade", True)),
                        cache_enabled=bool(row.get("caching_enabled")),
                        block_exploits=bool(row.get("block_exploits", True)),
                        advanced_config=str(row.get("advanced_config", "")),
                        metadata_json={"legacy_id": host_id, "compat": dict(row)},
                    )
                )
                session.flush()
                for domain in row.get("domain_names", []):
                    session.add(
                        RoutingSource(
                            routing_host_id=routing_id,
                            domain_name=str(domain).casefold(),
                        )
                    )
                self._project_upstream(session, row, routing_id, kind)
                access_ids = row.get("access_list_ids", row.get("access_list_id"))
                for access_list_id in _iter_ids(access_ids):
                    session.add(
                        RoutingHostAccessList(
                            routing_host_id=routing_id,
                            access_list_id=access_list_id,
                        )
                    )

        for row in self._rows("streams"):
            stream_id = _integer(row.get("id"))
            if stream_id is None:
                continue
            target = str(row.get("forwarding_host", row.get("forward_host", "")))
            session.add(
                StreamRoute(
                    id=stream_id,
                    owner_principal_id=_positive_integer(row.get("owner_user_id")),
                    protocol=str(row.get("protocol", "tcp")),
                    incoming_port=int(row.get("incoming_port", 0)),
                    target_kind=_target_kind(target, row.get("target_kind")),
                    target=target,
                    target_port=int(row.get("forwarding_port", row.get("forward_port", 0))),
                    enabled=bool(row.get("enabled", True)),
                    metadata_json={"compat": dict(row)},
                )
            )

    @staticmethod
    def _project_upstream(session: Any, row: Mapping[str, Any], routing_id: int, kind: str) -> None:
        if kind == "dead":
            return
        target = str(
            row.get("forward_host")
            or row.get("forwarding_domain_name")
            or row.get("forward_domain_name")
            or ""
        )
        if not target:
            return
        session.add(
            RoutingUpstream(
                routing_host_id=routing_id,
                protocol=str(row.get("forward_scheme", "https" if kind == "redirect" else "http")),
                target_kind=_target_kind(target, row.get("target_kind")),
                target=target,
                port=int(row.get("forward_port", 443 if kind == "redirect" else 80)),
            )
        )

    def _project_settings(self, session: Any) -> None:
        for row in self._rows("settings"):
            key = str(row.get("name", row.get("id", "")))
            session.add(
                Setting(
                    key=key,
                    value=row.get("value"),
                    metadata_json={"compat": dict(row)},
                )
            )

    def _project_audit(self, session: Any) -> None:
        for row in self._rows("_audit"):
            event_id = _integer(row.get("id"))
            details = dict(row.get("details") or {})
            session.add(
                AuditEvent(
                    id=event_id,
                    actor_principal_id=_integer(row.get("actor_id")),
                    action=str(row.get("action", "unknown")),
                    object_type=str(row.get("object_type", "unknown")),
                    object_id=str(row.get("object_id", "")),
                    details=details,
                )
            )
            if row.get("action") != "configuration.applied":
                continue
            host_id = _integer(row.get("object_id"))
            generation_value = details.get("generation")
            generation = str(generation_value) if generation_value else ""
            snapshot = details.get("snapshot")
            if host_id is None or not generation or not isinstance(snapshot, Mapping):
                continue
            object_type = str(row.get("object_type", "")).replace("-", "_")
            routing_id = {
                "proxy_hosts": host_id,
                "redirection_hosts": 1_000_000 + host_id,
                "dead_hosts": 2_000_000 + host_id,
            }.get(object_type)
            if routing_id is None:
                continue
            config_text = json.dumps(snapshot, sort_keys=True, indent=2)
            session.add(
                ConfigRevision(
                    routing_host_id=routing_id,
                    generation=generation,
                    config_text=config_text,
                    config_digest=sha256(config_text.encode()).hexdigest(),
                    applied=True,
                )
            )
