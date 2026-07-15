"""Compatibility repository projected from authoritative normalized Tigrbl tables."""

from __future__ import annotations

import copy
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from threading import RLock
from typing import Any

from sqlalchemy import text
from tigrbl.engine import resolver

from portwyrm.persistence import MemoryRepository
from portwyrm.persistence.base import MappingTransaction, Resource

from .legacy import LegacyProjector
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
    Credential,
    MFAEnrollment,
    MFARecoveryCode,
    PersonalAccessToken,
    Principal,
    RoutingHost,
    RoutingHostAccessList,
    RoutingSource,
    RoutingUpstream,
    Setting,
    StreamRoute,
)


class _TrackedTransaction(MappingTransaction):
    def __init__(self, state: dict[str, dict[str, Resource]]) -> None:
        super().__init__(state)
        self.dirty = False

    def upsert(self, collection: str, resource: Mapping[str, Any]) -> Resource:
        self.dirty = True
        return super().upsert(collection, resource)

    def delete(self, collection: str, resource_id: str | int) -> bool:
        deleted = super().delete(collection, resource_id)
        self.dirty = self.dirty or deleted
        return deleted


def _bucket(rows: list[dict[str, Any]]) -> dict[str, Resource]:
    return {str(row["id"]): row for row in rows}


def _compat(row: Any) -> dict[str, Any]:
    metadata = row.metadata_json if isinstance(row.metadata_json, dict) else {}
    value = metadata.get("compat")
    return copy.deepcopy(value) if isinstance(value, dict) else {}


class TigrblRepository:
    """Expose NPM-shaped transactions while Tigrbl tables remain the sole authority.

    The adapter is intentionally a compatibility boundary. Reads materialize the
    legacy wire shape from normalized rows; writes atomically replace normalized
    state through :class:`LegacyProjector`. An in-process lock prevents lost
    updates for the single-writer memory/SQLite/filesystem profiles.
    """

    def __init__(self, app: Any, *, backend_name: str) -> None:
        self.app = app
        self.backend_name = backend_name
        self._lock = RLock()

    def has_state(self) -> bool:
        session, release = resolver.acquire(router=self.app, model=Principal, require_ready=True)
        try:
            return any(session.query(table).first() is not None for table in PORTWYRM_TABLES)
        finally:
            release()

    @contextmanager
    def transaction(self) -> Iterator[_TrackedTransaction]:
        with self._lock:
            session, release = resolver.acquire(
                router=self.app,
                model=Principal,
                require_ready=True,
            )
            mysql_lock = False
            try:
                if self.backend_name == "postgresql":
                    session.execute(text("SELECT pg_advisory_xact_lock(5789726)"))
                elif self.backend_name == "mysql":
                    acquired = session.execute(
                        text("SELECT GET_LOCK('portwyrm-control-plane', 30)")
                    ).scalar()
                    if acquired != 1:
                        raise TimeoutError("timed out acquiring Portwyrm MySQL mutation lock")
                    mysql_lock = True

                candidate = self._export(session)
                transaction = _TrackedTransaction(copy.deepcopy(candidate))
                yield transaction
                if transaction.dirty:
                    source = MemoryRepository()
                    source._state = copy.deepcopy(transaction.state)
                    projector = LegacyProjector(self.app, source)
                    snapshot = {
                        collection: bucket.values()
                        for collection, bucket in transaction.state.items()
                    }
                    projector.replace_in_session(session, snapshot)
                    session.commit()
                else:
                    session.rollback()
            except BaseException:
                session.rollback()
                raise
            finally:
                if mysql_lock:
                    session.execute(text("SELECT RELEASE_LOCK('portwyrm-control-plane')"))
                release()

    def _export(self, session: Any) -> dict[str, dict[str, Resource]]:
        try:
            state: dict[str, dict[str, Resource]] = {}
            principals = session.query(Principal).all()
            credentials = {row.principal_id: row for row in session.query(Credential).all()}
            users: list[dict[str, Any]] = []
            for principal in principals:
                row = _compat(principal)
                row.update(
                    id=principal.id,
                    email=principal.email,
                    name=principal.display_name,
                    nickname=principal.nickname,
                    is_admin=int(principal.is_admin),
                    is_disabled=int(principal.is_disabled),
                    is_deleted=int(principal.is_deleted),
                    visibility=principal.visibility,
                )
                users.append(row)
            state["users"] = _bucket(users)
            state["_credentials"] = _bucket(
                [
                    {
                        "id": principal.email,
                        "password_hash": credentials[principal.id].password_hash,
                    }
                    for principal in principals
                    if principal.id in credentials
                ]
            )

            access_lists: list[dict[str, Any]] = []
            rules = session.query(AccessListRule).all()
            acl_credentials = session.query(AccessListCredential).all()
            acl_principals = session.query(AccessListPrincipal).all()
            for access_list in session.query(AccessList).all():
                row = _compat(access_list)
                row.update(
                    id=access_list.id,
                    name=access_list.name,
                    satisfy_any=int(access_list.satisfy_any),
                    pass_auth=int(access_list.pass_auth),
                    clients=[
                        {"directive": item.directive, "address": item.address}
                        for item in sorted(rules, key=lambda item: item.position)
                        if item.access_list_id == access_list.id
                    ],
                    items=[
                        {"username": item.username, "password_hash": item.password_hash}
                        for item in acl_credentials
                        if item.access_list_id == access_list.id
                    ],
                    identity_ids=[
                        item.principal_id
                        for item in acl_principals
                        if item.access_list_id == access_list.id
                    ],
                )
                access_lists.append(row)
            state["access_lists"] = _bucket(access_lists)

            domains = session.query(CertificateDomain).all()
            certificates: list[dict[str, Any]] = []
            for certificate in session.query(Certificate).all():
                row = _compat(certificate)
                row.update(
                    id=certificate.id,
                    nice_name=certificate.nice_name,
                    provider=certificate.provider,
                    challenge_type=certificate.challenge_type,
                    key_type=certificate.key_type,
                    material_ref=certificate.material_ref,
                    expires_at=certificate.expires_at,
                    status=certificate.status,
                    domain_names=[
                        item.domain_name
                        for item in domains
                        if item.certificate_id == certificate.id
                    ],
                )
                certificates.append(row)
            state["certificates"] = _bucket(certificates)

            sources = session.query(RoutingSource).all()
            upstreams = session.query(RoutingUpstream).all()
            host_acls = session.query(RoutingHostAccessList).all()
            host_rows: dict[str, list[dict[str, Any]]] = {
                "proxy_hosts": [],
                "redirection_hosts": [],
                "dead_hosts": [],
            }
            collection_for_kind = {
                "proxy": "proxy_hosts",
                "redirect": "redirection_hosts",
                "dead": "dead_hosts",
            }
            for host in session.query(RoutingHost).all():
                collection = collection_for_kind[host.kind]
                offset = {"proxy": 0, "redirect": 1_000_000, "dead": 2_000_000}[host.kind]
                legacy_id = int(host.id) - offset
                row = _compat(host)
                row.update(
                    id=legacy_id,
                    enabled=int(host.enabled),
                    certificate_id=host.certificate_id or 0,
                    ssl_forced=int(host.force_ssl),
                    hsts_enabled=int(host.hsts_enabled),
                    hsts_subdomains=int(host.hsts_subdomains),
                    allow_websocket_upgrade=int(host.websocket_enabled),
                    caching_enabled=int(host.cache_enabled),
                    block_exploits=int(host.block_exploits),
                    advanced_config=host.advanced_config,
                    domain_names=[
                        item.domain_name for item in sources if item.routing_host_id == host.id
                    ],
                    access_list_ids=[
                        item.access_list_id for item in host_acls if item.routing_host_id == host.id
                    ],
                )
                upstream = next(
                    (item for item in upstreams if item.routing_host_id == host.id), None
                )
                if upstream is not None:
                    row.update(
                        forward_scheme=upstream.protocol,
                        forward_host=upstream.target,
                        forward_port=upstream.port,
                        target_kind=upstream.target_kind,
                    )
                host_rows[collection].append(row)
            for collection, rows in host_rows.items():
                state[collection] = _bucket(rows)

            streams: list[dict[str, Any]] = []
            for stream in session.query(StreamRoute).all():
                row = _compat(stream)
                row.update(
                    id=stream.id,
                    protocol=stream.protocol,
                    incoming_port=stream.incoming_port,
                    forwarding_host=stream.target,
                    forwarding_port=stream.target_port,
                    target_kind=stream.target_kind,
                    enabled=int(stream.enabled),
                )
                streams.append(row)
            state["streams"] = _bucket(streams)

            settings: list[dict[str, Any]] = []
            for setting in session.query(Setting).all():
                row = _compat(setting)
                row.update(id=setting.key, name=setting.key, value=setting.value)
                settings.append(row)
            state["settings"] = _bucket(settings)

            principal_by_id = {row.id: row for row in principals}
            pats: list[dict[str, Any]] = []
            for pat in session.query(PersonalAccessToken).all():
                row = _compat(pat)
                principal = principal_by_id.get(pat.principal_id)
                row.update(
                    id=pat.token_prefix,
                    name=pat.name,
                    token_hash=pat.token_digest,
                    created_at=row.get("created_at", 0),
                    expires_at=pat.expires_at,
                    last_used_at=pat.last_used_at,
                    revoked_at=pat.revoked_at,
                )
                if "principal" not in row and principal is not None:
                    row["principal"] = {
                        "user_id": principal.id,
                        "identity": principal.email,
                        "is_admin": bool(principal.is_admin),
                        "permissions": _compat(principal).get("permissions", {}),
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

            state["_audit"] = _bucket(
                [
                    {
                        "id": item.id,
                        "actor_id": item.actor_principal_id,
                        "action": item.action,
                        "object_type": item.object_type,
                        "object_id": item.object_id,
                        "details": item.details,
                    }
                    for item in session.query(AuditEvent).all()
                ]
            )
            state.setdefault("access_tokens", {})
            return state
        finally:
            session.expire_all()
