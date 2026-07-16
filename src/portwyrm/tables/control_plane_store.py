"""Normalized persistence mapping for the NPM-compatible control plane."""

from __future__ import annotations

import copy
import ipaddress
import json
from collections.abc import Mapping
from hashlib import sha256
from typing import Any

from .models import (
    AccessList,
    AccessListCredential,
    AccessListPrincipal,
    AccessListRule,
    AuditEvent,
    Certificate,
    CertificateDomain,
    ConfigRevision,
    Credential,
    Permission,
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

HOST_KINDS = {
    "proxy-hosts": ("proxy", 0),
    "redirection-hosts": ("redirect", 1_000_000),
    "dead-hosts": ("dead", 2_000_000),
}


def _compat(row: Any) -> dict[str, Any]:
    metadata = row.metadata_json if isinstance(row.metadata_json, dict) else {}
    value = metadata.get("compat")
    return copy.deepcopy(value) if isinstance(value, dict) else {}


def _integer(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _positive_integer(value: Any) -> int | None:
    value = _integer(value)
    return value if value is not None and value > 0 else None


def _target_kind(target: str, explicit: Any = None) -> str:
    if explicit in {"ip", "dns", "docker"}:
        return str(explicit)
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return "dns" if "." in target else "docker"
    return "ip"


def _ids(value: Any) -> list[int]:
    candidates = value if isinstance(value, list) else [value]
    return [item for candidate in candidates if (item := _positive_integer(candidate)) is not None]


def load_control_plane_state(session: Any) -> dict[str, dict[str, dict[str, Any]]]:
    """Materialize only the synchronous compatibility service's normalized state."""
    state: dict[str, dict[str, dict[str, Any]]] = {}
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
            {"id": principal.email, "password_hash": credentials[principal.id].password_hash}
            for principal in principals
            if principal.id in credentials
        ]
    )

    rules = session.query(AccessListRule).all()
    acl_credentials = session.query(AccessListCredential).all()
    acl_principals = session.query(AccessListPrincipal).all()
    access_lists: list[dict[str, Any]] = []
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
                item.domain_name for item in domains if item.certificate_id == certificate.id
            ],
        )
        certificates.append(row)
    state["certificates"] = _bucket(certificates)

    sources = session.query(RoutingSource).all()
    upstreams = session.query(RoutingUpstream).all()
    host_acls = session.query(RoutingHostAccessList).all()
    hosts: dict[str, list[dict[str, Any]]] = {
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
        row = _compat(host)
        row.update(
            id=int(host.id) - offset,
            enabled=int(host.enabled),
            certificate_id=host.certificate_id or 0,
            ssl_forced=int(host.force_ssl),
            hsts_enabled=int(host.hsts_enabled),
            hsts_subdomains=int(host.hsts_subdomains),
            allow_websocket_upgrade=int(host.websocket_enabled),
            caching_enabled=int(host.cache_enabled),
            block_exploits=int(host.block_exploits),
            advanced_config=host.advanced_config,
            domain_names=[item.domain_name for item in sources if item.routing_host_id == host.id],
            access_list_ids=[
                item.access_list_id for item in host_acls if item.routing_host_id == host.id
            ],
        )
        upstream = next((item for item in upstreams if item.routing_host_id == host.id), None)
        if upstream is not None:
            row.update(
                forward_scheme=upstream.protocol,
                forward_host=upstream.target,
                forward_port=upstream.port,
                target_kind=upstream.target_kind,
            )
        hosts[collection].append(row)
    for collection, rows in hosts.items():
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

    events: list[dict[str, Any]] = []
    for event in session.query(AuditEvent).all():
        row = _compat(event)
        row.update(
            id=event.id,
            action=event.action,
            object_type=event.object_type,
            object_id=event.object_id,
        )
        row.setdefault("user_id", event.actor_principal_id)
        row.setdefault("meta", event.details)
        events.append(row)
    state["_audit"] = _bucket(events)
    state["access_tokens"] = {}
    return state


def persist_control_plane_resource(
    session: Any, collection: str, row: Mapping[str, Any], passwords: Mapping[str, str]
) -> None:
    """Upsert one compatibility resource and only its normalized dependents."""
    if collection == "users":
        _persist_user(session, row, passwords)
    elif collection == "access-lists":
        _persist_access_list(session, row)
    elif collection == "certificates":
        _persist_certificate(session, row)
    elif collection in HOST_KINDS:
        _persist_host(session, collection, row)
    elif collection == "streams":
        _persist_stream(session, row)
    elif collection == "settings":
        _persist_setting(session, row)
    elif collection != "access-tokens":
        raise KeyError(f"unsupported control-plane collection {collection!r}")


def persist_audit_event(session: Any, row: Mapping[str, Any]) -> None:
    event_id = _integer(row.get("id"))
    event = session.get(AuditEvent, event_id) if event_id is not None else None
    values = {
        "actor_principal_id": _integer(row.get("user_id", row.get("actor_id"))),
        "action": str(row.get("action", "unknown")),
        "object_type": str(row.get("object_type", "unknown")),
        "object_id": str(row.get("object_id", "")),
        "details": copy.deepcopy(row.get("meta", row.get("details", {})) or {}),
        "metadata_json": {"compat": copy.deepcopy(dict(row))},
    }
    if event is None:
        event = AuditEvent(id=event_id, **values)
        session.add(event)
    else:
        _assign(event, values)
    _persist_revision(session, row)


def _persist_user(session: Any, row: Mapping[str, Any], passwords: Mapping[str, str]) -> None:
    principal_id = int(row["id"])
    principal = session.get(Principal, principal_id)
    values = {
        "email": str(row.get("email", "")).strip().casefold(),
        "display_name": str(row.get("name", "")),
        "nickname": str(row.get("nickname", "")),
        "is_admin": bool(row.get("is_admin")),
        "is_disabled": bool(row.get("is_disabled")),
        "is_deleted": bool(row.get("is_deleted")),
        "visibility": str(row.get("visibility", "user")),
        "metadata_json": {"compat": copy.deepcopy(dict(row))},
    }
    if principal is None:
        principal = Principal(id=principal_id, **values)
        session.add(principal)
    else:
        _assign(principal, values)
    session.flush()

    admin_role = session.query(Role).filter(Role.name == "administrator").one_or_none()
    if admin_role is None:
        admin_role = Role(name="administrator", description="Full control", is_system=True)
        session.add(admin_role)
        session.flush()
    session.query(PrincipalRole).filter(PrincipalRole.principal_id == principal_id).delete(
        synchronize_session=False
    )
    if row.get("is_admin"):
        session.add(PrincipalRole(principal_id=principal_id, role_id=admin_role.id))

    session.query(PrincipalPermission).filter(
        PrincipalPermission.principal_id == principal_id
    ).delete(synchronize_session=False)
    for key, section, action in _permission_grants(row.get("permissions")):
        permission = session.query(Permission).filter(Permission.key == key).one_or_none()
        if permission is None:
            permission = Permission(
                key=key,
                section=section,
                action=action,
                description="Compatibility grant",
            )
            session.add(permission)
            session.flush()
        session.add(
            PrincipalPermission(
                principal_id=principal_id,
                permission_id=permission.id,
                effect="allow",
            )
        )

    credential = (
        session.query(Credential).filter(Credential.principal_id == principal_id).one_or_none()
    )
    digest = passwords.get(values["email"])
    if digest is None:
        if credential is not None:
            session.delete(credential)
    elif credential is None:
        session.add(Credential(principal_id=principal_id, password_hash=digest))
    else:
        credential.password_hash = digest
        credential.password_version = int(credential.password_version or 0) + 1


def _persist_access_list(session: Any, row: Mapping[str, Any]) -> None:
    resource_id = int(row["id"])
    model = session.get(AccessList, resource_id)
    values = {
        "name": str(row.get("name", f"Access list {resource_id}")),
        "satisfy_any": bool(row.get("satisfy_any")),
        "pass_auth": bool(row.get("pass_auth")),
        "metadata_json": {"compat": copy.deepcopy(dict(row))},
    }
    if model is None:
        session.add(AccessList(id=resource_id, **values))
    else:
        _assign(model, values)
    session.flush()
    for table in (AccessListRule, AccessListCredential, AccessListPrincipal):
        session.query(table).filter(table.access_list_id == resource_id).delete(
            synchronize_session=False
        )
    for position, rule in enumerate(row.get("clients", [])):
        if isinstance(rule, Mapping):
            session.add(
                AccessListRule(
                    access_list_id=resource_id,
                    position=position,
                    directive=str(rule.get("directive", "allow")),
                    address=str(rule.get("address", "")),
                )
            )
    for item in row.get("items", []):
        if isinstance(item, Mapping):
            session.add(
                AccessListCredential(
                    access_list_id=resource_id,
                    username=str(item.get("username", "")),
                    password_hash=str(item.get("password_hash", item.get("password", ""))),
                )
            )
    for principal_id in _ids(row.get("identity_ids", row.get("principal_ids", []))):
        session.add(AccessListPrincipal(access_list_id=resource_id, principal_id=principal_id))


def _persist_certificate(session: Any, row: Mapping[str, Any]) -> None:
    resource_id = int(row["id"])
    model = session.get(Certificate, resource_id)
    values = {
        "nice_name": str(row.get("nice_name", row.get("name", "Certificate"))),
        "provider": str(row.get("provider", "custom")),
        "challenge_type": str(row["challenge_type"]) if row.get("challenge_type") else None,
        "key_type": str(row.get("key_type", "rsa")),
        "material_ref": str(row["material_ref"]) if row.get("material_ref") else None,
        "expires_at": _integer(row.get("expires_at")),
        "status": str(row.get("status", "active")),
        "metadata_json": {"compat": copy.deepcopy(dict(row))},
    }
    if model is None:
        session.add(Certificate(id=resource_id, **values))
    else:
        _assign(model, values)
    session.flush()
    session.query(CertificateDomain).filter(
        CertificateDomain.certificate_id == resource_id
    ).delete(synchronize_session=False)
    for domain in row.get("domain_names", []):
        session.add(
            CertificateDomain(certificate_id=resource_id, domain_name=str(domain).casefold())
        )


def _persist_host(session: Any, collection: str, row: Mapping[str, Any]) -> None:
    kind, offset = HOST_KINDS[collection]
    routing_id = offset + int(row["id"])
    model = session.get(RoutingHost, routing_id)
    values = {
        "kind": kind,
        "owner_principal_id": _positive_integer(row.get("owner_user_id")),
        "enabled": bool(row.get("enabled", True)),
        "certificate_id": _positive_integer(row.get("certificate_id")),
        "force_ssl": bool(row.get("ssl_forced", row.get("force_ssl", False))),
        "hsts_enabled": bool(row.get("hsts_enabled")),
        "hsts_subdomains": bool(row.get("hsts_subdomains")),
        "websocket_enabled": bool(row.get("allow_websocket_upgrade", True)),
        "cache_enabled": bool(row.get("caching_enabled")),
        "block_exploits": bool(row.get("block_exploits", True)),
        "advanced_config": str(row.get("advanced_config", "")),
        "metadata_json": {
            "legacy_id": int(row["id"]),
            "compat": copy.deepcopy(dict(row)),
        },
    }
    if model is None:
        session.add(RoutingHost(id=routing_id, **values))
    else:
        _assign(model, values)
    session.flush()
    for table in (RoutingSource, RoutingUpstream, RoutingHostAccessList):
        session.query(table).filter(table.routing_host_id == routing_id).delete(
            synchronize_session=False
        )
    for domain in row.get("domain_names", []):
        session.add(RoutingSource(routing_host_id=routing_id, domain_name=str(domain).casefold()))
    if kind != "dead":
        target = str(
            row.get("forward_host")
            or row.get("forwarding_domain_name")
            or row.get("forward_domain_name")
            or ""
        )
        if target:
            session.add(
                RoutingUpstream(
                    routing_host_id=routing_id,
                    protocol=str(
                        row.get(
                            "forward_scheme", "https" if kind == "redirect" else "http"
                        )
                    ),
                    target_kind=_target_kind(target, row.get("target_kind")),
                    target=target,
                    port=int(row.get("forward_port", 443 if kind == "redirect" else 80)),
                )
            )
    access_ids = row.get("access_list_ids", row.get("access_list_id"))
    for access_list_id in _ids(access_ids):
        session.add(
            RoutingHostAccessList(routing_host_id=routing_id, access_list_id=access_list_id)
        )


def _persist_stream(session: Any, row: Mapping[str, Any]) -> None:
    resource_id = int(row["id"])
    target = str(row.get("forwarding_host", row.get("forward_host", "")))
    model = session.get(StreamRoute, resource_id)
    values = {
        "owner_principal_id": _positive_integer(row.get("owner_user_id")),
        "protocol": str(row.get("protocol", "tcp")),
        "incoming_port": int(row.get("incoming_port", 0)),
        "target_kind": _target_kind(target, row.get("target_kind")),
        "target": target,
        "target_port": int(row.get("forwarding_port", row.get("forward_port", 0))),
        "enabled": bool(row.get("enabled", True)),
        "metadata_json": {"compat": copy.deepcopy(dict(row))},
    }
    if model is None:
        session.add(StreamRoute(id=resource_id, **values))
    else:
        _assign(model, values)


def _persist_setting(session: Any, row: Mapping[str, Any]) -> None:
    key = str(row.get("name", row.get("id", "")))
    model = session.query(Setting).filter(Setting.key == key).one_or_none()
    values = {
        "key": key,
        "value": copy.deepcopy(row.get("value")),
        "metadata_json": {"compat": copy.deepcopy(dict(row))},
    }
    if model is None:
        session.add(Setting(**values))
    else:
        _assign(model, values)


def _persist_revision(session: Any, row: Mapping[str, Any]) -> None:
    if row.get("action") != "configuration.applied":
        return
    details = row.get("meta", row.get("details", {}))
    if not isinstance(details, Mapping) or not isinstance(details.get("snapshot"), Mapping):
        return
    object_type = str(row.get("object_type", "")).replace("_", "-")
    host = HOST_KINDS.get(object_type)
    host_id = _integer(row.get("object_id"))
    generation = str(details.get("generation", ""))
    if host is None or host_id is None or not generation:
        return
    routing_id = host[1] + host_id
    existing = (
        session.query(ConfigRevision)
        .filter(
            ConfigRevision.routing_host_id == routing_id,
            ConfigRevision.generation == generation,
        )
        .one_or_none()
    )
    if existing is not None:
        return
    text = json.dumps(details["snapshot"], sort_keys=True, indent=2)
    session.add(
        ConfigRevision(
            routing_host_id=routing_id,
            generation=generation,
            config_text=text,
            config_digest=sha256(text.encode()).hexdigest(),
            applied=True,
        )
    )


def _permission_grants(value: Any) -> list[tuple[str, str, str]]:
    if not isinstance(value, Mapping):
        return []
    grants: list[tuple[str, str, str]] = []
    for section, grant in value.items():
        if grant == "manage":
            actions = ("create", "read", "update", "delete")
        elif grant == "view":
            actions = ("read",)
        elif isinstance(grant, Mapping):
            actions = tuple(str(action) for action, allowed in grant.items() if allowed is True)
        else:
            actions = ()
        grants.extend((f"{section}.{action}", str(section), action) for action in actions)
    return grants


def _assign(model: Any, values: Mapping[str, Any]) -> None:
    for key, value in values.items():
        setattr(model, key, value)


def _bucket(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(row["id"]): row for row in rows}
