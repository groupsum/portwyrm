"""Application-wide table lifecycle policy."""

from __future__ import annotations

import inspect
import logging
import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from portwyrm.domain.ownership import Ownership
from portwyrm.errors import AuthorizationError, OwnershipError
from portwyrm.identity.permissions import permission_allows

from .audit import AuditEventStore

logger = logging.getLogger(__name__)


def _no_runtime() -> None:
    return None


_runtime_provider: Callable[[], Any] = _no_runtime

_MUTATIONS = {
    "create",
    "update",
    "replace",
    "delete",
    "enable",
    "disable",
    "register",
    "update_identity",
    "set_authorization",
    "authenticate",
    "change_password",
    "set_password",
    "issue",
    "refresh",
    "revoke",
    "rotate",
    "verify",
    "begin",
    "enroll",
    "confirm",
    "remove",
    "recover",
    "regenerate_backup_codes",
    "record_failure",
    "record",
    "apply",
    "stage",
    "upload",
    "request",
    "renew",
    "activate",
    "clear_active",
    "reconcile",
    "reload",
    "acquire",
    "release",
}
_OWNERSHIP_MUTATIONS = _MUTATIONS | {"probe"}
_AUDIT_EXCLUDED_TABLES = {"audit_events", "runtime_leases"}
_ACTION = {
    "create": "created",
    "update": "updated",
    "replace": "replaced",
    "delete": "deleted",
    "enable": "enabled",
    "disable": "disabled",
}
_RECONCILE_TABLES = {
    "access_lists",
    "access_rules",
    "access_list_rules",
    "access_credentials",
    "access_list_credentials",
    "access_principals",
    "access_list_principals",
    "certificates",
    "certificate_domains",
    "certificate_challenges",
    "routing_hosts",
    "routing_sources",
    "routing_upstreams",
    "routing_locations",
    "routing_host_access_lists",
    "stream_routes",
    "settings",
}
_RECONCILE_COLLECTION = {
    "access_lists": "access_lists",
    "access_rules": "access_lists",
    "access_list_rules": "access_lists",
    "access_credentials": "access_lists",
    "access_list_credentials": "access_lists",
    "access_principals": "access_lists",
    "access_list_principals": "access_lists",
    "certificates": "certificates",
    "certificate_domains": "certificates",
    "certificate_challenges": "certificates",
    "stream_routes": "streams",
    "settings": "settings",
}
_SECTION_BY_TABLE = {
    "access_lists": "access_lists",
    "certificates": "certificates",
    "routing_hosts": "proxy_hosts",
    "stream_routes": "streams",
}
_ACTION_BY_ALIAS = {
    "create": "create",
    "read": "read",
    "list": "read",
    "update": "update",
    "replace": "update",
    "enable": "update",
    "disable": "update",
    "delete": "delete",
    "health_read": "read",
    "health_list": "read",
    "probe": "update",
}


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


async def protect_model_descriptors(ctx: dict[str, Any]) -> None:
    """Keep Tigrbl's storage preparation from assigning payloads to model classes.

    Canonical handlers receive the validated payload directly and remain responsible
    for persistence.  The 0.4 runtime otherwise treats the table class passed to its
    storage atom as a hydrated row and overwrites mapped ``acol`` descriptors before
    the CRUD handler runs.
    """

    ctx["persist"] = False


def _alias(ctx: Mapping[str, Any]) -> str:
    value = ctx.get("op") or ctx.get("alias") or ctx.get("target") or ""
    return str(getattr(value, "alias", value)).casefold()


def _table_name(ctx: Mapping[str, Any]) -> str:
    model = ctx.get("model") or ctx.get("table")
    return str(getattr(model, "__tablename__", ""))


def _principal_id(ctx: Mapping[str, Any]) -> int | None:
    principal = ctx.get("principal") or ctx.get("actor")
    if isinstance(principal, Mapping):
        value = principal.get("user_id", principal.get("id"))
    else:
        value = getattr(principal, "user_id", getattr(principal, "id", None))
    if value is None and isinstance(ctx.get("payload"), Mapping):
        payload = ctx["payload"]
        value = payload.get("principal_id")
        if value is None and isinstance(payload.get("principal"), Mapping):
            value = payload["principal"].get("principal_id", payload["principal"].get("id"))
    if value is None and isinstance(ctx.get("result"), Mapping):
        value = ctx["result"].get("principal_id")
    return int(value) if value is not None else None


def _principal_value(ctx: Mapping[str, Any], name: str) -> Any:
    principal = ctx.get("principal") or ctx.get("actor")
    if isinstance(principal, Mapping):
        return principal.get(name)
    return getattr(principal, name, None)


def _ownership_from_row(row: Any) -> Ownership | None:
    metadata = dict(getattr(row, "metadata_json", None) or {})
    extensions = dict(metadata.get("extensions") or {})
    meta = extensions.get("meta")
    return Ownership.from_meta(meta) if isinstance(meta, Mapping) else None


async def enforce_ownership(ctx: dict[str, Any]) -> None:
    """Assign row ownership and reject foreign mutation at the table boundary."""

    alias = _alias(ctx)
    if alias not in _OWNERSHIP_MUTATIONS:
        return
    model = ctx.get("model")
    payload = ctx.get("payload")
    if not isinstance(model, type) or not isinstance(payload, dict):
        return
    principal_id = _principal_id(ctx)
    if alias == "create" and principal_id is not None and hasattr(model, "owner_principal_id"):
        if payload.get("owner_principal_id") is None:
            payload["owner_principal_id"] = principal_id
        return
    resource_id = payload.get("id")
    if resource_id is None:
        return
    row = await _await(ctx["db"].get(model, int(resource_id)))
    if row is None:
        return
    if _table_name(ctx) == "routing_hosts":
        ctx.setdefault("temp", {})["object_type"] = {
            "proxy": "proxy_hosts",
            "redirect": "redirection_hosts",
            "dead": "dead_hosts",
        }.get(str(getattr(row, "kind", None)), "routing_hosts")
    if _principal_value(ctx, "is_admin"):
        return
    row_owner = getattr(row, "owner_principal_id", None)
    if row_owner is not None and principal_id is not None and int(row_owner) != principal_id:
        raise OwnershipError("foreign-owned resources cannot be mutated")
    ownership = _ownership_from_row(row)
    actor_owner = _principal_value(ctx, "owner")
    if ownership is not None and actor_owner is not None and ownership.owner != actor_owner:
        raise OwnershipError("foreign npmctl resources require explicit adoption")


async def enforce_authorization(ctx: dict[str, Any]) -> None:
    """Enforce collection permissions for every carrier that supplies a principal."""

    principal = ctx.get("principal") or ctx.get("actor")
    if principal is None or _principal_value(ctx, "is_admin"):
        return
    alias = _alias(ctx)
    action = _ACTION_BY_ALIAS.get(alias)
    table_name = _table_name(ctx)
    if action is None:
        return
    if table_name in {"principals", "settings"}:
        raise AuthorizationError("administrator permission is required")
    section = _SECTION_BY_TABLE.get(table_name)
    if section is None:
        return
    if table_name == "routing_hosts":
        payload = ctx.get("payload")
        kind = payload.get("kind") if isinstance(payload, Mapping) else None
        if kind is None and isinstance(payload, Mapping) and payload.get("id") is not None:
            row = await _await(ctx["db"].get(ctx["model"], int(payload["id"])))
            kind = getattr(row, "kind", None)
        section = {
            "redirect": "redirection_hosts",
            "dead": "dead_hosts",
        }.get(str(kind), "proxy_hosts")
    permissions = _principal_value(ctx, "permissions")
    grant = permissions.get(section, "hidden") if isinstance(permissions, Mapping) else "hidden"
    if not permission_allows(grant, action):
        raise AuthorizationError("permission denied")


def _contains_advanced_config(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(
            (key == "advanced_config" and bool(str(item).strip()))
            or _contains_advanced_config(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_advanced_config(item) for item in value)
    return False


async def enforce_raw_nginx_policy(ctx: dict[str, Any]) -> None:
    """Reserve arbitrary Nginx directives for authenticated administrators."""

    if _alias(ctx) not in {"create", "update", "replace", "validate"}:
        return
    if _table_name(ctx) not in {"routing_hosts", "routing_locations"}:
        return
    principal = ctx.get("principal") or ctx.get("actor")
    if principal is None or _principal_value(ctx, "is_admin"):
        return
    if _contains_advanced_config(ctx.get("payload")):
        raise AuthorizationError("advanced Nginx configuration requires an administrator")


def _visible_to(result: Any, ctx: Mapping[str, Any]) -> bool:
    if _principal_value(ctx, "is_admin") or _principal_value(ctx, "visibility") == "all":
        return True
    principal_id = _principal_id(ctx)
    if isinstance(result, Mapping):
        owner = result.get("owner_principal_id", result.get("owner_user_id"))
    else:
        owner = getattr(result, "owner_principal_id", None)
    return owner is None or principal_id is None or int(owner) == principal_id


async def enforce_visibility(ctx: dict[str, Any]) -> None:
    """Apply the same owner visibility policy to every carrier."""

    if (
        _alias(ctx) not in {"read", "list", "health_read", "health_list"}
        or ctx.get("principal") is None
    ):
        return
    result = ctx.get("result")
    if isinstance(result, Mapping) and isinstance(result.get("items"), list):
        result["items"] = [item for item in result["items"] if _visible_to(item, ctx)]
        return
    if isinstance(result, list):
        ctx["result"] = [item for item in result if _visible_to(item, ctx)]
    elif result is not None and not _visible_to(result, ctx):
        raise LookupError("resource not found")


def _object_id(ctx: Mapping[str, Any]) -> str:
    obj = ctx.get("obj")
    value = getattr(obj, "id", None)
    result = ctx.get("result")
    if value is None:
        value = result.get("id") if isinstance(result, Mapping) else getattr(result, "id", None)
    if value is None and isinstance(ctx.get("payload"), Mapping):
        value = ctx["payload"].get("id", "collection")
    return str(value if value is not None else "collection")


def _details(ctx: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(ctx.get("payload") or {})
    for secret in {
        "password",
        "old_password",
        "new_password",
        "secret",
        "token",
        "private_key",
        "certificate",
        "certificate_key",
    }:
        if secret in payload:
            payload[secret] = "[redacted]"
    return payload


def _object_type(ctx: Mapping[str, Any]) -> str:
    table_name = _table_name(ctx)
    if table_name != "routing_hosts":
        return table_name
    temp = ctx.get("temp")
    if isinstance(temp, Mapping) and temp.get("object_type"):
        return str(temp["object_type"])
    result = ctx.get("result")
    payload = ctx.get("payload")
    kind = result.get("kind") if isinstance(result, Mapping) else getattr(result, "kind", None)
    if kind is None and isinstance(payload, Mapping):
        kind = payload.get("kind")
    return {
        "proxy": "proxy_hosts",
        "redirect": "redirection_hosts",
        "dead": "dead_hosts",
    }.get(str(kind), table_name)


async def audit_mutation(ctx: dict[str, Any]) -> None:
    """Stage one audit row in the mutation's kernel-owned transaction."""

    alias = _alias(ctx)
    table_name = _table_name(ctx)
    temp = ctx.setdefault("temp", {})
    if temp.get("portwyrm_audit_staged"):
        return
    if alias == "probe" and table_name == "routing_hosts":
        result = ctx.get("result")
        if hasattr(result, "model_dump"):
            result = result.model_dump(mode="python")
        if not isinstance(result, Mapping):
            return
        from portwyrm.kernel_support import select

        from .health import ProxyHostHealthObservationStore

        observations = list(
            (
                await _await(
                    ctx["db"].execute(
                        select(ProxyHostHealthObservationStore)
                        .where(ProxyHostHealthObservationStore.routing_host_id == int(result["id"]))
                        .order_by(
                            ProxyHostHealthObservationStore.checked_at.desc(),
                            ProxyHostHealthObservationStore.id.desc(),
                        )
                        .limit(2)
                    )
                )
            ).scalars()
        )
        if len(observations) < 2:
            return
        current = str(observations[0].status)
        previous = str(observations[1].status)
        if previous not in {"online", "offline"} or current == previous:
            return
        temp["portwyrm_audit_staged"] = True
        ctx["db"].add(
            AuditEventStore(
                actor_principal_id=_principal_id(ctx),
                action="proxy_host.health.changed",
                object_type="proxy_hosts",
                object_id=str(result["id"]),
                details={
                    "from": previous,
                    "to": current,
                    "phase": result.get("phase"),
                    "error_code": result.get("error_code"),
                },
            )
        )
        return
    if alias not in _MUTATIONS or table_name in _AUDIT_EXCLUDED_TABLES:
        return
    temp["portwyrm_audit_staged"] = True
    ctx["db"].add(
        AuditEventStore(
            actor_principal_id=_principal_id(ctx),
            action=_ACTION.get(alias, alias),
            object_type=_object_type(ctx),
            object_id=_object_id(ctx),
            details=_details(ctx),
        )
    )


async def reconcile_committed_change(ctx: dict[str, Any]) -> None:
    """Reconcile only after a relevant database mutation has committed."""

    table_name = _table_name(ctx)
    if _alias(ctx) not in _MUTATIONS or table_name not in _RECONCILE_TABLES:
        return
    temp = ctx.setdefault("temp", {})
    if temp.get("portwyrm_reconciled"):
        return
    temp["portwyrm_reconciled"] = True
    runtime = getattr(getattr(ctx.get("app"), "state", None), "runtime", None)
    if runtime is None:
        runtime = _runtime_provider()
    if runtime is not None:
        collection = _RECONCILE_COLLECTION.get(table_name, _object_type(ctx))
        try:
            await runtime.changed(collection)
        except Exception:
            # The kernel has already committed the resource mutation. The runtime
            # controller persists its failed reconcile attempt, so transport must
            # not report the durable write as rolled back.
            logger.exception("post-commit reconciliation failed for %s", collection)


async def remove_consumed_bootstrap_credentials(ctx: dict[str, Any]) -> None:
    """Discard the one-time bootstrap secret after its password change commits."""

    if _table_name(ctx) != "credentials" or _alias(ctx) != "change_password":
        return
    configured = os.getenv("PORTWYRM_BOOTSTRAP_CREDENTIAL_FILE")
    if not configured:
        return
    path = Path(configured)
    try:
        path.unlink(missing_ok=True)
    except OSError:
        logger.exception("failed to remove consumed bootstrap credential file")


async def schedule_committed_health_probe(ctx: dict[str, Any]) -> None:
    """Wake the scheduler after a committed proxy-host configuration change."""

    if _table_name(ctx) != "routing_hosts" or _alias(ctx) not in {
        "create",
        "update",
        "replace",
        "enable",
    }:
        return
    scheduler = getattr(getattr(ctx.get("app"), "state", None), "health_scheduler", None)
    if scheduler is not None:
        scheduler.wake()


def configure_lifecycle_runtime(provider: Callable[[], Any]) -> None:
    """Bind the active runtime controller used by the global post-commit hook."""

    global _runtime_provider
    _runtime_provider = provider


def global_hooks() -> dict[str, dict[str, list[Callable[..., Any]]]]:
    """Return hooks selected onto every table operation by the app router."""

    return {
        "*": {
            "PRE_HANDLER": [
                protect_model_descriptors,
                enforce_authorization,
                enforce_raw_nginx_policy,
                enforce_ownership,
            ],
            "POST_HANDLER": [enforce_visibility],
            "PRE_COMMIT": [audit_mutation],
            "POST_COMMIT": [
                reconcile_committed_change,
                schedule_committed_health_probe,
                remove_consumed_bootstrap_credentials,
            ],
        }
    }


__all__ = ["configure_lifecycle_runtime", "global_hooks"]
