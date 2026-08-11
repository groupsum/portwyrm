"""Fail-closed personal-access-token scope and ownership policy."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from tigrbl_identity_contracts import ScopeMatcherPort, ScopeMatchRequest, ScopeMatchResult

from .permissions import PERMISSION_ACTIONS, PermissionAction, permission_allows

TOKEN_SCOPE_SECTIONS = frozenset(
    {
        "proxy_hosts",
        "redirection_hosts",
        "dead_hosts",
        "streams",
        "access_lists",
        "certificates",
    }
)
TOKEN_SCOPE_ACTIONS = frozenset(PERMISSION_ACTIONS)
FULL_ACCOUNT_SCOPE = "user"


@dataclass(frozen=True, slots=True)
class PortwyrmScopeMatcher(ScopeMatcherPort):
    """Match required scopes using the standalone Tigrbl Auth contract."""

    def match(self, request: ScopeMatchRequest, /) -> ScopeMatchResult:
        granted = tuple(dict.fromkeys(request.granted))
        required = tuple(dict.fromkeys(request.required))
        granted_set = set(granted)
        if request.mode not in {"all", "any"}:
            raise ValueError("unsupported scope matching mode")
        missing = tuple(scope for scope in required if scope not in granted_set)
        allowed = not missing if request.mode == "all" else bool(set(required) & granted_set)
        if not required:
            allowed = True
        return ScopeMatchResult(
            allowed=allowed,
            granted=granted,
            required=required,
            missing=missing,
        )


SCOPE_MATCHER: ScopeMatcherPort = PortwyrmScopeMatcher()


def parse_scope(scope: str) -> tuple[str, PermissionAction]:
    normalized = str(scope).strip().casefold().replace("-", "_")
    section, separator, action = normalized.partition(":")
    if not separator or section not in TOKEN_SCOPE_SECTIONS or action not in TOKEN_SCOPE_ACTIONS:
        raise ValueError("invalid token scopes")
    return section, action  # type: ignore[return-value]


def normalize_token_scopes(scopes: object) -> frozenset[str]:
    if not isinstance(scopes, (list, tuple, set, frozenset)):
        raise ValueError("invalid token scopes")
    normalized = frozenset(str(scope).strip().casefold().replace("-", "_") for scope in scopes)
    if not normalized or "" in normalized:
        raise ValueError("select at least one access scope")
    if normalized == {FULL_ACCOUNT_SCOPE}:
        return normalized
    resource_scopes = normalized - {FULL_ACCOUNT_SCOPE}
    if not resource_scopes:
        raise ValueError("select at least one access scope")
    for scope in resource_scopes:
        parse_scope(scope)
    return resource_scopes | {FULL_ACCOUNT_SCOPE}


def validate_requested_scopes(
    scopes: object,
    *,
    permissions: Mapping[str, Any],
    is_admin: bool,
) -> frozenset[str]:
    normalized = normalize_token_scopes(scopes)
    if normalized == {FULL_ACCOUNT_SCOPE}:
        return normalized
    required = tuple(sorted(normalized - {FULL_ACCOUNT_SCOPE}))
    granted: list[str] = []
    for scope in required:
        section, action = parse_scope(scope)
        if is_admin or permission_allows(permissions.get(section), action):
            granted.append(scope)
    match = SCOPE_MATCHER.match(
        ScopeMatchRequest(granted=tuple(granted), required=required, mode="all")
    )
    if not match.allowed:
        raise ValueError(f"scope exceeds account permission: {match.missing[0]}")
    return normalized


def permissions_from_scopes(scopes: object) -> dict[str, dict[str, bool]]:
    normalized = normalize_token_scopes(scopes)
    permissions: dict[str, dict[str, bool]] = {}
    for scope in normalized - {FULL_ACCOUNT_SCOPE}:
        section, action = parse_scope(scope)
        permissions.setdefault(section, {})[action] = True
    return permissions


def effective_token_authority(
    *,
    scopes: object,
    permissions: Mapping[str, Any],
    is_admin: bool,
) -> tuple[dict[str, Any], bool, frozenset[str]]:
    """Intersect durable principal authority with the token's granted scopes."""

    normalized = normalize_token_scopes(scopes)
    if normalized == {FULL_ACCOUNT_SCOPE}:
        return dict(permissions), is_admin, normalized
    effective: dict[str, dict[str, bool]] = {}
    for scope in normalized - {FULL_ACCOUNT_SCOPE}:
        section, action = parse_scope(scope)
        principal_granted = is_admin or permission_allows(permissions.get(section), action)
        match = SCOPE_MATCHER.match(
            ScopeMatchRequest(
                granted=(scope,) if principal_granted else (),
                required=(scope,),
                mode="all",
            )
        )
        if match.allowed:
            effective.setdefault(section, {})[action] = True
    return effective, False, normalized


def may_manage_foreign_tokens(principal: object, action: PermissionAction) -> bool:
    if bool(getattr(principal, "is_admin", False)):
        return True
    may = getattr(principal, "may", None)
    return bool(callable(may) and may("access_tokens", action=action))


__all__ = [
    "FULL_ACCOUNT_SCOPE",
    "SCOPE_MATCHER",
    "TOKEN_SCOPE_ACTIONS",
    "TOKEN_SCOPE_SECTIONS",
    "PortwyrmScopeMatcher",
    "effective_token_authority",
    "may_manage_foreign_tokens",
    "normalize_token_scopes",
    "parse_scope",
    "permissions_from_scopes",
    "validate_requested_scopes",
]
