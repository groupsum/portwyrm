"""Independent administrative, deployment, and reachability state contracts."""

from __future__ import annotations

from enum import StrEnum


class AdministrativeState(StrEnum):
    ENABLED = "enabled"
    DISABLED = "disabled"


class DeploymentState(StrEnum):
    PENDING = "pending"
    APPLYING = "applying"
    APPLIED = "applied"
    FAILED = "failed"
    DRIFTED = "drifted"
    ROLLED_BACK = "rolled_back"


class ReachabilityState(StrEnum):
    UNKNOWN = "unknown"
    PROBING = "probing"
    ONLINE = "online"
    OFFLINE = "offline"
    STALE = "stale"


class ProbePhase(StrEnum):
    DNS = "dns"
    CONNECT = "connect"
    TLS = "tls"
    HTTP = "http"


def derive_host_summary(
    administrative: AdministrativeState,
    deployment: DeploymentState,
    reachability: ReachabilityState,
) -> str:
    """Return the governed UI summary without discarding source dimensions."""

    if administrative == AdministrativeState.DISABLED:
        return AdministrativeState.DISABLED.value
    if deployment in {
        DeploymentState.FAILED,
        DeploymentState.DRIFTED,
        DeploymentState.ROLLED_BACK,
    }:
        return deployment.value
    if deployment in {DeploymentState.PENDING, DeploymentState.APPLYING}:
        return deployment.value
    return reachability.value


__all__ = [
    "AdministrativeState",
    "DeploymentState",
    "ProbePhase",
    "ReachabilityState",
    "derive_host_summary",
]
