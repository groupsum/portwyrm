"""Immutable proxy-host reachability observations."""

from tigrbl.types import ForeignKey, Integer, String, Text

from .base import READ_ONLY_PROFILE, PortwyrmTable, acol


class ProxyHostHealthObservationStore(PortwyrmTable):
    __tablename__ = "proxy_host_health_observations"
    TABLE_PROFILE = READ_ONLY_PROFILE

    routing_host_id = acol(Integer, ForeignKey("routing_hosts.id"), nullable=False, index=True)
    status = acol(String(32), nullable=False, index=True)
    phase = acol(String(32), nullable=False)
    checked_at = acol(Integer, nullable=False, index=True)
    expires_at = acol(Integer, nullable=False, index=True)
    latency_ms = acol(Integer, nullable=True)
    http_status = acol(Integer, nullable=True)
    error_code = acol(String(128), nullable=True)
    error_detail = acol(Text, nullable=True)


ProxyHostHealthObservation = ProxyHostHealthObservationStore

__all__ = ["ProxyHostHealthObservation", "ProxyHostHealthObservationStore"]
