"""Pure normalized-wire to Nginx domain projections."""

from __future__ import annotations

from typing import Any

from portwyrm.domain import (
    AccessClient,
    AccessList,
    AccessListCredential,
    DeadHost,
    ProxyHost,
    ProxyLocation,
    RedirectionHost,
    SSLSettings,
    Stream,
)


def ssl_settings(row: dict[str, Any]) -> SSLSettings:
    return SSLSettings(
        certificate_id=int(row.get("certificate_id") or 0),
        forced=bool(row.get("ssl_forced")),
        http2=bool(row.get("http2_support")),
        hsts=bool(row.get("hsts_enabled")),
        hsts_subdomains=bool(row.get("hsts_subdomains")),
        trust_forwarded_proto=bool(row.get("trust_forwarded_proto")),
    )


def proxy_host(row: dict[str, Any]) -> ProxyHost:
    return ProxyHost(
        id=int(row["id"]),
        domain_names=row["domain_names"],
        forward_scheme=row.get("forward_scheme", "http"),
        forward_host=row["forward_host"],
        forward_port=int(row["forward_port"]),
        owner_user_id=int(row.get("owner_user_id") or 1),
        access_list_id=int(row.get("access_list_id") or 0),
        access_list_ids=[int(value) for value in row.get("access_list_ids", [])],
        ssl=ssl_settings(row),
        caching_enabled=bool(row.get("caching_enabled")),
        block_exploits=bool(row.get("block_exploits")),
        allow_websocket_upgrade=bool(row.get("allow_websocket_upgrade")),
        advanced_config=str(row.get("advanced_config") or ""),
        locations=[
            ProxyLocation(
                item["path"],
                item.get("forward_scheme", "http"),
                item["forward_host"],
                int(item["forward_port"]),
                str(item.get("forward_path") or ""),
                str(item.get("advanced_config") or ""),
            )
            for item in row.get("locations", [])
        ],
        enabled=bool(row.get("enabled", 1)),
        meta=row.get("meta", {}),
    )


def redirection_host(row: dict[str, Any]) -> RedirectionHost:
    return RedirectionHost(
        int(row["id"]),
        row["domain_names"],
        row["forward_domain_name"],
        row.get("forward_scheme", "auto"),
        int(row.get("forward_http_code", 301)),
        bool(row.get("preserve_path")),
        int(row.get("owner_user_id") or 1),
        ssl_settings(row),
        bool(row.get("block_exploits")),
        str(row.get("advanced_config") or ""),
        bool(row.get("enabled", 1)),
        row.get("meta", {}),
    )


def dead_host(row: dict[str, Any]) -> DeadHost:
    return DeadHost(
        int(row["id"]),
        row["domain_names"],
        int(row.get("owner_user_id") or 1),
        ssl_settings(row),
        bool(row.get("block_exploits")),
        str(row.get("advanced_config") or ""),
        bool(row.get("enabled", 1)),
        row.get("meta", {}),
    )


def stream(row: dict[str, Any]) -> Stream:
    return Stream(
        int(row["id"]),
        int(row["incoming_port"]),
        row["forwarding_host"],
        int(row["forwarding_port"]),
        bool(row.get("tcp_forwarding")),
        bool(row.get("udp_forwarding")),
        int(row.get("owner_user_id") or 1),
        int(row.get("certificate_id") or 0),
        bool(row.get("enabled", 1)),
        row.get("meta", {}),
    )


def access_list(row: dict[str, Any]) -> AccessList:
    return AccessList(
        int(row["id"]),
        str(row["name"]),
        [
            AccessListCredential(str(item["username"]), str(item["password"]))
            for item in row.get("items", [])
        ],
        [
            AccessClient(str(item["address"]), str(item["directive"]))
            for item in row.get("clients", [])
        ],
        bool(row.get("satisfy_any")),
        bool(row.get("pass_auth")),
        int(row.get("owner_user_id") or 1),
        dict(row.get("meta") or {}),
    )


__all__ = ["access_list", "dead_host", "proxy_host", "redirection_host", "ssl_settings", "stream"]
