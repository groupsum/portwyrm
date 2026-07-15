"""Translate desired-state records into an active Nginx generation."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
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
from portwyrm.runtime.hooks import NginxCommandHooks
from portwyrm.runtime.nginx import NginxRenderer
from portwyrm.runtime.reconcile import GenerationStore, Reconciler, ReconcileResult

ROUTING_COLLECTIONS = {
    "proxy-hosts",
    "redirection-hosts",
    "dead-hosts",
    "streams",
    "access-lists",
    "certificates",
    "settings",
}


def _ssl(row: dict[str, Any]) -> SSLSettings:
    return SSLSettings(
        certificate_id=int(row.get("certificate_id") or 0),
        forced=bool(row.get("ssl_forced")),
        http2=bool(row.get("http2_support")),
        hsts=bool(row.get("hsts_enabled")),
        hsts_subdomains=bool(row.get("hsts_subdomains")),
        trust_forwarded_proto=bool(row.get("trust_forwarded_proto")),
    )


class RuntimeCoordinator:
    """Render, validate, activate, expose, and reload Nginx configuration."""

    def __init__(
        self,
        service: Any,
        root: str | Path,
        *,
        validate: bool = True,
        reload: bool = True,
    ) -> None:
        self.service = service
        self.root = Path(root)
        self.current = self.root / "current"
        hooks = NginxCommandHooks()
        validator = hooks.validate if validate else (lambda _path: None)
        reloader = self._reload if reload else self._publish
        self.reconciler = Reconciler(
            GenerationStore(self.root), validator=validator, reloader=reloader
        )

    def changed(self, collection: str) -> ReconcileResult | None:
        if collection in ROUTING_COLLECTIONS:
            return self.reconcile()
        return None

    def reconcile(self) -> ReconcileResult:
        rendered = NginxRenderer().render(
            proxy_hosts=[self._proxy(row) for row in self.service.list("proxy-hosts")],
            redirection_hosts=[
                self._redirection(row) for row in self.service.list("redirection-hosts")
            ],
            dead_hosts=[self._dead(row) for row in self.service.list("dead-hosts")],
            streams=[self._stream(row) for row in self.service.list("streams")],
            access_lists=[self._access(row) for row in self.service.list("access-lists")],
        )
        return self.reconciler.reconcile(rendered.files)

    def _publish(self, generation: Path) -> None:
        if os.name != "nt":
            temporary_link = self.root / f".current-{os.getpid()}"
            temporary_link.unlink(missing_ok=True)
            temporary_link.symlink_to(generation.resolve(), target_is_directory=True)
            if self.current.is_dir() and not self.current.is_symlink():
                shutil.rmtree(self.current)
            os.replace(temporary_link, self.current)
            return
        temporary = self.root / f".current-{os.getpid()}"
        if temporary.exists():
            shutil.rmtree(temporary)
        shutil.copytree(generation, temporary)
        if self.current.exists():
            shutil.rmtree(self.current)
        os.replace(temporary, self.current)

    def _reload(self, generation: Path) -> None:
        self._publish(generation)
        NginxCommandHooks().reload(self.current)

    @staticmethod
    def _proxy(row: dict[str, Any]) -> ProxyHost:
        return ProxyHost(
            id=int(row["id"]),
            domain_names=row["domain_names"],
            forward_scheme=row.get("forward_scheme", "http"),
            forward_host=row["forward_host"],
            forward_port=int(row["forward_port"]),
            owner_user_id=int(row.get("owner_user_id") or 1),
            access_list_id=int(row.get("access_list_id") or 0),
            access_list_ids=[int(value) for value in row.get("access_list_ids", [])],
            ssl=_ssl(row),
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

    @staticmethod
    def _redirection(row: dict[str, Any]) -> RedirectionHost:
        return RedirectionHost(
            int(row["id"]),
            row["domain_names"],
            row["forward_domain_name"],
            row.get("forward_scheme", "auto"),
            int(row.get("forward_http_code", 301)),
            bool(row.get("preserve_path")),
            int(row.get("owner_user_id") or 1),
            _ssl(row),
            bool(row.get("block_exploits")),
            str(row.get("advanced_config") or ""),
            bool(row.get("enabled", 1)),
            row.get("meta", {}),
        )

    @staticmethod
    def _dead(row: dict[str, Any]) -> DeadHost:
        return DeadHost(
            int(row["id"]),
            row["domain_names"],
            int(row.get("owner_user_id") or 1),
            _ssl(row),
            bool(row.get("block_exploits")),
            str(row.get("advanced_config") or ""),
            bool(row.get("enabled", 1)),
            row.get("meta", {}),
        )

    @staticmethod
    def _stream(row: dict[str, Any]) -> Stream:
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

    def _access(self, row: dict[str, Any]) -> AccessList:
        credentials = row.get("items", row.get("credentials", []))
        identity_credentials = [
            self.service.access_list_credential(user_id)
            for user_id in row.get("identity_ids", [])
        ]
        return AccessList(
            int(row["id"]),
            row["name"],
            [AccessListCredential(item["username"], item["password"]) for item in credentials]
            + [
                AccessListCredential(username, password)
                for username, password in identity_credentials
            ],
            [AccessClient(item["address"], item["directive"]) for item in row.get("clients", [])],
            bool(row.get("satisfy_any")),
            bool(row.get("pass_auth")),
            int(row.get("owner_user_id") or 1),
            row.get("meta", {}),
        )
