"""Deterministic assembly of complete Nginx configuration generations."""

from __future__ import annotations

from collections.abc import Iterable

from portwyrm.tables.access import RuntimeAccessList as AccessList
from portwyrm.tables.routing import DeadHost, ProxyHost, RedirectionHost, Stream

from .nginx_http import render_dead, render_proxy, render_redirection
from .nginx_models import PlatformConfig, RenderedConfiguration
from .nginx_platform import (
    render_block_exploits,
    render_default_site,
    render_main,
    render_proxy_include,
    render_status_site,
    render_trusted_proxies,
)
from .nginx_primitives import merge_access_lists, render_htpasswd
from .nginx_stream import render_stream

CUSTOM_INCLUDE_NAMES = (
    "root_top",
    "root",
    "http_top",
    "http",
    "events",
    "stream",
    "server_proxy",
    "server_redirect",
    "server_stream",
    "server_stream_tcp",
    "server_stream_udp",
    "server_dead",
)


class NginxRenderer:
    """Render complete deterministic generations from canonical table schemas."""

    def __init__(self, platform: PlatformConfig | None = None) -> None:
        self.platform = platform or PlatformConfig()

    def render(
        self,
        *,
        proxy_hosts: Iterable[ProxyHost] = (),
        redirection_hosts: Iterable[RedirectionHost] = (),
        dead_hosts: Iterable[DeadHost] = (),
        streams: Iterable[Stream] = (),
        access_lists: Iterable[AccessList] = (),
    ) -> RenderedConfiguration:
        access_lists = tuple(access_lists)
        access_by_id = {item.id: item for item in access_lists}
        files: dict[str, str] = {
            "nginx.conf": self.render_main(),
            "http/default.conf": self.render_default_site(),
            "http/status.conf": self.render_status_site(),
            "include/trusted-proxies.conf": self.render_trusted_proxies(),
            "conf.d/include/proxy.conf": self.render_proxy_include(),
            "conf.d/include/block-exploits.conf": self.render_block_exploits(),
            **{f"custom/{name}.conf": "" for name in CUSTOM_INCLUDE_NAMES},
        }
        if self.platform.default_site == "html":
            files["default_www/index.html"] = self.platform.default_html
        for access_list in sorted(access_lists, key=lambda item: item.id):
            files[f"access/{access_list.id}"] = self.render_htpasswd(access_list)
        for host in sorted(proxy_hosts, key=lambda item: item.id):
            selected_ids = host.access_list_ids or (
                (host.access_list_id,) if host.access_list_id else ()
            )
            selected = [access_by_id[item] for item in selected_ids if item in access_by_id]
            effective = self._merge_access_lists(selected)
            password_file = f"proxy-host-{host.id}" if len(selected) > 1 else None
            if password_file and effective is not None:
                files[f"access/{password_file}"] = self.render_htpasswd(effective)
            files[f"http/proxy-{host.id}.conf"] = self.render_proxy(host, effective, password_file)
        for host in sorted(redirection_hosts, key=lambda item: item.id):
            files[f"http/redirection-{host.id}.conf"] = self.render_redirection(host)
        for host in sorted(dead_hosts, key=lambda item: item.id):
            files[f"http/dead-{host.id}.conf"] = self.render_dead(host)
        for stream in sorted(streams, key=lambda item: item.id):
            files[f"stream/stream-{stream.id}.conf"] = self.render_stream(stream)
        for name, contents in sorted(self.platform.custom_includes.items()):
            if name not in CUSTOM_INCLUDE_NAMES:
                raise ValueError(f"unsupported custom include point: {name}")
            files[f"custom/{name}.conf"] = contents.rstrip() + "\n"
        return RenderedConfiguration(files)

    def render_main(self) -> str:
        return render_main(self.platform)

    @staticmethod
    def render_status_site() -> str:
        return render_status_site()

    @staticmethod
    def render_proxy_include() -> str:
        return render_proxy_include()

    @staticmethod
    def render_block_exploits() -> str:
        return render_block_exploits()

    def render_trusted_proxies(self) -> str:
        return render_trusted_proxies(self.platform)

    def render_default_site(self) -> str:
        return render_default_site(self.platform)

    @staticmethod
    def render_htpasswd(access_list: AccessList) -> str:
        return render_htpasswd(access_list)

    @staticmethod
    def _merge_access_lists(access_lists: list[AccessList]) -> AccessList | None:
        return merge_access_lists(access_lists)

    def render_proxy(
        self,
        host: ProxyHost,
        access_list: AccessList | None = None,
        password_file: str | None = None,
    ) -> str:
        return render_proxy(self.platform, host, access_list, password_file)

    def render_redirection(self, host: RedirectionHost) -> str:
        return render_redirection(self.platform, host)

    def render_dead(self, host: DeadHost) -> str:
        return render_dead(self.platform, host)

    def render_stream(self, stream: Stream) -> str:
        return render_stream(self.platform, stream)


__all__ = ["CUSTOM_INCLUDE_NAMES", "NginxRenderer", "PlatformConfig", "RenderedConfiguration"]
