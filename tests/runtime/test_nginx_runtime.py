from __future__ import annotations

from pathlib import Path

import pytest

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
from portwyrm.runtime import (
    GenerationStore,
    NginxRenderer,
    PlatformConfig,
    ReconcileError,
    Reconciler,
)


def test_proxy_render_covers_websocket_cache_tls_access_and_advanced_config() -> None:
    access = AccessList(
        8,
        "private",
        credentials=[AccessListCredential("alice", "$2y$hash")],
        clients=[AccessClient("10.0.0.0/8", "allow")],
        satisfy_any=True,
        pass_auth=False,
    )
    host = ProxyHost(
        id=2,
        domain_names=["app.example.com"],
        forward_scheme="https",
        forward_host="backend",
        forward_port=8443,
        access_list_id=8,
        ssl=SSLSettings(
            certificate_id=7,
            forced=True,
            http2=True,
            hsts=True,
            hsts_subdomains=True,
            trust_forwarded_proto=True,
        ),
        caching_enabled=True,
        block_exploits=True,
        allow_websocket_upgrade=True,
        advanced_config="client_max_body_size 2g;",
    )

    rendered = NginxRenderer().render(proxy_hosts=[host], access_lists=[access])
    config = rendered.files["http/proxy-2.conf"]

    assert "listen 443 ssl http2" in config
    assert "Strict-Transport-Security" in config and "includeSubDomains" in config
    assert "$http_x_forwarded_proto != https" in config
    assert "proxy_set_header Upgrade $http_upgrade" in config
    assert "proxy_cache_valid any 30m" in config
    assert "proxy_cache_valid 404 1m" in config
    assert "include conf.d/include/block-exploits.conf" in config
    assert "auth_basic_user_file /data/access/8" in config
    assert 'proxy_set_header Authorization ""' in config
    assert "allow 10.0.0.0/8" in config and "deny all" in config and "satisfy any" in config
    assert "client_max_body_size 2g" in config
    assert rendered.files["access/8"] == "alice:$2y$hash\n"


def test_custom_root_location_suppresses_generated_default() -> None:
    host = ProxyHost(
        id=1,
        domain_names=["app.example.com"],
        forward_scheme="http",
        forward_host="default-backend",
        forward_port=80,
        locations=[ProxyLocation("/", "http", "custom-backend", 9000, "/root")],
    )
    config = NginxRenderer().render(proxy_hosts=[host]).files["http/proxy-1.conf"]

    assert config.count("location / {") == 1
    assert "proxy_pass http://custom-backend:9000/root" in config


def test_redirect_dead_stream_and_platform_rendering() -> None:
    platform = PlatformConfig(
        ipv6=False,
        resolver_enabled=False,
        trusted_proxy_ranges=("10.0.0.0/8", "2001:db8::/32"),
        default_site="redirect",
        default_redirect="https://status.example.com",
        custom_includes={"root_top": "load_module modules/ngx_http_geoip2_module.so;"},
    )
    rendered = NginxRenderer(platform).render(
        redirection_hosts=[
            RedirectionHost(
                1,
                ["old.example.com"],
                "new.example.com",
                preserve_path=True,
                forward_http_code=308,
            )
        ],
        dead_hosts=[DeadHost(2, ["gone.example.com"], block_exploits=True)],
        streams=[
            Stream(
                3,
                9443,
                "tcp-backend",
                9000,
                tcp_forwarding=True,
                udp_forwarding=True,
                certificate_id=9,
            )
        ],
    )

    assert (
        "return 308 $scheme://new.example.com$request_uri"
        in rendered.files["http/redirection-1.conf"]
    )
    assert "return 404" in rendered.files["http/dead-2.conf"]
    assert "include conf.d/include/block-exploits.conf" in rendered.files["http/dead-2.conf"]
    stream = rendered.files["stream/stream-3.conf"]
    assert "listen 9443 ssl" in stream and "listen 9443 udp" in stream
    assert "listen [::]" not in stream
    assert "resolver " not in rendered.files["nginx.conf"]
    assert "return 301 https://status.example.com" in rendered.files["http/default.conf"]
    assert "set_real_ip_from 10.0.0.0/8" in rendered.files["include/trusted-proxies.conf"]
    assert rendered.files["custom/root_top.conf"].startswith("load_module")


def test_render_is_deterministic_across_input_order() -> None:
    first = ProxyHost(2, ["b.example.com"], "http", "b", 80)
    second = ProxyHost(1, ["a.example.com"], "http", "a", 80)
    renderer = NginxRenderer()

    left = renderer.render(proxy_hosts=[first, second])
    right = renderer.render(proxy_hosts=[second, first])

    assert left.files == right.files
    assert left.digest == right.digest


def test_reconciler_applies_and_is_idempotent(tmp_path: Path) -> None:
    validations: list[str] = []
    reloads: list[str] = []
    store = GenerationStore(tmp_path)
    reconciler = Reconciler(
        store,
        validator=lambda path: validations.append(path.name),
        reloader=lambda path: reloads.append(path.name),
    )

    first = reconciler.reconcile({"nginx.conf": "events {}\n"})
    second = reconciler.reconcile({"nginx.conf": "events {}\n"})

    assert first.applied and first.changed
    assert not second.changed
    assert store.active_id() == first.generation
    assert validations == [first.generation]
    assert reloads == [first.generation]


def test_validation_failure_never_activates_candidate(tmp_path: Path) -> None:
    store = GenerationStore(tmp_path)

    def fail(_path: Path) -> None:
        raise RuntimeError("syntax error")

    reconciler = Reconciler(store, validator=fail, reloader=lambda _path: None)
    with pytest.raises(ReconcileError, match="validation failed"):
        reconciler.reconcile({"nginx.conf": "invalid"})

    assert store.active_id() is None
    assert list(store.failed.glob("*.txt"))


def test_reload_failure_restores_last_known_good(tmp_path: Path) -> None:
    store = GenerationStore(tmp_path)
    reloads: list[str] = []

    def reload(path: Path) -> None:
        reloads.append(path.name)
        if (path / "nginx.conf").read_text(encoding="utf-8") == "bad reload\n":
            raise RuntimeError("reload refused")

    reconciler = Reconciler(store, validator=lambda _path: None, reloader=reload)
    good = reconciler.reconcile({"nginx.conf": "good\n"})

    with pytest.raises(ReconcileError, match="reload failed"):
        reconciler.reconcile({"nginx.conf": "bad reload\n"})

    assert store.active_id() == good.generation
    assert reloads[-1] == good.generation


def test_generation_store_rejects_path_traversal(tmp_path: Path) -> None:
    store = GenerationStore(tmp_path)
    with pytest.raises(ReconcileError, match="unsafe"):
        store.generation_id({"../outside": "bad"})
