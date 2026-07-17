"""T1 acceptance coverage for disabled proxy-host isolation."""

from portwyrm.domain import ProxyHost
from portwyrm.runtime import NginxRenderer


def test_disabled_proxy_host_has_an_explicit_non_proxying_server_block() -> None:
    host = ProxyHost(
        91, ["disabled.example.test"], "http", "must-not-receive-traffic", 8080, enabled=False
    )
    config = NginxRenderer().render(proxy_hosts=[host]).files["http/proxy-91.conf"]

    assert "server_name disabled.example.test" in config
    assert "return 503;" in config
    assert "proxy_pass" not in config
    assert "must-not-receive-traffic" not in config
    assert "default" not in config
