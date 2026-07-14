from __future__ import annotations

import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, Lock

import pytest

from portwyrm.certificates import (
    DEFAULT_PROVIDER_CATALOG,
    ACMEOrder,
    CertificateLifecycle,
    Challenge,
    ChallengeType,
    CustomCertificateBundle,
    DNSProvider,
    DNSProviderCatalog,
    IssuedCertificate,
    OpenSSLPEMValidator,
    PEMValidationError,
)
from portwyrm.domain import (
    AccessClient,
    AccessList,
    AccessListCredential,
    CollisionError,
    DeadHost,
    DomainValidationError,
    HostInventory,
    Ownership,
    OwnershipError,
    ProxyHost,
    ProxyLocation,
    RedirectionHost,
    SSLSettings,
    Stream,
)
from portwyrm.domain.ownership import assert_owner_scoped_prune
from portwyrm.runtime import (
    GenerationStore,
    NginxRenderer,
    PlatformConfig,
    ReconcileError,
    Reconciler,
)

CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----
"""
PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
MIIB
-----END PRIVATE KEY-----
"""
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
PUB
-----END PUBLIC KEY-----
"""


def _proxy(host_id: int, *domains: str, **overrides: object) -> ProxyHost:
    values = {
        "id": host_id,
        "domain_names": list(domains),
        "forward_scheme": "http",
        "forward_host": f"backend-{host_id}",
        "forward_port": 8000 + host_id,
    }
    values.update(overrides)
    return ProxyHost(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("foreign", "message"),
    [
        (None, "unmanaged"),
        (Ownership("npmctl", "another-team", "proxy.other"), "adoption"),
        (Ownership("portwyrm", "platform", "proxy.other"), "adoption"),
    ],
)
def test_owner_scoped_prune_fails_closed_for_every_foreign_selection(
    foreign: Ownership | None, message: str
) -> None:
    selected = [Ownership("npmctl", "platform", "proxy.mine"), foreign]

    with pytest.raises(OwnershipError, match=message):
        assert_owner_scoped_prune(selected, managed_by="npmctl", owner="platform")


def test_cross_family_domain_collision_is_atomic_and_case_insensitive() -> None:
    proxy = _proxy(1, "API.Example.COM.", "www.example.com")
    dead = DeadHost(2, ["api.example.com"])
    redirect = RedirectionHost(3, ["legacy.example.com"], "www.example.com")

    with pytest.raises(CollisionError, match=r"api\.example\.com.*proxy host 1"):
        HostInventory(proxy_hosts=[proxy], dead_hosts=[dead], redirection_hosts=[redirect])

    assert proxy.domain_names == ("api.example.com", "www.example.com")
    assert dead.domain_names == ("api.example.com",)


def test_stream_collision_namespace_separates_protocol_but_rejects_overlap() -> None:
    tcp = Stream(1, 443, "tcp", 8443, tcp_forwarding=True, udp_forwarding=False)
    udp = Stream(2, 443, "udp", 8443, tcp_forwarding=False, udp_forwarding=True)
    HostInventory(streams=[tcp, udp])

    dual = Stream(3, 443, "dual", 8443, tcp_forwarding=True, udp_forwarding=True)
    with pytest.raises(CollisionError, match="443/tcp"):
        HostInventory(streams=[tcp, udp, dual])


@pytest.mark.parametrize(
    "factory",
    [
        lambda: AccessClient("not-an-ip", "allow"),
        lambda: AccessListCredential("root:admin", "hash"),
        lambda: ProxyLocation("relative", "http", "upstream", 80),
        lambda: Stream(1, 443, "upstream", 443, False, False),
    ],
)
def test_invalid_routing_inputs_are_rejected_before_render(factory: object) -> None:
    with pytest.raises((DomainValidationError, ValueError)):
        factory()  # type: ignore[operator]


def test_full_nginx_generation_is_byte_deterministic_under_permutations() -> None:
    access_a = AccessList(
        2,
        "two",
        credentials=[AccessListCredential("bob", "hash-b")],
        clients=[AccessClient("192.0.2.4/24", "allow")],
    )
    access_b = AccessList(1, "one", credentials=[AccessListCredential("alice", "hash-a")])
    proxies = [
        _proxy(
            2,
            "b.example.com",
            access_list_id=2,
            allow_websocket_upgrade=True,
            caching_enabled=True,
            locations=[ProxyLocation("/z", "https", "z", 9443, "/v2")],
        ),
        _proxy(1, "a.example.com", access_list_id=1),
    ]
    redirects = [
        RedirectionHost(2, ["r2.example.com"], "b.example.com"),
        RedirectionHost(1, ["r1.example.com"], "a.example.com"),
    ]
    dead = [DeadHost(2, ["d2.example.com"]), DeadHost(1, ["d1.example.com"])]
    streams = [
        Stream(2, 5353, "dns", 53, False, True),
        Stream(1, 9443, "tls", 443, True, False, certificate_id=9),
    ]
    renderer = NginxRenderer(
        PlatformConfig(
            resolver_addresses=("9.9.9.9", "1.1.1.1"),
            trusted_proxy_ranges=("2001:db8::/32", "10.0.0.0/8"),
            custom_includes={"server_proxy": "proxy_read_timeout 120s;"},
        )
    )

    left = renderer.render(
        proxy_hosts=proxies,
        redirection_hosts=redirects,
        dead_hosts=dead,
        streams=streams,
        access_lists=[access_a, access_b],
    )
    right = renderer.render(
        proxy_hosts=reversed(proxies),
        redirection_hosts=reversed(redirects),
        dead_hosts=reversed(dead),
        streams=reversed(streams),
        access_lists=[access_b, access_a],
    )

    assert left.files == right.files
    assert left.digest == right.digest
    assert left.files["access/1"] == "alice:hash-a\n"
    assert "listen 9443 ssl" in left.files["stream/stream-1.conf"]


def test_platform_and_advanced_config_boundaries_fail_closed() -> None:
    with pytest.raises(ValueError, match="unsupported default-site"):
        PlatformConfig(default_site="proxy")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="destination"):
        PlatformConfig(default_site="redirect")
    with pytest.raises(ValueError):
        PlatformConfig(trusted_proxy_ranges=("not-a-network",))

    renderer = NginxRenderer(PlatformConfig(custom_includes={"unknown": "unsafe;"}))
    with pytest.raises(ValueError, match="unsupported custom include"):
        renderer.render()


def test_rendered_feature_interactions_do_not_weaken_access_or_tls() -> None:
    access = AccessList(
        7,
        "restricted",
        credentials=[AccessListCredential("alice", "hash")],
        clients=[AccessClient("10.0.0.0/8", "deny")],
        satisfy_any=False,
        pass_auth=False,
    )
    host = _proxy(
        7,
        "secure.example.com",
        access_list_id=7,
        ssl=SSLSettings(
            certificate_id=42,
            forced=True,
            http2=True,
            hsts=True,
            hsts_subdomains=True,
        ),
        allow_websocket_upgrade=True,
        caching_enabled=True,
        locations=[ProxyLocation("/api", "https", "api", 9443)],
        advanced_config="client_max_body_size 32m;",
    )

    config = (
        NginxRenderer().render(proxy_hosts=[host], access_lists=[access]).files["http/proxy-7.conf"]
    )

    assert config.count('auth_basic "Authorization required"') == 2
    assert config.count('proxy_set_header Authorization ""') == 2
    assert config.count("proxy_set_header Upgrade $http_upgrade") == 2
    assert "proxy_cache_use_stale error timeout updating" in config
    assert "Strict-Transport-Security" in config
    assert "return 301 https://$host$request_uri" in config


def test_invalid_candidate_preserves_last_known_good_and_diagnostic(tmp_path: Path) -> None:
    store = GenerationStore(tmp_path)

    def validate(path: Path) -> None:
        if "INVALID" in (path / "nginx.conf").read_text(encoding="utf-8"):
            raise RuntimeError("nginx -t: directive rejected")

    reloads: list[str] = []
    reconciler = Reconciler(
        store, validator=validate, reloader=lambda path: reloads.append(path.name)
    )
    good = reconciler.reconcile({"nginx.conf": "events {}\n"})

    with pytest.raises(ReconcileError, match="directive rejected"):
        reconciler.reconcile({"nginx.conf": "INVALID\n"})

    assert store.active_id() == good.generation
    assert reloads == [good.generation]
    diagnostics = [path.read_text(encoding="utf-8") for path in store.failed.glob("*.txt")]
    assert len(diagnostics) == 1
    assert "validation failed" in diagnostics[0]


def test_concurrent_reconciliation_serializes_complete_generations(tmp_path: Path) -> None:
    store = GenerationStore(tmp_path)
    gate = Barrier(3)
    events: list[tuple[str, str]] = []
    event_lock = Lock()

    def record(kind: str, path: Path) -> None:
        assert (path / "nginx.conf").is_file()
        with event_lock:
            events.append((kind, path.name))

    reconciler = Reconciler(
        store,
        validator=lambda path: record("validate", path),
        reloader=lambda path: record("reload", path),
    )

    def apply(contents: str):
        gate.wait()
        return reconciler.reconcile({"nginx.conf": contents})

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(apply, "events { worker_connections 64; }\n"),
            pool.submit(apply, "events { worker_connections 128; }\n"),
        ]
        gate.wait()
        results = [future.result(timeout=5) for future in futures]

    generations = {result.generation for result in results}
    assert len(generations) == 2
    assert store.active_id() in generations
    assert {path.name for path in store.generations.iterdir()} == generations
    assert [kind for kind, _generation in events].count("validate") == 2
    assert [kind for kind, _generation in events].count("reload") == 2
    assert not list(store.failed.iterdir())


def _openssl(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
    command = args[0]
    assert isinstance(command, list)
    if "-subject" in command:
        stdout = (
            "subject=CN = robust.example.com\n"
            "issuer=CN = Test CA\n"
            "serial=FF01\n"
            "notBefore=Jan  1 00:00:00 2025 GMT\n"
            "notAfter=Jan  1 00:00:00 2030 GMT\n"
            "X509v3 Subject Alternative Name:\n"
            "    DNS:robust.example.com\n"
        )
    else:
        stdout = PUBLIC_KEY
    return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")


@pytest.mark.parametrize(
    "bundle",
    [
        CustomCertificateBundle("certificate", PRIVATE_KEY),
        CustomCertificateBundle(CERTIFICATE, "private-key"),
        CustomCertificateBundle(CERTIFICATE, PRIVATE_KEY, "intermediate"),
    ],
)
def test_malformed_pem_components_never_reach_openssl(bundle: CustomCertificateBundle) -> None:
    calls: list[object] = []

    def should_not_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        raise AssertionError("OpenSSL must not run for malformed PEM")

    with pytest.raises(PEMValidationError, match="PEM"):
        OpenSSLPEMValidator(runner=should_not_run).validate(bundle)
    assert calls == []


def test_certificate_date_boundaries_fail_closed() -> None:
    validator = OpenSSLPEMValidator(runner=_openssl)
    bundle = CustomCertificateBundle(CERTIFICATE, PRIVATE_KEY)

    with pytest.raises(PEMValidationError, match="not yet valid"):
        validator.validate(bundle, now=datetime(2024, 12, 31, tzinfo=UTC))
    with pytest.raises(PEMValidationError, match="expired"):
        validator.validate(bundle, now=datetime(2030, 1, 1, tzinfo=UTC))


class _FailingClient:
    def __init__(self, failure: str) -> None:
        self.failure = failure

    def create_order(self, domains, *, challenge_type, key_type):
        challenges = tuple(
            Challenge(challenge_type, domain, f"token-{index}", f"value-{index}")
            for index, domain in enumerate(domains)
        )
        return ACMEOrder("robust-order", domains, challenges)

    def validate_challenges(self, order):
        if self.failure == "validate":
            raise RuntimeError("validation unavailable")

    def finalize(self, order):
        if self.failure == "finalize":
            raise RuntimeError("CA finalize unavailable")
        return IssuedCertificate(
            CERTIFICATE,
            PRIVATE_KEY,
            CERTIFICATE,
            datetime.now(UTC) + timedelta(days=90),
        )


class _FailingHandler:
    def __init__(self, fail_on_present: str | None = None) -> None:
        self.fail_on_present = fail_on_present
        self.presented: list[str] = []
        self.cleaned: list[str] = []

    def present(self, challenge):
        if challenge.identifier == self.fail_on_present:
            raise RuntimeError("provider present failed")
        self.presented.append(challenge.identifier)

    def cleanup(self, challenge):
        self.cleaned.append(challenge.identifier)


@pytest.mark.parametrize("failure", ["validate", "finalize"])
def test_acme_renewal_failure_cleans_all_challenges_in_reverse_order(failure: str) -> None:
    handler = _FailingHandler()
    lifecycle = CertificateLifecycle(_FailingClient(failure), handler)

    with pytest.raises(RuntimeError, match="unavailable"):
        lifecycle.issue(("one.example.com", "two.example.com"))

    assert handler.presented == ["one.example.com", "two.example.com"]
    assert handler.cleaned == ["two.example.com", "one.example.com"]


def test_dns_provider_present_failure_cleans_only_successfully_presented_inputs() -> None:
    handler = _FailingHandler(fail_on_present="two.example.com")
    lifecycle = CertificateLifecycle(_FailingClient("none"), handler)

    with pytest.raises(RuntimeError, match="provider present failed"):
        lifecycle.issue(("one.example.com", "two.example.com"), challenge_type=ChallengeType.DNS_01)

    assert handler.presented == ["one.example.com"]
    assert handler.cleaned == ["one.example.com"]


def test_dns_provider_catalog_keeps_credentials_outside_frozen_provider_identity() -> None:
    provider = DNSProvider("isolated", "Isolated", "certbot-dns-isolated", ("token",))
    catalog = DNSProviderCatalog([provider])
    credentials = {"token": "super-secret", "unexpected": "do-not-retain"}

    catalog.validate_credentials("isolated", credentials)
    credentials["token"] = "rotated"

    assert catalog.get("isolated") is provider
    assert "super-secret" not in repr(catalog.__dict__)
    with pytest.raises(AttributeError):
        provider.name = "mutated"  # type: ignore[misc]
    with pytest.raises(KeyError, match="unknown DNS provider"):
        DEFAULT_PROVIDER_CATALOG.get("../../shell")
