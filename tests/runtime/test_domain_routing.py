from __future__ import annotations

import pytest

from portwyrm.domain import (
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


def proxy(host_id: int = 1, domains: list[str] | None = None) -> ProxyHost:
    return ProxyHost(
        id=host_id,
        domain_names=domains or ["app.example.com"],
        forward_scheme="http",
        forward_host="backend",
        forward_port=8080,
    )


def test_ownership_round_trip_and_foreign_mutation_is_fail_closed() -> None:
    ownership = Ownership("npmctl", "platform", "proxy.web")
    meta = ownership.apply_to({"unknown": {"preserved": True}})

    assert Ownership.from_meta(meta) == ownership
    assert meta["unknown"] == {"preserved": True}
    ownership.assert_mutable_by(managed_by="npmctl", owner="platform")

    with pytest.raises(OwnershipError, match="adoption"):
        ownership.assert_mutable_by(managed_by="portwyrm", owner="platform")
    ownership.assert_mutable_by(managed_by="portwyrm", owner="platform", adopt=True)


def test_partial_ownership_metadata_is_invalid() -> None:
    with pytest.raises(DomainValidationError, match="all three"):
        Ownership.from_meta({"managed_by": "npmctl", "owner": "platform"})


def test_ssl_dependencies_are_normalized_server_side() -> None:
    assert SSLSettings(forced=True, http2=True, hsts=True, hsts_subdomains=True).normalized() == (
        SSLSettings()
    )
    assert SSLSettings(certificate_id=4, hsts=True, hsts_subdomains=True).normalized() == (
        SSLSettings(certificate_id=4)
    )
    assert (
        SSLSettings(
            certificate_id=4,
            forced=True,
            http2=True,
            hsts=True,
            hsts_subdomains=True,
            trust_forwarded_proto=True,
        )
        .normalized()
        .hsts_subdomains
    )


def test_domains_are_canonical_and_cross_family_collisions_fail() -> None:
    first = proxy(domains=["App.Example.COM."])
    assert first.domain_names == ("app.example.com",)
    redirect = RedirectionHost(
        id=2,
        domain_names=["app.example.com"],
        forward_domain_name="target.example.com",
    )

    with pytest.raises(CollisionError, match="already used"):
        HostInventory(proxy_hosts=[first], redirection_hosts=[redirect])


def test_duplicate_domains_and_invalid_ports_fail_at_construction() -> None:
    with pytest.raises(DomainValidationError, match="duplicate"):
        proxy(domains=["a.example.com", "A.EXAMPLE.COM"])
    with pytest.raises(DomainValidationError, match="between 1 and 65535"):
        ProxyHost(
            id=1,
            domain_names=["a.example.com"],
            forward_scheme="http",
            forward_host="backend",
            forward_port=0,
        )


def test_proxy_location_invariants() -> None:
    with pytest.raises(DomainValidationError, match="start with"):
        ProxyLocation("api", "http", "backend", 80)
    with pytest.raises(DomainValidationError, match="unique"):
        ProxyHost(
            id=1,
            domain_names=["a.example.com"],
            forward_scheme="http",
            forward_host="backend",
            forward_port=80,
            locations=[
                ProxyLocation("/api", "http", "one", 80),
                ProxyLocation("/api", "http", "two", 80),
            ],
        )


def test_stream_protocol_collisions_are_scoped_by_protocol() -> None:
    tcp = Stream(1, 5353, "dns-a", 53, tcp_forwarding=True, udp_forwarding=False)
    udp = Stream(2, 5353, "dns-b", 53, tcp_forwarding=False, udp_forwarding=True)
    HostInventory(streams=[tcp, udp])

    with pytest.raises(CollisionError, match="5353/tcp"):
        HostInventory(
            streams=[
                tcp,
                Stream(3, 5353, "dns-c", 53, tcp_forwarding=True, udp_forwarding=False),
            ]
        )


def test_stream_tls_requires_tcp() -> None:
    with pytest.raises(DomainValidationError, match="only for TCP"):
        Stream(
            1,
            5353,
            "dns",
            53,
            tcp_forwarding=False,
            udp_forwarding=True,
            certificate_id=7,
        )


def test_dead_host_is_a_valid_inventory_member() -> None:
    inventory = HostInventory(dead_hosts=[DeadHost(4, ["gone.example.com"])])
    assert inventory.dead_hosts[0].domain_names == ("gone.example.com",)
