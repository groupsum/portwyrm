"""Frozen NPM 2.15.1 DNS-01 provider catalog and execution port."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from typing import Protocol


@dataclass(frozen=True, slots=True)
class DNSProvider:
    id: str
    name: str
    package_name: str
    credential_fields: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DNSProviderStatus:
    installed: bool
    version: str | None
    support_tier: str


def provider_status(
    provider: DNSProvider,
    *,
    distribution_version=version,
) -> DNSProviderStatus:
    """Describe executable support without confusing catalog presence with installation."""

    try:
        installed_version = distribution_version(provider.package_name)
    except PackageNotFoundError:
        return DNSProviderStatus(installed=False, version=None, support_tier="catalog")
    return DNSProviderStatus(
        installed=True,
        version=str(installed_version),
        support_tier="installed-unqualified",
    )


class DNSProviderExecutor(Protocol):
    """Isolated provider execution boundary."""

    def present(self, provider: DNSProvider, fqdn: str, value: str, credentials: str) -> None: ...

    def cleanup(self, provider: DNSProvider, fqdn: str, value: str, credentials: str) -> None: ...


class DNSProviderCatalog:
    def __init__(self, providers: Iterable[DNSProvider]) -> None:
        values = tuple(providers)
        by_id = {provider.id: provider for provider in values}
        if len(values) != len(by_id):
            raise ValueError("DNS provider ids must be unique")
        self._providers = values
        self._by_id = by_id

    def __len__(self) -> int:
        return len(self._providers)

    def __iter__(self):
        return iter(self._providers)

    def get(self, provider_id: str) -> DNSProvider:
        try:
            return self._by_id[provider_id]
        except KeyError as exc:
            raise KeyError(f"unknown DNS provider: {provider_id}") from exc

    def validate_credentials(self, provider_id: str, values: Mapping[str, str]) -> None:
        provider = self.get(provider_id)
        missing = [field for field in provider.credential_fields if not values.get(field)]
        if missing:
            raise ValueError(f"missing {provider.name} credential fields: {', '.join(missing)}")


_PROVIDERS = (
    ("acmedns", "ACME-DNS"),
    ("active24", "Active24"),
    ("aliyun", "Aliyun"),
    ("arvan", "ArvanCloud"),
    ("azure", "Azure"),
    ("baidu", "Baidu"),
    ("beget", "Beget"),
    ("bunny", "bunny.net"),
    ("cdmon", "cdmon"),
    ("cloudflare", "Cloudflare"),
    ("cloudns", "ClouDNS"),
    ("cloudxns", "CloudXNS"),
    ("constellix", "Constellix"),
    ("corenetworks", "Core Networks"),
    ("cpanel", "cPanel"),
    ("ddnss", "DDNSS"),
    ("desec", "deSEC"),
    ("digitalocean", "DigitalOcean"),
    ("directadmin", "DirectAdmin"),
    ("dnsimple", "DNSimple"),
    ("dnsmadeeasy", "DNS Made Easy"),
    ("dnsmulti", "DnsMulti"),
    ("dnspod", "DNSPod"),
    ("domainoffensive", "DomainOffensive (do.de)"),
    ("domeneshop", "Domeneshop"),
    ("duckdns", "DuckDNS"),
    ("dynu", "Dynu"),
    ("easydns", "easyDNS"),
    ("edgedns", "Akamai Edge DNS"),
    ("eurodns", "EuroDNS"),
    ("firstdomains", "First Domains"),
    ("freedns", "FreeDNS"),
    ("gandi", "Gandi Live DNS"),
    ("gcore", "Gcore DNS"),
    ("glesys", "Glesys"),
    ("godaddy", "GoDaddy"),
    ("google", "Google"),
    ("googledomains", "GoogleDomainsDNS"),
    ("he", "Hurricane Electric"),
    ("he-ddns", "Hurricane Electric - DDNS"),
    ("hetzner", "Hetzner"),
    ("hetzner-cloud", "Hetzner Cloud"),
    ("hostinger", "Hostinger.com"),
    ("hostingnl", "Hosting.nl"),
    ("hover", "Hover"),
    ("hosterby", "hoster.by"),
    ("infomaniak", "Infomaniak"),
    ("inwx", "INWX"),
    ("ionos", "IONOS"),
    ("ispconfig", "ISPConfig"),
    ("isset", "Isset"),
    ("joker", "Joker"),
    ("kas", "All-Inkl"),
    ("leaseweb", "LeaseWeb"),
    ("linode", "Linode"),
    ("loopia", "Loopia"),
    ("luadns", "LuaDNS"),
    ("mchost24", "MC-HOST24"),
    ("mijnhost", "mijn.host"),
    ("namecheap", "Namecheap"),
    ("namecom", "Name.com"),
    ("netcup", "netcup"),
    ("nicru", "nic.ru"),
    ("njalla", "Njalla"),
    ("nsone", "NS1"),
    ("oci", "Oracle Cloud Infrastructure DNS"),
    ("ovh", "OVH"),
    ("plesk", "Plesk"),
    ("porkbun", "Porkbun"),
    ("powerdns", "PowerDNS"),
    ("regru", "reg.ru"),
    ("rfc2136", "RFC 2136"),
    ("rockenstein", "rockenstein AG"),
    ("route53", "Route 53 (Amazon)"),
    ("selectelv2", "Selectel api v2"),
    ("simply", "Simply"),
    ("spaceship", "Spaceship"),
    ("strato", "Strato"),
    ("tencentcloud", "Tencent Cloud"),
    ("timeweb", "Timeweb Cloud"),
    ("transip", "TransIP"),
    ("vultr", "Vultr"),
    ("websupport", "Websupport.sk"),
    ("wedos", "Wedos"),
    ("zoneedit", "ZoneEdit"),
    ("rcode0", "RcodeZero"),
)

_CREDENTIAL_FIELDS = {
    "cloudflare": ("dns_cloudflare_api_token",),
    "digitalocean": ("dns_digitalocean_token",),
    "duckdns": ("dns_duckdns_token",),
    "route53": ("aws_access_key_id", "aws_secret_access_key"),
    "rfc2136": ("dns_rfc2136_server", "dns_rfc2136_name", "dns_rfc2136_secret"),
}

DEFAULT_PROVIDER_CATALOG = DNSProviderCatalog(
    DNSProvider(
        provider_id,
        name,
        "certbot-dns-acmedns" if provider_id == "acmedns" else f"certbot-dns-{provider_id}",
        _CREDENTIAL_FIELDS.get(provider_id, ()),
    )
    for provider_id, name in _PROVIDERS
)
