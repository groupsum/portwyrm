from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from portwyrm.certificates import (
    DEFAULT_PROVIDER_CATALOG,
    ACMEOrder,
    CertificateLifecycle,
    CertificateManager,
    CertificateMaterialStore,
    CertificateRequest,
    Challenge,
    ChallengeType,
    CustomCertificateBundle,
    IssuedCertificate,
    OpenSSLPEMValidator,
    PEMValidationError,
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


def fake_openssl(*args, **kwargs) -> subprocess.CompletedProcess[str]:
    command = args[0]
    if "-subject" in command:
        stdout = (
            "subject=CN = app.example.com\n"
            "issuer=CN = Test CA\n"
            "serial=01AB\n"
            "notBefore=Jan  1 00:00:00 2025 GMT\n"
            "notAfter=Jan  1 00:00:00 2030 GMT\n"
            "X509v3 Subject Alternative Name:\n"
            "    DNS:app.example.com, DNS:www.example.com\n"
        )
    else:
        stdout = PUBLIC_KEY
    return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")


def test_custom_certificate_validates_dates_domains_and_key() -> None:
    validator = OpenSSLPEMValidator(runner=fake_openssl)
    info = validator.validate(
        CustomCertificateBundle(CERTIFICATE, PRIVATE_KEY, CERTIFICATE),
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert info.subject == "CN = app.example.com"
    assert info.serial == "01AB"
    assert info.domain_names == ("app.example.com", "www.example.com")


def test_malformed_certificate_is_rejected_before_openssl() -> None:
    validator = OpenSSLPEMValidator(runner=fake_openssl)
    with pytest.raises(PEMValidationError, match="not a PEM"):
        validator.validate(CustomCertificateBundle("garbage", PRIVATE_KEY))


def test_mismatched_private_key_is_rejected() -> None:
    def mismatch(*args, **kwargs) -> subprocess.CompletedProcess[str]:
        command = args[0]
        result = fake_openssl(*args, **kwargs)
        if "pkey" in command:
            return subprocess.CompletedProcess(command, 0, stdout="different", stderr="")
        return result

    with pytest.raises(PEMValidationError, match="do not match"):
        OpenSSLPEMValidator(runner=mismatch).validate(
            CustomCertificateBundle(CERTIFICATE, PRIVATE_KEY),
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )


class FakeClient:
    def __init__(self, *, fail_validation: bool = False) -> None:
        self.fail_validation = fail_validation

    def create_order(self, domains, *, challenge_type, key_type):
        return ACMEOrder(
            "order-1",
            domains,
            tuple(
                Challenge(challenge_type, domain, f"token-{domain}", "value") for domain in domains
            ),
        )

    def validate_challenges(self, order):
        if self.fail_validation:
            raise RuntimeError("challenge failed")

    def finalize(self, order):
        return IssuedCertificate(
            CERTIFICATE,
            PRIVATE_KEY,
            CERTIFICATE,
            datetime.now(UTC) + timedelta(days=90),
        )


class RecordingHandler:
    def __init__(self) -> None:
        self.presented: list[str] = []
        self.cleaned: list[str] = []

    def present(self, challenge):
        self.presented.append(challenge.identifier)

    def cleanup(self, challenge):
        self.cleaned.append(challenge.identifier)


def test_acme_issue_presents_and_cleans_every_challenge() -> None:
    handler = RecordingHandler()
    result = CertificateLifecycle(FakeClient(), handler).issue(("app.example.com",))

    assert result.certificate == CERTIFICATE
    assert handler.presented == ["app.example.com"]
    assert handler.cleaned == ["app.example.com"]


def test_acme_failure_still_cleans_presented_challenges() -> None:
    handler = RecordingHandler()
    with pytest.raises(RuntimeError, match="challenge failed"):
        CertificateLifecycle(FakeClient(fail_validation=True), handler).issue(("app.example.com",))
    assert handler.cleaned == ["app.example.com"]


def test_wildcard_requires_dns01_and_renewal_window_is_30_days() -> None:
    handler = RecordingHandler()
    lifecycle = CertificateLifecycle(FakeClient(), handler)
    with pytest.raises(ValueError, match="DNS-01"):
        lifecycle.issue(("*.example.com",), challenge_type=ChallengeType.HTTP_01)

    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert lifecycle.renewal_due(now + timedelta(days=29), now=now)
    assert not lifecycle.renewal_due(now + timedelta(days=31), now=now)


def test_frozen_provider_catalog_has_86_unique_entries_and_validates_known_fields() -> None:
    assert len(DEFAULT_PROVIDER_CATALOG) == 86
    assert DEFAULT_PROVIDER_CATALOG.get("cloudflare").name == "Cloudflare"
    assert DEFAULT_PROVIDER_CATALOG.get("route53").name == "Route 53 (Amazon)"

    with pytest.raises(ValueError, match="dns_cloudflare_api_token"):
        DEFAULT_PROVIDER_CATALOG.validate_credentials("cloudflare", {})
    DEFAULT_PROVIDER_CATALOG.validate_credentials(
        "cloudflare", {"dns_cloudflare_api_token": "redacted"}
    )


class FakeIssuer:
    def issue(self, domains, **kwargs):
        assert domains == ("app.example.com",)
        assert kwargs["email"] == "admin@example.test"
        return IssuedCertificate(
            CERTIFICATE,
            PRIVATE_KEY,
            CERTIFICATE,
            datetime(2030, 1, 1, tzinfo=UTC),
        )


def test_certificate_manager_atomically_publishes_custom_and_acme_material(tmp_path: Path) -> None:
    from portwyrm.service import ControlPlane

    service = ControlPlane()
    manager = CertificateManager(
        service,
        CertificateMaterialStore(tmp_path / "live"),
        validator=OpenSSLPEMValidator(runner=fake_openssl),
        issuer=FakeIssuer(),
    )
    custom = manager.upload(
        CustomCertificateBundle(CERTIFICATE, PRIVATE_KEY, CERTIFICATE), nice_name="Custom"
    )
    custom_root = tmp_path / "live" / f"npm-{custom['id']}"
    assert (custom_root / "fullchain.pem").read_text(encoding="utf-8").count(
        "BEGIN CERTIFICATE"
    ) == 2
    assert "private_key" not in custom

    acme = manager.request(
        CertificateRequest(
            "Automatic",
            ("app.example.com",),
            "admin@example.test",
            ChallengeType.HTTP_01,
        )
    )
    assert acme["provider"] == "letsencrypt"
    assert (tmp_path / "live" / f"npm-{acme['id']}" / "privkey.pem").is_file()


def test_certificate_manager_refuses_delete_while_certificate_is_assigned(tmp_path: Path) -> None:
    from portwyrm.service import Conflict, ControlPlane

    service = ControlPlane()
    manager = CertificateManager(
        service,
        CertificateMaterialStore(tmp_path / "live"),
        validator=OpenSSLPEMValidator(runner=fake_openssl),
    )
    certificate = manager.upload(
        CustomCertificateBundle(CERTIFICATE, PRIVATE_KEY), nice_name="Assigned"
    )
    service.create(
        "proxy-hosts",
        {
            "domain_names": ["secure.example.com"],
            "forward_scheme": "http",
            "forward_host": "app",
            "forward_port": 8080,
            "certificate_id": certificate["id"],
        },
    )
    with pytest.raises(Conflict, match="still assigned"):
        manager.delete(certificate["id"])
