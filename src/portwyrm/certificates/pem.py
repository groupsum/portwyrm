"""Custom PEM bundle validation through an injectable OpenSSL inspector."""

from __future__ import annotations

import re
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


class PEMValidationError(ValueError):
    """Certificate material is malformed, expired, or does not match its key."""


Runner = Callable[..., subprocess.CompletedProcess[str]]

_CERTIFICATE_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----",
    re.MULTILINE,
)
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----\s+"
    r"[A-Za-z0-9+/=\r\n]+-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----",
    re.MULTILINE,
)


@dataclass(frozen=True, slots=True)
class CustomCertificateBundle:
    certificate: str
    private_key: str
    intermediate_certificate: str = ""

    @property
    def fullchain(self) -> str:
        values = [self.certificate.strip()]
        if self.intermediate_certificate.strip():
            values.append(self.intermediate_certificate.strip())
        return "\n".join(values) + "\n"


@dataclass(frozen=True, slots=True)
class CertificateInfo:
    subject: str
    issuer: str
    serial: str
    not_before: datetime
    not_after: datetime
    domain_names: tuple[str, ...]


class OpenSSLPEMValidator:
    """Validate certificate shape, dates, and public-key equality using OpenSSL."""

    def __init__(self, openssl_binary: str = "openssl", *, runner: Runner = subprocess.run) -> None:
        self.openssl_binary = openssl_binary
        self.runner = runner

    @staticmethod
    def _validate_shape(bundle: CustomCertificateBundle) -> None:
        if not _CERTIFICATE_RE.search(bundle.certificate):
            raise PEMValidationError("certificate is not a PEM certificate")
        if not _PRIVATE_KEY_RE.search(bundle.private_key):
            raise PEMValidationError("private key is not a supported PEM private key")
        if bundle.intermediate_certificate and not _CERTIFICATE_RE.search(
            bundle.intermediate_certificate
        ):
            raise PEMValidationError("intermediate is not a PEM certificate")

    def _run(self, args: Sequence[str], *, input_text: str | None = None) -> str:
        result = self.runner(
            list(args),
            input=input_text,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode:
            raise PEMValidationError((result.stderr or result.stdout or "OpenSSL failed").strip())
        return result.stdout

    def validate(
        self,
        bundle: CustomCertificateBundle,
        *,
        now: datetime | None = None,
    ) -> CertificateInfo:
        self._validate_shape(bundle)
        instant = now or datetime.now(UTC)
        with tempfile.TemporaryDirectory(prefix="portwyrm-cert-") as directory:
            root = Path(directory)
            cert_path = root / "certificate.pem"
            key_path = root / "private-key.pem"
            cert_path.write_text(bundle.certificate, encoding="utf-8")
            key_path.write_text(bundle.private_key, encoding="utf-8")

            details = self._run(
                [
                    self.openssl_binary,
                    "x509",
                    "-in",
                    str(cert_path),
                    "-noout",
                    "-subject",
                    "-issuer",
                    "-serial",
                    "-dates",
                    "-ext",
                    "subjectAltName",
                ]
            )
            cert_public = self._run(
                [self.openssl_binary, "x509", "-in", str(cert_path), "-pubkey", "-noout"]
            )
            key_public = self._run([self.openssl_binary, "pkey", "-in", str(key_path), "-pubout"])

        if "".join(cert_public.split()) != "".join(key_public.split()):
            raise PEMValidationError("certificate and private key do not match")
        info = self._parse_details(details)
        if instant < info.not_before:
            raise PEMValidationError("certificate is not yet valid")
        if instant >= info.not_after:
            raise PEMValidationError("certificate has expired")
        return info

    @staticmethod
    def _parse_details(details: str) -> CertificateInfo:
        values: dict[str, str] = {}
        domains: list[str] = []
        for line in details.splitlines():
            stripped = line.strip()
            if "=" in stripped:
                key, value = stripped.split("=", 1)
                values[key.lower()] = value.strip()
            if "DNS:" in stripped:
                for entry in stripped.split(","):
                    domain = entry.replace("DNS:", "").strip().lower()
                    if domain:
                        domains.append(domain)
        try:
            not_before = datetime.strptime(values["notbefore"], "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=UTC
            )
            not_after = datetime.strptime(values["notafter"], "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=UTC
            )
        except (KeyError, ValueError) as exc:
            raise PEMValidationError("OpenSSL did not return parseable certificate dates") from exc
        return CertificateInfo(
            subject=values.get("subject", ""),
            issuer=values.get("issuer", ""),
            serial=values.get("serial", ""),
            not_before=not_before,
            not_after=not_after,
            domain_names=tuple(dict.fromkeys(domains)),
        )
