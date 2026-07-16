"""Durable certificate material, issuance, renewal, and safe replacement."""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .acme import ChallengeType, IssuedCertificate
from .pem import CustomCertificateBundle, OpenSSLPEMValidator
from .providers import DEFAULT_PROVIDER_CATALOG, provider_status


class Issuer(Protocol):
    def issue(
        self,
        domains: tuple[str, ...],
        *,
        challenge_type: ChallengeType,
        key_type: str,
        email: str,
        provider: str | None = None,
        credentials_file: Path | None = None,
    ) -> IssuedCertificate: ...


class CertificateConflict(ValueError):
    """Certificate metadata conflicts with an assigned routing resource."""


@dataclass(frozen=True, slots=True)
class CertificateRequest:
    nice_name: str
    domain_names: tuple[str, ...]
    email: str
    challenge_type: ChallengeType = ChallengeType.HTTP_01
    key_type: str = "rsa"
    provider: str | None = None


class CertificateMaterialStore:
    """Atomically publish Nginx-compatible certificate directories."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _directory(self, certificate_id: int, *, prefix: str = "npm-", suffix: str = "") -> Path:
        if isinstance(certificate_id, bool) or not isinstance(certificate_id, int):
            raise ValueError("certificate ID must be a positive integer")
        if certificate_id < 1:
            raise ValueError("certificate ID must be a positive integer")
        candidate = f"{prefix}{certificate_id}{suffix}"
        name = os.path.basename(candidate)
        if name != candidate:
            raise ValueError("certificate path component is invalid")
        target = (self.root / name).resolve()  # lgtm [py/path-injection]
        if target.parent != self.root:
            raise ValueError("certificate path escapes the material root")
        return target

    def put(self, certificate_id: int, bundle: CustomCertificateBundle) -> None:
        target = self._directory(certificate_id)
        stage = self._directory(certificate_id, prefix=".npm-", suffix=f"-{uuid.uuid4().hex}")
        stage.mkdir(mode=0o700)
        try:
            self._write(stage / "cert.pem", bundle.certificate)
            self._write(stage / "chain.pem", bundle.intermediate_certificate)
            self._write(stage / "fullchain.pem", bundle.fullchain)
            self._write(stage / "privkey.pem", bundle.private_key)
            backup = self._directory(certificate_id, prefix=".npm-", suffix="-backup")
            if backup.exists():
                shutil.rmtree(backup)
            if target.exists():
                os.replace(target, backup)
            try:
                os.replace(stage, target)
            except BaseException:
                if backup.exists():
                    os.replace(backup, target)
                raise
            if backup.exists():
                shutil.rmtree(backup)
        finally:
            if stage.exists():
                shutil.rmtree(stage)

    @staticmethod
    def _write(path: Path, value: str) -> None:
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(value.strip() + "\n" if value.strip() else "")
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(0o600)

    def delete(self, certificate_id: int) -> bool:
        target = self._directory(certificate_id)
        if not target.exists():  # lgtm [py/path-injection]
            return False
        shutil.rmtree(target)  # lgtm [py/path-injection]
        return True

    def detach(self, certificate_id: int) -> Path | None:
        """Atomically quarantine material so a metadata delete can be compensated."""

        target = self._directory(certificate_id)
        if not target.exists():
            return None
        quarantine = self._directory(
            certificate_id, prefix=".npm-", suffix=f"-delete-{uuid.uuid4().hex}"
        )
        os.replace(target, quarantine)
        return quarantine

    def rollback_detach(self, certificate_id: int, quarantine: Path | None) -> None:
        if quarantine is not None and quarantine.exists():
            os.replace(quarantine, self._directory(certificate_id))

    @staticmethod
    def commit_detach(quarantine: Path | None) -> None:
        if quarantine is not None and quarantine.exists():
            shutil.rmtree(quarantine)

    def archive(self, certificate_id: int) -> bytes:
        target = self._directory(certificate_id)
        if not target.is_dir():  # lgtm [py/path-injection]
            raise FileNotFoundError(f"certificate material {certificate_id} was not found")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name in ("cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"):
                path = target / name  # lgtm [py/path-injection]
                if path.is_file():  # lgtm [py/path-injection]
                    archive.writestr(
                        name,
                        path.read_bytes(),  # lgtm [py/path-injection]
                    )
        return output.getvalue()


class CertbotIssuer:
    """Concrete Certbot adapter for HTTP-01 and installed DNS plugins."""

    def __init__(
        self,
        *,
        webroot: str | Path = "/data/acme-challenge",
        server: str | None = None,
        staging: bool = False,
        runner: Any = subprocess.run,
        validator: OpenSSLPEMValidator | None = None,
    ) -> None:
        self.webroot = Path(webroot)
        self.server = server
        self.staging = staging
        self.runner = runner
        self.validator = validator or OpenSSLPEMValidator()

    def issue(
        self,
        domains: tuple[str, ...],
        *,
        challenge_type: ChallengeType,
        key_type: str,
        email: str,
        provider: str | None = None,
        credentials_file: Path | None = None,
    ) -> IssuedCertificate:
        self.webroot.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="portwyrm-certbot-") as directory:
            root = Path(directory)
            name = "portwyrm-order"
            command = [
                "certbot",
                "certonly",
                "--non-interactive",
                "--agree-tos",
                "--email",
                email,
                "--cert-name",
                name,
                "--config-dir",
                str(root / "config"),
                "--work-dir",
                str(root / "work"),
                "--logs-dir",
                str(root / "logs"),
                "--key-type",
                key_type,
            ]
            if challenge_type == ChallengeType.HTTP_01:
                command.extend(["--webroot", "--webroot-path", str(self.webroot)])
            else:
                if not provider or credentials_file is None:
                    raise ValueError("DNS-01 requires a provider and credentials file")
                dns_provider = DEFAULT_PROVIDER_CATALOG.get(provider)
                status = provider_status(dns_provider)
                if not status.installed:
                    raise RuntimeError(
                        f"DNS provider {provider!r} is catalogued but unavailable; "
                        f"install {dns_provider.package_name} before requesting a certificate"
                    )
                command.extend(
                    [f"--dns-{provider}", f"--dns-{provider}-credentials", str(credentials_file)]
                )
            if self.server:
                command.extend(["--server", self.server])
            if self.staging:
                command.append("--staging")
            for domain in domains:
                command.extend(["-d", domain])
            result = self.runner(command, capture_output=True, text=True, check=False)
            if result.returncode:
                raise RuntimeError((result.stderr or result.stdout or "Certbot failed").strip())
            live = root / "config" / "live" / name
            certificate = (live / "cert.pem").read_text(encoding="utf-8")
            private_key = (live / "privkey.pem").read_text(encoding="utf-8")
            chain = (live / "chain.pem").read_text(encoding="utf-8")
            info = self.validator.validate(CustomCertificateBundle(certificate, private_key, chain))
            return IssuedCertificate(certificate, private_key, chain, info.not_after)
