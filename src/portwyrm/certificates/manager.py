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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from portwyrm.service import Conflict, ControlPlane, NotFound

from .acme import ChallengeType, IssuedCertificate
from .pem import CustomCertificateBundle, OpenSSLPEMValidator


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
        target = (self.root / name).resolve()
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
        if not target.exists():
            return False
        shutil.rmtree(target)
        return True

    def archive(self, certificate_id: int) -> bytes:
        target = self._directory(certificate_id)
        if not target.is_dir():
            raise FileNotFoundError(f"certificate material {certificate_id} was not found")
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name in ("cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"):
                path = target / name
                if path.is_file():
                    archive.writestr(name, path.read_bytes())
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


class CertificateManager:
    """Coordinate metadata and protected certificate material."""

    def __init__(
        self,
        service: ControlPlane,
        store: CertificateMaterialStore,
        *,
        validator: OpenSSLPEMValidator | None = None,
        issuer: Issuer | None = None,
    ) -> None:
        self.service = service
        self.store = store
        self.validator = validator or OpenSSLPEMValidator()
        self.issuer = issuer

    def upload(
        self,
        bundle: CustomCertificateBundle,
        *,
        nice_name: str,
        certificate_id: int | None = None,
    ) -> dict[str, Any]:
        info = self.validator.validate(bundle)
        payload = {
            "nice_name": nice_name.strip() or info.subject,
            "provider": "other",
            "domain_names": list(info.domain_names),
            "expires_on": info.not_after.isoformat(),
            "meta": {"subject": info.subject, "issuer": info.issuer, "serial": info.serial},
        }
        if certificate_id is None:
            record = self.service.create("certificates", payload)
            certificate_id = int(record["id"])
            try:
                self.store.put(certificate_id, bundle)
            except BaseException:
                self.service.delete("certificates", certificate_id)
                raise
        else:
            self.service.get("certificates", certificate_id)
            self.store.put(certificate_id, bundle)
            record = self.service.update("certificates", certificate_id, payload)
        return record

    def request(
        self, request: CertificateRequest, *, credentials_file: Path | None = None
    ) -> dict[str, Any]:
        if self.issuer is None:
            raise RuntimeError("ACME issuer is not configured")
        issued = self.issuer.issue(
            request.domain_names,
            challenge_type=request.challenge_type,
            key_type=request.key_type,
            email=request.email,
            provider=request.provider,
            credentials_file=credentials_file,
        )
        bundle = CustomCertificateBundle(issued.certificate, issued.private_key, issued.chain)
        record = self.service.create(
            "certificates",
            {
                "nice_name": request.nice_name,
                "provider": "letsencrypt",
                "domain_names": list(request.domain_names),
                "expires_on": issued.expires_at.isoformat(),
                "meta": {
                    "challenge_type": request.challenge_type.value,
                    "key_type": request.key_type,
                    "email": request.email,
                    "dns_provider": request.provider,
                },
            },
        )
        try:
            self.store.put(int(record["id"]), bundle)
        except BaseException:
            self.service.delete("certificates", int(record["id"]))
            raise
        return record

    def renew(self, certificate_id: int, *, force: bool = False) -> dict[str, Any]:
        record = self.service.get("certificates", certificate_id)
        if record.get("provider") != "letsencrypt":
            raise Conflict("only ACME certificates can be renewed")
        expires = datetime.fromisoformat(str(record["expires_on"]))
        if not force and expires > datetime.now(UTC).replace(microsecond=0):
            from .acme import CertificateLifecycle

            if not CertificateLifecycle.renewal_due(expires):
                return record
        meta = dict(record.get("meta", {}))
        request = CertificateRequest(
            nice_name=str(record.get("nice_name", "Certificate")),
            domain_names=tuple(record.get("domain_names", ())),
            email=str(meta.get("email", "")),
            challenge_type=ChallengeType(meta.get("challenge_type", "http-01")),
            key_type=str(meta.get("key_type", "rsa")),
            provider=meta.get("dns_provider"),
        )
        if self.issuer is None:
            raise RuntimeError("ACME issuer is not configured")
        issued = self.issuer.issue(
            request.domain_names,
            challenge_type=request.challenge_type,
            key_type=request.key_type,
            email=request.email,
            provider=request.provider,
        )
        self.store.put(
            certificate_id,
            CustomCertificateBundle(issued.certificate, issued.private_key, issued.chain),
        )
        return self.service.update(
            "certificates", certificate_id, {"expires_on": issued.expires_at.isoformat()}
        )

    def renew_due(self) -> dict[str, list[int] | dict[int, str]]:
        """Renew every due ACME certificate while isolating per-certificate failures."""
        renewed: list[int] = []
        skipped: list[int] = []
        failed: dict[int, str] = {}
        for record in self.service.list("certificates"):
            if record.get("provider") != "letsencrypt":
                continue
            certificate_id = int(record["id"])
            before = str(record.get("expires_on", ""))
            try:
                after = self.renew(certificate_id)
                (renewed if str(after.get("expires_on", "")) != before else skipped).append(
                    certificate_id
                )
            except Exception as exc:
                failed[certificate_id] = type(exc).__name__
        return {"renewed": renewed, "skipped": skipped, "failed": failed}

    def delete(self, certificate_id: int) -> None:
        for collection in ("proxy-hosts", "redirection-hosts", "dead-hosts", "streams"):
            if any(
                int(row.get("certificate_id") or 0) == certificate_id
                for row in self.service.list(collection)
            ):
                raise Conflict("certificate is still assigned to an active resource")
        try:
            self.service.delete("certificates", certificate_id)
        except NotFound:
            raise
        self.store.delete(certificate_id)

    def download(self, certificate_id: int) -> bytes:
        self.service.get("certificates", certificate_id)
        return self.store.archive(certificate_id)
