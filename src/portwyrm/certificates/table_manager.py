"""Certificate material workflows backed by CertificateStore operations."""

from __future__ import annotations

import asyncio
import hashlib
import os
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from portwyrm.api.compat.resources import TableResources

from .acme import CertificateLifecycle, ChallengeType
from .manager import CertificateConflict, CertificateMaterialStore, CertificateRequest, Issuer
from .pem import CustomCertificateBundle, OpenSSLPEMValidator


class TableCertificateManager:
    def __init__(
        self,
        resources: TableResources,
        store: CertificateMaterialStore,
        *,
        validator: OpenSSLPEMValidator | None = None,
        issuer: Issuer | None = None,
    ) -> None:
        self.resources = resources
        self.store = store
        self.validator = validator or OpenSSLPEMValidator()
        self.issuer = issuer
        self._renewal_lock = asyncio.Lock()

    def _credential_scope(self, certificate_id: int, domains: tuple[str, ...]) -> Path:
        scope = "\n".join(sorted(domain.casefold() for domain in domains))
        digest = hashlib.sha256(scope.encode()).hexdigest()
        return self.store.root / ".dns-credentials" / str(certificate_id) / digest

    def _save_credentials(self, target: Path, source: Path) -> None:
        target.parent.parent.mkdir(mode=0o700, exist_ok=True)
        target.parent.mkdir(mode=0o700, exist_ok=True)
        descriptor, name = tempfile.mkstemp(dir=target.parent)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(source.read_bytes())
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(name, target)
        finally:
            Path(name).unlink(missing_ok=True)

    async def upload(
        self,
        bundle: CustomCertificateBundle,
        *,
        nice_name: str,
        certificate_id: int | None = None,
        actor: Any | None = None,
        owner_principal_id: int | None = None,
        meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        info = await asyncio.to_thread(self.validator.validate, bundle)
        payload = {
            "nice_name": nice_name.strip() or info.subject,
            "provider": "other",
            "domain_names": list(info.domain_names),
            "expires_at": int(info.not_after.timestamp()),
            "expires_on": info.not_after.isoformat(),
            "status": "pending" if certificate_id is None else "active",
            "owner_principal_id": owner_principal_id,
            "meta": {
                **dict(meta or {}),
                "subject": info.subject,
                "issuer": info.issuer,
                "serial": info.serial,
            },
        }
        created = certificate_id is None
        previous: dict[str, Any] | None = None
        actor_context = {"actor": actor} if actor is not None else {}
        if created:
            record = await self.resources.create_resource("certificates", payload, **actor_context)
            certificate_id = int(record["id"])
        else:
            previous = await self.resources.get_resource("certificates", certificate_id)
            if previous is None:
                raise FileNotFoundError(f"certificate {certificate_id} was not found")
            record = await self.resources.update_resource(
                "certificates", certificate_id, payload, **actor_context
            )
            if record is None:
                raise FileNotFoundError(f"certificate {certificate_id} was not found")
        try:
            await asyncio.to_thread(self.store.put, certificate_id, bundle)
            if created:
                activated = await self.resources.update_resource(
                    "certificates",
                    certificate_id,
                    {"status": "active"},
                    **actor_context,
                )
                if activated is None:
                    raise FileNotFoundError(f"certificate {certificate_id} was not found")
                record = activated
        except BaseException:
            if created:
                await asyncio.to_thread(self.store.delete, certificate_id)
                await self.resources.delete_resource("certificates", certificate_id)
            elif previous is not None:
                await self.resources.update_resource("certificates", certificate_id, previous)
            raise
        return record

    async def request(
        self,
        request: CertificateRequest,
        *,
        credentials_file: Path | None = None,
        actor: Any | None = None,
        owner_principal_id: int | None = None,
        meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self.issuer is None:
            raise RuntimeError("ACME issuer is not configured")
        is_namecheap = (
            request.challenge_type == ChallengeType.DNS_01 and request.provider == "namecheap"
        )
        if is_namecheap and credentials_file is None:
            raise ValueError("Namecheap DNS-01 requires a credentials file")
        lineage = uuid.uuid4().hex if is_namecheap else None
        issuer_options = {"lineage": lineage} if lineage else {}
        issued = await asyncio.to_thread(
            self.issuer.issue,
            request.domain_names,
            challenge_type=request.challenge_type,
            key_type=request.key_type,
            email=request.email,
            provider=request.provider,
            credentials_file=credentials_file,
            **issuer_options,
        )
        record = await self.resources.create_resource(
            "certificates",
            {
                "nice_name": request.nice_name,
                "provider": "letsencrypt",
                "domain_names": list(request.domain_names),
                "expires_at": int(issued.expires_at.timestamp()),
                "expires_on": issued.expires_at.isoformat(),
                "challenge_type": request.challenge_type.value,
                "key_type": request.key_type,
                "status": "pending",
                "owner_principal_id": owner_principal_id,
                "meta": {
                    **dict(meta or {}),
                    "email": request.email,
                    "dns_provider": request.provider,
                    "challenge_type": request.challenge_type.value,
                    "key_type": request.key_type,
                },
            },
            **({"actor": actor} if actor is not None else {}),
        )
        stored_credentials = None
        try:
            if lineage and credentials_file is not None:
                scope = self._credential_scope(int(record["id"]), request.domain_names)
                stored_credentials = scope.with_name(f"{scope.name}-{lineage}.ini")
                await asyncio.to_thread(
                    self._save_credentials, stored_credentials, credentials_file
                )
            await asyncio.to_thread(
                self.store.put,
                int(record["id"]),
                CustomCertificateBundle(issued.certificate, issued.private_key, issued.chain),
            )
            activated = await self.resources.update_resource(
                "certificates",
                int(record["id"]),
                {"status": "active"},
                **({"actor": actor} if actor is not None else {}),
            )
            if activated is None:
                raise FileNotFoundError(f"certificate {record['id']} was not found")
            record = activated
        except BaseException:
            if stored_credentials is not None:
                stored_credentials.unlink(missing_ok=True)
            await asyncio.to_thread(self.store.delete, int(record["id"]))
            await self.resources.delete_resource("certificates", int(record["id"]))
            raise
        return record

    async def renew(
        self,
        certificate_id: int,
        *,
        force: bool = False,
        actor: Any | None = None,
    ) -> dict[str, Any]:
        async with self._renewal_lock:
            return await self._renew(certificate_id, force=force, actor=actor)

    async def _renew(
        self, certificate_id: int, *, force: bool, actor: Any | None
    ) -> dict[str, Any]:
        record = await self.resources.get_resource("certificates", certificate_id)
        if record is None:
            raise FileNotFoundError(f"certificate {certificate_id} was not found")
        if record.get("provider") != "letsencrypt":
            raise CertificateConflict("only ACME certificates can be renewed")
        if not force:
            expires_value = record.get("expires_on")
            if expires_value is not None:
                expires = datetime.fromisoformat(str(expires_value))
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=UTC)
                if not CertificateLifecycle.renewal_due(expires, now=datetime.now(UTC)):
                    return record
        meta = dict(record.get("meta") or {})
        dns_challenge = bool(meta.get("dns_challenge"))
        return await self._replace_acme(
            certificate_id,
            CertificateRequest(
                nice_name=str(record.get("nice_name") or "Certificate"),
                domain_names=tuple(record.get("domain_names") or ()),
                email=str(
                    record.get("email")
                    or record.get("letsencrypt_email")
                    or meta.get("email")
                    or meta.get("letsencrypt_email")
                    or ""
                ),
                challenge_type=ChallengeType(
                    record.get("challenge_type")
                    or meta.get("challenge_type")
                    or ("dns-01" if dns_challenge else "http-01")
                ),
                key_type=str(record.get("key_type") or meta.get("key_type") or "rsa"),
                provider=record.get("dns_provider") or meta.get("dns_provider"),
            ),
            actor=actor,
            force=force,
        )

    async def _replace_acme(
        self,
        certificate_id: int,
        request: CertificateRequest,
        *,
        actor: Any | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        if self.issuer is None:
            raise RuntimeError("ACME issuer is not configured")
        issuer_options = {}
        if request.challenge_type == ChallengeType.DNS_01 and request.provider == "namecheap":
            scope = self._credential_scope(certificate_id, request.domain_names)
            matches = list(scope.parent.glob(f"{scope.name}-*.ini"))
            if len(matches) != 1 or not matches[0].is_file():
                raise CertificateConflict(
                    "Namecheap renewal credentials are missing for this domain set"
                )
            credentials = matches[0]
            issuer_options["credentials_file"] = credentials
            issuer_options["force_renewal"] = force
            issuer_options["lineage"] = credentials.stem.rsplit("-", 1)[1]
        issued = await asyncio.to_thread(
            self.issuer.issue,
            request.domain_names,
            challenge_type=request.challenge_type,
            key_type=request.key_type,
            email=request.email,
            provider=request.provider,
            **issuer_options,
        )
        previous = dict(await self.resources.get_resource("certificates", certificate_id) or {})
        if not force and previous.get("expires_at") == int(issued.expires_at.timestamp()):
            return previous
        quarantine = await asyncio.to_thread(self.store.detach, certificate_id)
        metadata_updated = False
        try:
            await asyncio.to_thread(
                self.store.put,
                certificate_id,
                CustomCertificateBundle(issued.certificate, issued.private_key, issued.chain),
            )
            result = await self.resources.update_resource(
                "certificates",
                certificate_id,
                {
                    "expires_at": int(issued.expires_at.timestamp()),
                    "expires_on": issued.expires_at.isoformat(),
                    "status": "active",
                },
                **({"actor": actor} if actor is not None else {}),
            )
            if result is None:
                raise FileNotFoundError(f"certificate {certificate_id} was not found")
            metadata_updated = True
            await asyncio.to_thread(self.store.commit_detach, quarantine)
        except BaseException:
            await asyncio.to_thread(self.store.delete, certificate_id)
            await asyncio.to_thread(self.store.rollback_detach, certificate_id, quarantine)
            if metadata_updated:
                await self.resources.update_resource("certificates", certificate_id, previous)
            raise
        return result

    async def download(self, certificate_id: int) -> bytes:
        if await self.resources.get_resource("certificates", certificate_id) is None:
            raise FileNotFoundError(f"certificate {certificate_id} was not found")
        return await asyncio.to_thread(self.store.archive, certificate_id)

    async def delete(self, certificate_id: int) -> None:
        async with self._renewal_lock:
            await self._delete(certificate_id)

    async def _delete(self, certificate_id: int) -> None:
        for collection in ("proxy_hosts", "redirection_hosts", "dead_hosts", "streams"):
            if any(
                int(row.get("certificate_id") or 0) == certificate_id
                for row in await self.resources.list_resources(collection)
            ):
                raise CertificateConflict("certificate is still assigned to an active resource")
        quarantine = await asyncio.to_thread(self.store.detach, certificate_id)
        try:
            if not await self.resources.delete_resource("certificates", certificate_id):
                raise FileNotFoundError(f"certificate {certificate_id} was not found")
        except BaseException:
            await asyncio.to_thread(self.store.rollback_detach, certificate_id, quarantine)
            raise
        await asyncio.to_thread(self.store.commit_detach, quarantine)
        credential_dir = self.store.root / ".dns-credentials" / str(certificate_id)
        if credential_dir.is_dir():
            for path in credential_dir.glob("*.ini"):
                path.unlink()
            credential_dir.rmdir()


__all__ = ["TableCertificateManager"]
