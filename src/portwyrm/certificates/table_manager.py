"""Certificate material workflows backed by CertificateStore operations."""

from __future__ import annotations

import asyncio
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

    async def upload(
        self,
        bundle: CustomCertificateBundle,
        *,
        nice_name: str,
        certificate_id: int | None = None,
    ) -> dict[str, Any]:
        info = await asyncio.to_thread(self.validator.validate, bundle)
        payload = {
            "nice_name": nice_name.strip() or info.subject,
            "provider": "other",
            "domain_names": list(info.domain_names),
            "expires_at": int(info.not_after.timestamp()),
            "expires_on": info.not_after.isoformat(),
            "status": "active",
            "meta": {"subject": info.subject, "issuer": info.issuer, "serial": info.serial},
        }
        created = certificate_id is None
        previous: dict[str, Any] | None = None
        if created:
            record = await self.resources.create_resource("certificates", payload)
            certificate_id = int(record["id"])
        else:
            previous = await self.resources.get_resource("certificates", certificate_id)
            if previous is None:
                raise FileNotFoundError(f"certificate {certificate_id} was not found")
            record = await self.resources.update_resource("certificates", certificate_id, payload)
            if record is None:
                raise FileNotFoundError(f"certificate {certificate_id} was not found")
        try:
            await asyncio.to_thread(self.store.put, certificate_id, bundle)
        except BaseException:
            if created:
                await self.resources.delete_resource("certificates", certificate_id)
            elif previous is not None:
                await self.resources.update_resource("certificates", certificate_id, previous)
            raise
        return record

    async def request(
        self, request: CertificateRequest, *, credentials_file: Path | None = None
    ) -> dict[str, Any]:
        if self.issuer is None:
            raise RuntimeError("ACME issuer is not configured")
        issued = await asyncio.to_thread(
            self.issuer.issue,
            request.domain_names,
            challenge_type=request.challenge_type,
            key_type=request.key_type,
            email=request.email,
            provider=request.provider,
            credentials_file=credentials_file,
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
                "status": "active",
                "meta": {
                    "email": request.email,
                    "dns_provider": request.provider,
                    "challenge_type": request.challenge_type.value,
                    "key_type": request.key_type,
                },
            },
        )
        try:
            await asyncio.to_thread(
                self.store.put,
                int(record["id"]),
                CustomCertificateBundle(issued.certificate, issued.private_key, issued.chain),
            )
        except BaseException:
            await self.resources.delete_resource("certificates", int(record["id"]))
            raise
        return record

    async def renew(self, certificate_id: int, *, force: bool = False) -> dict[str, Any]:
        record = await self.resources.get_resource("certificates", certificate_id)
        if record is None:
            raise FileNotFoundError(f"certificate {certificate_id} was not found")
        if record.get("provider") != "letsencrypt":
            raise CertificateConflict("only ACME certificates can be renewed")
        expires = datetime.fromisoformat(str(record["expires_on"]))
        if not force and not CertificateLifecycle.renewal_due(expires, now=datetime.now(UTC)):
            return record
        meta = dict(record.get("meta") or {})
        return await self._replace_acme(
            certificate_id,
            CertificateRequest(
                nice_name=str(record.get("nice_name") or "Certificate"),
                domain_names=tuple(record.get("domain_names") or ()),
                email=str(meta.get("email") or ""),
                challenge_type=ChallengeType(meta.get("challenge_type", "http-01")),
                key_type=str(meta.get("key_type") or "rsa"),
                provider=meta.get("dns_provider"),
            ),
        )

    async def _replace_acme(
        self, certificate_id: int, request: CertificateRequest
    ) -> dict[str, Any]:
        if self.issuer is None:
            raise RuntimeError("ACME issuer is not configured")
        issued = await asyncio.to_thread(
            self.issuer.issue,
            request.domain_names,
            challenge_type=request.challenge_type,
            key_type=request.key_type,
            email=request.email,
            provider=request.provider,
        )
        previous = dict(await self.resources.get_resource("certificates", certificate_id) or {})
        result = await self.resources.update_resource(
            "certificates",
            certificate_id,
            {
                "expires_at": int(issued.expires_at.timestamp()),
                "expires_on": issued.expires_at.isoformat(),
                "status": "active",
            },
        )
        if result is None:
            raise FileNotFoundError(f"certificate {certificate_id} was not found")
        try:
            await asyncio.to_thread(
                self.store.put,
                certificate_id,
                CustomCertificateBundle(issued.certificate, issued.private_key, issued.chain),
            )
        except BaseException:
            await self.resources.update_resource("certificates", certificate_id, previous)
            raise
        return result

    async def download(self, certificate_id: int) -> bytes:
        if await self.resources.get_resource("certificates", certificate_id) is None:
            raise FileNotFoundError(f"certificate {certificate_id} was not found")
        return await asyncio.to_thread(self.store.archive, certificate_id)

    async def delete(self, certificate_id: int) -> None:
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


__all__ = ["TableCertificateManager"]
