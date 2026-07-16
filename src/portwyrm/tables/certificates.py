"""Certificate inventory, domains, and ACME challenges."""

from __future__ import annotations

import inspect
import os
import tempfile
from pathlib import Path
from typing import Any

from tigrbl import hook_ctx, op_ctx
from tigrbl.types import JSON, ForeignKey, Integer, String, Text, UniqueConstraint

from portwyrm.kernel_support import delete, select

from .base import READ_ONLY_PROFILE, ManagedPortwyrmTable, PortwyrmTable, acol
from .compat import extension_metadata, extensions, iso

_CERTIFICATE_KNOWN = {
    "id",
    "nice_name",
    "provider",
    "challenge_type",
    "key_type",
    "material_ref",
    "expires_at",
    "status",
    "domain_names",
    "created_on",
    "modified_on",
    "created_at",
    "updated_at",
}


class CertificateStore(ManagedPortwyrmTable):
    __tablename__ = "certificates"
    _workflow: Any = None
    nice_name = acol(String(255), nullable=False)
    provider = acol(String(64), nullable=False)
    challenge_type = acol(String(32), nullable=True)
    key_type = acol(String(32), nullable=False, default="rsa")
    material_ref = acol(String(1024), nullable=True)
    expires_at = acol(Integer, nullable=True)
    status = acol(String(32), nullable=False, default="pending")

    @classmethod
    def configure_workflow(cls, workflow: Any) -> None:
        cls._workflow = workflow

    @classmethod
    def _require_workflow(cls) -> Any:
        if cls._workflow is None:
            raise RuntimeError("certificate workflow is not configured")
        return cls._workflow

    @op_ctx(alias="validate", target="custom", arity="collection", persist="skip")
    async def validate(cls, ctx: Any) -> dict[str, Any]:
        from portwyrm.certificates import CustomCertificateBundle

        payload = dict(ctx.get("payload") or {})
        bundle = CustomCertificateBundle(
            str(payload["certificate"]),
            str(payload["private_key"]),
            str(payload.get("intermediate_certificate") or ""),
        )
        info = cls._require_workflow().validator.validate(bundle)
        return {
            "subject": info.subject,
            "issuer": info.issuer,
            "serial": info.serial,
            "domain_names": list(info.domain_names),
            "not_before": info.not_before.isoformat(),
            "not_after": info.not_after.isoformat(),
        }

    @op_ctx(alias="upload", target="custom", arity="collection")
    async def upload(cls, ctx: Any) -> dict[str, Any]:
        from portwyrm.certificates import CustomCertificateBundle

        payload = dict(ctx.get("payload") or {})
        return await cls._require_workflow().upload(
            CustomCertificateBundle(
                str(payload["certificate"]),
                str(payload["private_key"]),
                str(payload.get("intermediate_certificate") or ""),
            ),
            nice_name=str(payload.get("nice_name") or ""),
            certificate_id=(int(payload["id"]) if payload.get("id") is not None else None),
        )

    @op_ctx(alias="request", target="custom", arity="collection")
    async def request(cls, ctx: Any) -> dict[str, Any]:
        from portwyrm.certificates import (
            DEFAULT_PROVIDER_CATALOG,
            CertificateRequest,
            ChallengeType,
        )

        payload = dict(ctx.get("payload") or {})
        request = CertificateRequest(
            nice_name=str(payload.get("nice_name") or "Certificate"),
            domain_names=tuple(str(item) for item in payload.get("domain_names") or ()),
            email=str(payload.get("email") or ""),
            challenge_type=ChallengeType(str(payload.get("challenge_type") or "http-01")),
            key_type=str(payload.get("key_type") or "rsa"),
            provider=(str(payload["dns_provider"]) if payload.get("dns_provider") else None),
        )
        credentials = payload.get("dns_credentials")
        if request.challenge_type != ChallengeType.DNS_01:
            return await cls._require_workflow().request(request)
        if not request.provider or not isinstance(credentials, dict):
            raise ValueError("DNS-01 requires dns_provider and dns_credentials")
        normalized = {str(key): str(value) for key, value in credentials.items()}
        DEFAULT_PROVIDER_CATALOG.validate_credentials(request.provider, normalized)
        descriptor, name = tempfile.mkstemp(prefix="portwyrm-dns-", text=True)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                for key, value in normalized.items():
                    handle.write(f"{key} = {value}\n")
            os.chmod(name, 0o600)
            return await cls._require_workflow().request(
                request, credentials_file=Path(name)
            )
        finally:
            Path(name).unlink(missing_ok=True)

    @op_ctx(alias="renew", target="custom", arity="member")
    async def renew(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        return await cls._require_workflow().renew(
            int(payload["id"]), force=bool(payload.get("force"))
        )

    @op_ctx(alias="download", target="custom", arity="member", persist="skip")
    async def download(cls, ctx: Any) -> bytes:
        return await cls._require_workflow().download(int((ctx.get("payload") or {})["id"]))

    @op_ctx(alias="remove", target="custom", arity="member")
    async def remove(cls, ctx: Any) -> dict[str, Any]:
        certificate_id = int((ctx.get("payload") or {})["id"])
        await cls._require_workflow().delete(certificate_id)
        return {"deleted": True, "id": certificate_id}

    @hook_ctx(ops=("create", "update", "replace"), phase="PRE_HANDLER")
    async def prepare_aggregate(cls, ctx: dict[str, Any]) -> None:
        payload = dict(ctx.get("payload") or {})
        op = ctx.get("op") or ctx.get("alias") or ""
        alias = str(getattr(op, "alias", op)).casefold()
        if alias == "update":
            row = await _await(ctx["db"].get(cls, int(payload["id"])))
            if row is not None:
                payload = {**(await cls._project(ctx["db"], row)), **payload}
        ctx.setdefault("temp", {})["certificate_aggregate"] = payload
        root = cls._values(payload)
        if payload.get("id") is not None:
            root["id"] = int(payload["id"])
        ctx["payload"] = root

    @hook_ctx(ops=("create", "update", "replace"), phase="POST_HANDLER")
    async def persist_aggregate(cls, ctx: dict[str, Any]) -> None:
        row = ctx["result"]
        payload = ctx.get("temp", {}).get("certificate_aggregate", {})
        await cls._replace_domains(ctx["db"], row.id, payload)
        ctx["result"] = await cls._project(ctx["db"], row)

    @hook_ctx(ops=("read", "list"), phase="POST_HANDLER")
    async def project_aggregate(cls, ctx: dict[str, Any]) -> None:
        result = ctx["result"]
        if isinstance(result, list):
            ctx["result"] = [await cls._project(ctx["db"], row) for row in result]
        else:
            ctx["result"] = await cls._project(ctx["db"], result)

    @hook_ctx(ops="delete", phase="PRE_HANDLER")
    async def delete_aggregate_children(cls, ctx: dict[str, Any]) -> None:
        certificate_id = int(ctx["payload"]["id"])
        await cls._replace_domains(ctx["db"], certificate_id, {})
        await _await(
            ctx["db"].execute(
                delete(CertificateChallengeStore).where(
                    CertificateChallengeStore.certificate_id == certificate_id
                )
            )
        )

    @staticmethod
    def _values(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "nice_name": str(payload.get("nice_name") or "Certificate"),
            "provider": str(payload.get("provider") or "custom"),
            "challenge_type": payload.get("challenge_type")
            or (payload.get("meta") or {}).get("challenge_type"),
            "key_type": str(payload.get("key_type") or "rsa"),
            "material_ref": payload.get("material_ref"),
            "expires_at": payload.get("expires_at"),
            "status": str(payload.get("status") or "pending"),
            "metadata_json": extension_metadata(payload, _CERTIFICATE_KNOWN),
        }

    @classmethod
    async def _project(cls, db: Any, row: Any) -> dict[str, Any]:
        domains = list(
            (
                await _await(
                    db.execute(
                        select(CertificateDomainStore.domain_name)
                        .where(CertificateDomainStore.certificate_id == row.id)
                        .order_by(CertificateDomainStore.id)
                    )
                )
            ).scalars()
        )
        result = extensions(row)
        result.update(
            {
                "id": row.id,
                "nice_name": row.nice_name,
                "provider": row.provider,
                "challenge_type": row.challenge_type,
                "key_type": row.key_type,
                "material_ref": row.material_ref,
                "expires_at": row.expires_at,
                "status": row.status,
                "domain_names": domains,
                "created_on": iso(row.created_at),
                "modified_on": iso(row.updated_at),
            }
        )
        return result

    @staticmethod
    async def _replace_domains(db: Any, certificate_id: int, payload: dict[str, Any]) -> None:
        await _await(
            db.execute(
                delete(CertificateDomainStore).where(
                    CertificateDomainStore.certificate_id == certificate_id
                )
            )
        )
        for domain in payload.get("domain_names") or []:
            db.add(
                CertificateDomainStore(
                    certificate_id=certificate_id,
                    domain_name=str(domain).casefold(),
                )
            )


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class CertificateDomainStore(PortwyrmTable):
    __tablename__ = "certificate_domains"
    TABLE_PROFILE = READ_ONLY_PROFILE
    __table_args__ = (
        UniqueConstraint("certificate_id", "domain_name", name="uq_certificate_domain"),
    )
    certificate_id = acol(Integer, ForeignKey("certificates.id"), nullable=False, index=True)
    domain_name = acol(String(253), nullable=False, index=True)


class CertificateChallengeStore(PortwyrmTable):
    __tablename__ = "certificate_challenges"
    TABLE_PROFILE = READ_ONLY_PROFILE
    certificate_id = acol(Integer, ForeignKey("certificates.id"), nullable=False, index=True)
    challenge_type = acol(String(32), nullable=False)
    provider = acol(String(64), nullable=False)
    state = acol(String(32), nullable=False, default="pending")
    external_reference = acol(String(512), nullable=True)
    diagnostic = acol(Text, nullable=True)
    details = acol(JSON, nullable=False, default=dict)


Certificate = CertificateStore
CertificateDomain = CertificateDomainStore

__all__ = [
    "Certificate",
    "CertificateChallengeStore",
    "CertificateDomain",
    "CertificateDomainStore",
    "CertificateStore",
]
