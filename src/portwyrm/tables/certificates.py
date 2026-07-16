"""Certificate inventory, domains, and ACME challenges."""

from __future__ import annotations

import inspect
from typing import Any

from sqlalchemy import delete, select
from tigrbl import op_ctx
from tigrbl.types import JSON, Column, ForeignKey, Integer, String, Text, UniqueConstraint

from .base import ManagedPortwyrmTable
from .compat import add_audit, extension_metadata, extensions, iso

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
    nice_name = Column(String(255), nullable=False)
    provider = Column(String(64), nullable=False)
    challenge_type = Column(String(32), nullable=True)
    key_type = Column(String(32), nullable=False, default="rsa")
    material_ref = Column(String(1024), nullable=True)
    expires_at = Column(Integer, nullable=True)
    status = Column(String(32), nullable=False, default="pending")

    @op_ctx(alias="create_compat", target="custom", arity="collection")
    async def create_compat(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        row = cls(**cls._values(payload))
        ctx["db"].add(row)
        await _await(ctx["db"].flush())
        await cls._replace_domains(ctx["db"], row.id, payload)
        result = await cls._project(ctx["db"], row)
        await add_audit(
            ctx["db"],
            action="created",
            object_type="certificates",
            object_id=row.id,
            details=result,
        )
        return result

    @op_ctx(alias="update_compat", target="custom", arity="collection")
    async def update_compat(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        certificate_id = int(payload.pop("id"))
        result = await _await(ctx["db"].execute(select(cls).where(cls.id == certificate_id)))
        row = result.scalar_one_or_none()
        if row is None:
            raise ValueError("certificate not found")
        for key, value in cls._values(payload).items():
            setattr(row, key, value)
        await cls._replace_domains(ctx["db"], row.id, payload)
        result = await cls._project(ctx["db"], row)
        await add_audit(
            ctx["db"],
            action="updated",
            object_type="certificates",
            object_id=row.id,
            details=result,
        )
        return result

    @op_ctx(alias="delete_compat", target="custom", arity="collection")
    async def delete_compat(cls, ctx: Any) -> dict[str, Any]:
        certificate_id = int((ctx.get("payload") or {})["id"])
        await cls._replace_domains(ctx["db"], certificate_id, {})
        await _await(
            ctx["db"].execute(
                delete(CertificateChallengeStore).where(
                    CertificateChallengeStore.certificate_id == certificate_id
                )
            )
        )
        result = await _await(ctx["db"].execute(delete(cls).where(cls.id == certificate_id)))
        if result.rowcount:
            await add_audit(
                ctx["db"], action="deleted", object_type="certificates", object_id=certificate_id
            )
        return {"deleted": bool(result.rowcount), "id": certificate_id}

    @op_ctx(alias="compat_list", target="custom", arity="collection")
    async def compat_list(cls, ctx: Any) -> list[dict[str, Any]]:
        rows = list((await _await(ctx["db"].execute(select(cls).order_by(cls.id)))).scalars())
        return [await cls._project(ctx["db"], row) for row in rows]

    @op_ctx(alias="compat_read", target="custom", arity="collection")
    async def compat_read(cls, ctx: Any) -> dict[str, Any]:
        row = (
            await _await(
                ctx["db"].execute(
                    select(cls).where(cls.id == int((ctx.get("payload") or {})["id"]))
                )
            )
        ).scalar_one_or_none()
        if row is None:
            raise ValueError("certificate not found")
        return await cls._project(ctx["db"], row)

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


class CertificateDomainStore(ManagedPortwyrmTable):
    __tablename__ = "certificate_domains"
    __table_args__ = (
        UniqueConstraint("certificate_id", "domain_name", name="uq_certificate_domain"),
    )
    certificate_id = Column(Integer, ForeignKey("certificates.id"), nullable=False, index=True)
    domain_name = Column(String(253), nullable=False, index=True)


class CertificateChallengeStore(ManagedPortwyrmTable):
    __tablename__ = "certificate_challenges"
    certificate_id = Column(Integer, ForeignKey("certificates.id"), nullable=False, index=True)
    challenge_type = Column(String(32), nullable=False)
    provider = Column(String(64), nullable=False)
    state = Column(String(32), nullable=False, default="pending")
    external_reference = Column(String(512), nullable=True)
    diagnostic = Column(Text, nullable=True)
    details = Column(JSON, nullable=False, default=dict)


Certificate = CertificateStore
CertificateDomain = CertificateDomainStore

__all__ = [
    "Certificate",
    "CertificateChallengeStore",
    "CertificateDomain",
    "CertificateDomainStore",
    "CertificateStore",
]
