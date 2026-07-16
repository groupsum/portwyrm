"""MFA enrollment and recovery as table-owned Tigrbl operations."""

from __future__ import annotations

import inspect
import time
from typing import Any, ClassVar

from cryptography.fernet import Fernet, InvalidToken
from pydantic import Field
from sqlalchemy import delete, select
from tigrbl import op_ctx, schema_ctx
from tigrbl.factories.table import defineTableSpec
from tigrbl.types import (
    BaseModel,
    Boolean,
    Column,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from portwyrm.identity.mfa import (
    consume_backup_code,
    generate_backup_codes,
    generate_totp_secret,
    verify_totp,
)

from .base import PortwyrmTable


async def _await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class MFAEnrollmentStore(PortwyrmTable, defineTableSpec(ops=("read", "list"))):
    __tablename__ = "mfa_enrollments"
    __table_args__ = (UniqueConstraint("principal_id", name="uq_mfa_principal"),)
    principal_id = Column(Integer, ForeignKey("principals.id"), nullable=False, index=True)
    method = Column(String(32), nullable=False, default="totp")
    encrypted_secret = Column(Text, nullable=False)
    confirmed = Column(Boolean, nullable=False, default=False)
    _configured_cipher: ClassVar[Fernet | None] = None

    @classmethod
    def configure_cipher(cls, cipher: Fernet) -> None:
        cls._configured_cipher = cipher

    @schema_ctx(alias="begin", kind="out")
    class BeginResult(BaseModel):
        secret: str
        backup_codes: list[str] = Field(default_factory=list)

    @op_ctx(alias="begin", target="custom", arity="collection")
    async def begin(cls, ctx: Any) -> dict[str, Any]:
        principal_id = int((ctx.get("payload") or {})["principal_id"])
        await cls._delete_enrollment(ctx["db"], principal_id)
        secret = generate_totp_secret()
        codes, hashes = generate_backup_codes()
        row = cls(
            principal_id=principal_id,
            method="totp",
            encrypted_secret=cls._cipher(ctx).encrypt(secret.encode()).decode(),
            confirmed=False,
        )
        ctx["db"].add(row)
        await _await(ctx["db"].flush())
        for digest in hashes:
            ctx["db"].add(MFARecoveryCodeStore(enrollment_id=row.id, code_digest=digest))
        return {"secret": secret, "backup_codes": list(codes)}

    @op_ctx(alias="enabled", target="custom", arity="collection")
    async def enabled(cls, ctx: Any) -> dict[str, Any]:
        row = await cls._enrollment(ctx["db"], int((ctx.get("payload") or {})["principal_id"]))
        return {"enabled": bool(row and row.confirmed)}

    @op_ctx(alias="confirm", target="custom", arity="collection")
    async def confirm(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        row = await cls._enrollment(ctx["db"], int(payload["principal_id"]))
        confirmed = bool(
            row
            and not row.confirmed
            and verify_totp(cls._secret(ctx, row), str(payload.get("code") or ""))
        )
        if confirmed:
            row.confirmed = True
        return {"confirmed": confirmed}

    @op_ctx(alias="verify", target="custom", arity="collection")
    async def verify(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        row = await cls._enrollment(ctx["db"], int(payload["principal_id"]))
        if row is None or not row.confirmed:
            return {"verified": True}
        code = str(payload.get("code") or "")
        if verify_totp(cls._secret(ctx, row), code):
            return {"verified": True}
        result = await _await(
            ctx["db"].execute(
                select(MFARecoveryCodeStore).where(
                    MFARecoveryCodeStore.enrollment_id == row.id,
                    MFARecoveryCodeStore.used_at.is_(None),
                )
            )
        )
        for recovery in result.scalars().all():
            hashes = [recovery.code_digest]
            if consume_backup_code(code, hashes):
                recovery.used_at = int(time.time())
                return {"verified": True}
        return {"verified": False}

    @op_ctx(alias="disable", target="custom", arity="collection")
    async def disable(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        verified = await cls.verify(cls, ctx)
        disabled = bool(verified["verified"])
        if disabled:
            await cls._delete_enrollment(ctx["db"], int(payload["principal_id"]))
        return {"disabled": disabled}

    @op_ctx(alias="regenerate_backup_codes", target="custom", arity="collection")
    async def regenerate_backup_codes(cls, ctx: Any) -> dict[str, Any]:
        payload = dict(ctx.get("payload") or {})
        verified = await cls.verify(cls, ctx)
        row = await cls._enrollment(ctx["db"], int(payload["principal_id"]))
        if not verified["verified"] or row is None or not row.confirmed:
            return {"backup_codes": None}
        await _await(
            ctx["db"].execute(
                delete(MFARecoveryCodeStore).where(MFARecoveryCodeStore.enrollment_id == row.id)
            )
        )
        codes, hashes = generate_backup_codes()
        for digest in hashes:
            ctx["db"].add(MFARecoveryCodeStore(enrollment_id=row.id, code_digest=digest))
        return {"backup_codes": list(codes)}

    @staticmethod
    async def _enrollment(db: Any, principal_id: int) -> Any | None:
        result = await _await(
            db.execute(
                select(MFAEnrollmentStore).where(MFAEnrollmentStore.principal_id == principal_id)
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def _delete_enrollment(db: Any, principal_id: int) -> None:
        row = await MFAEnrollmentStore._enrollment(db, principal_id)
        if row is None:
            return
        await _await(
            db.execute(
                delete(MFARecoveryCodeStore).where(MFARecoveryCodeStore.enrollment_id == row.id)
            )
        )
        await _await(db.delete(row))

    @staticmethod
    def _cipher(ctx: Any) -> Fernet:
        cipher = getattr(getattr(ctx.get("app"), "state", None), "mfa_cipher", None)
        cipher = cipher or MFAEnrollmentStore._configured_cipher
        if not isinstance(cipher, Fernet):
            raise RuntimeError("MFA encryption is not configured")
        return cipher

    @classmethod
    def _secret(cls, ctx: Any, row: Any) -> str:
        try:
            return cls._cipher(ctx).decrypt(row.encrypted_secret.encode()).decode()
        except InvalidToken as exc:
            raise RuntimeError("MFA secret cannot be decrypted") from exc


class MFARecoveryCodeStore(PortwyrmTable, defineTableSpec(ops=())):
    __tablename__ = "mfa_recovery_codes"
    enrollment_id = Column(Integer, ForeignKey("mfa_enrollments.id"), nullable=False, index=True)
    code_digest = Column(String(255), nullable=False)
    used_at = Column(Integer, nullable=True)


MFAEnrollment = MFAEnrollmentStore
MFARecoveryCode = MFARecoveryCodeStore
MFABeginResult = MFAEnrollmentStore.BeginResult

__all__ = [
    "MFABeginResult",
    "MFAEnrollment",
    "MFAEnrollmentStore",
    "MFARecoveryCode",
    "MFARecoveryCodeStore",
]
