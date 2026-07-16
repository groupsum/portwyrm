"""Tigrbl table-native multi-factor authentication service."""

from __future__ import annotations

import inspect
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import delete, select

from portwyrm.security import (
    consume_backup_code,
    generate_backup_codes,
    generate_totp_secret,
    verify_totp,
)
from portwyrm.tables import KernelUnitOfWork
from portwyrm.tables.models import MFAEnrollment, MFARecoveryCode


async def _result(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


class KernelMFAStore:
    def __init__(self, app: Any, encryption_key: str | bytes) -> None:
        self.uow = KernelUnitOfWork(app)
        key = encryption_key.encode() if isinstance(encryption_key, str) else encryption_key
        self.cipher = Fernet(key)

    async def begin(self, user_id: int | str) -> dict[str, Any]:
        secret = generate_totp_secret()
        codes, hashes = generate_backup_codes()

        async def create(db: Any) -> None:
            existing = await self._enrollment(db, user_id)
            if existing is not None:
                await _result(
                    db.execute(
                        delete(MFARecoveryCode).where(MFARecoveryCode.enrollment_id == existing.id)
                    )
                )
                await _result(db.delete(existing))
                await _result(db.flush())
            enrollment = MFAEnrollment(
                principal_id=int(user_id),
                encrypted_secret=self.cipher.encrypt(secret.encode()).decode(),
                confirmed=False,
            )
            db.add(enrollment)
            await _result(db.flush())
            for digest in hashes:
                db.add(MFARecoveryCode(enrollment_id=enrollment.id, code_digest=digest))

        await self.uow.run(create)
        return {"secret": secret, "backup_codes": list(codes)}

    async def enabled(self, user_id: int | str) -> bool:
        async def read(db: Any) -> bool:
            enrollment = await self._enrollment(db, user_id)
            return bool(enrollment and enrollment.confirmed)

        return await self.uow.run(read)

    async def confirm(self, user_id: int | str, code: str) -> bool:
        async def update(db: Any) -> bool:
            enrollment = await self._enrollment(db, user_id)
            if enrollment is None or enrollment.confirmed:
                return False
            if not verify_totp(self._secret(enrollment), code):
                return False
            enrollment.confirmed = True
            return True

        return await self.uow.run(update)

    async def verify(self, user_id: int | str, code: str) -> bool:
        async def check(db: Any) -> bool:
            enrollment = await self._enrollment(db, user_id)
            if enrollment is None or not enrollment.confirmed:
                return True
            if verify_totp(self._secret(enrollment), code):
                return True
            result = await _result(
                db.execute(
                    select(MFARecoveryCode).where(
                        MFARecoveryCode.enrollment_id == enrollment.id,
                        MFARecoveryCode.used_at.is_(None),
                    )
                )
            )
            for recovery in result.scalars():
                if consume_backup_code(code, [recovery.code_digest]):
                    await _result(db.delete(recovery))
                    return True
            return False

        return await self.uow.run(check)

    async def disable(self, user_id: int | str, code: str) -> bool:
        if not await self.verify(user_id, code):
            return False

        async def remove(db: Any) -> bool:
            enrollment = await self._enrollment(db, user_id)
            if enrollment is None or not enrollment.confirmed:
                return False
            await _result(
                db.execute(
                    delete(MFARecoveryCode).where(MFARecoveryCode.enrollment_id == enrollment.id)
                )
            )
            await _result(db.delete(enrollment))
            return True

        return await self.uow.run(remove)

    async def regenerate_backup_codes(self, user_id: int | str, code: str) -> list[str] | None:
        if not await self.verify(user_id, code):
            return None
        codes, hashes = generate_backup_codes()

        async def replace(db: Any) -> bool:
            enrollment = await self._enrollment(db, user_id)
            if enrollment is None or not enrollment.confirmed:
                return False
            await _result(
                db.execute(
                    delete(MFARecoveryCode).where(MFARecoveryCode.enrollment_id == enrollment.id)
                )
            )
            for digest in hashes:
                db.add(MFARecoveryCode(enrollment_id=enrollment.id, code_digest=digest))
            return True

        return list(codes) if await self.uow.run(replace) else None

    @staticmethod
    async def _enrollment(db: Any, user_id: int | str) -> MFAEnrollment | None:
        result = await _result(
            db.execute(select(MFAEnrollment).where(MFAEnrollment.principal_id == int(user_id)))
        )
        return result.scalar_one_or_none()

    def _secret(self, enrollment: MFAEnrollment) -> str:
        try:
            return self.cipher.decrypt(enrollment.encrypted_secret.encode()).decode()
        except InvalidToken as exc:
            raise RuntimeError("MFA secret cannot be decrypted with the configured key") from exc
