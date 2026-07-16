"""HTTP compatibility adapter for MFA table operations."""

from __future__ import annotations

from typing import Any


class TableMFA:
    def __init__(self, app: Any) -> None:
        self.app = app

    async def begin(self, user_id: int | str) -> dict[str, Any]:
        return await self.app.core.MFAEnrollmentStore.begin({"principal_id": int(user_id)})

    async def enabled(self, user_id: int | str) -> bool:
        result = await self.app.core.MFAEnrollmentStore.enabled({"principal_id": int(user_id)})
        return bool(result["enabled"])

    async def confirm(self, user_id: int | str, code: str) -> bool:
        result = await self.app.core.MFAEnrollmentStore.confirm(
            {"principal_id": int(user_id), "code": code}
        )
        return bool(result["confirmed"])

    async def verify(self, user_id: int | str, code: str) -> bool:
        result = await self.app.core.MFAEnrollmentStore.verify(
            {"principal_id": int(user_id), "code": code}
        )
        return bool(result["verified"])

    async def disable(self, user_id: int | str, code: str) -> bool:
        result = await self.app.core.MFAEnrollmentStore.disable(
            {"principal_id": int(user_id), "code": code}
        )
        return bool(result["disabled"])

    async def regenerate_backup_codes(self, user_id: int | str, code: str) -> list[str] | None:
        result = await self.app.core.MFAEnrollmentStore.regenerate_backup_codes(
            {"principal_id": int(user_id), "code": code}
        )
        return result["backup_codes"]


__all__ = ["TableMFA"]
