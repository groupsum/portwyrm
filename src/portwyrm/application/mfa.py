"""Durable TOTP enrollment and one-use recovery verification."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from portwyrm.persistence import Repository
from portwyrm.security import (
    consume_backup_code,
    generate_backup_codes,
    generate_totp_secret,
    verify_totp,
)


class MFAStore:
    def __init__(
        self,
        repository: Repository,
        encryption_key: str | bytes,
        *,
        on_change: Callable[[], Any] | None = None,
    ) -> None:
        self.repository = repository
        key = encryption_key.encode() if isinstance(encryption_key, str) else encryption_key
        self.cipher = Fernet(key)
        self.on_change = on_change

    def begin(self, user_id: int | str) -> dict[str, Any]:
        secret = generate_totp_secret()
        codes, hashes = generate_backup_codes()
        record = {
            "id": str(user_id),
            "secret_ciphertext": self.cipher.encrypt(secret.encode()).decode(),
            "backup_hashes": list(hashes),
            "active": False,
        }
        with self.repository.transaction() as tx:
            tx.upsert("_mfa", record)
        self._changed()
        return {"secret": secret, "backup_codes": list(codes)}

    def enabled(self, user_id: int | str) -> bool:
        record = self._get(user_id)
        return bool(record and record.get("active"))

    def confirm(self, user_id: int | str, code: str) -> bool:
        record = self._get(user_id)
        if record is None or record.get("active") or not verify_totp(self._secret(record), code):
            return False
        record["active"] = True
        self._put(record)
        return True

    def verify(self, user_id: int | str, code: str) -> bool:
        record = self._get(user_id)
        if record is None or not record.get("active"):
            return True
        if verify_totp(self._secret(record), code):
            return True
        hashes = list(record.get("backup_hashes", []))
        if not consume_backup_code(code, hashes):
            return False
        record["backup_hashes"] = hashes
        self._put(record)
        return True

    def disable(self, user_id: int | str, code: str) -> bool:
        if not self.enabled(user_id) or not self.verify(user_id, code):
            return False
        with self.repository.transaction() as tx:
            tx.delete("_mfa", str(user_id))
        self._changed()
        return True

    def regenerate_backup_codes(self, user_id: int | str, code: str) -> list[str] | None:
        if not self.enabled(user_id) or not self.verify(user_id, code):
            return None
        record = self._get(user_id)
        assert record is not None
        codes, hashes = generate_backup_codes()
        record["backup_hashes"] = list(hashes)
        self._put(record)
        return list(codes)

    def _get(self, user_id: int | str) -> dict[str, Any] | None:
        with self.repository.transaction() as tx:
            return tx.get("_mfa", str(user_id))

    def _put(self, record: dict[str, Any]) -> None:
        with self.repository.transaction() as tx:
            tx.upsert("_mfa", record)
        self._changed()

    def _changed(self) -> None:
        if self.on_change is not None:
            self.on_change()

    def _secret(self, record: dict[str, Any]) -> str:
        try:
            return self.cipher.decrypt(str(record["secret_ciphertext"]).encode()).decode()
        except (InvalidToken, KeyError) as exc:
            raise RuntimeError("MFA secret cannot be decrypted with the configured key") from exc
