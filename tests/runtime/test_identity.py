from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from portwyrm.application import MFAStore
from portwyrm.persistence import MemoryRepository, SQLiteRepository
from portwyrm.security import (
    Principal,
    TokenStore,
    consume_backup_code,
    generate_backup_codes,
    generate_totp_secret,
    totp_code,
    verify_totp,
)


def test_principal_admin_and_section_permissions() -> None:
    admin = Principal(1, "admin@example.com", is_admin=True)
    viewer = Principal(2, "viewer@example.com", permissions={"proxy_hosts": "view"})
    manager = Principal(3, "manager@example.com", permissions={"proxy_hosts": "manage"})
    assert admin.may("users", write=True)
    assert viewer.may("proxy_hosts")
    assert not viewer.may("proxy_hosts", write=True)
    assert manager.may("proxy_hosts", write=True)
    assert not manager.may("certificates")


def test_principal_supports_independent_crud_grants() -> None:
    creator = Principal(
        4,
        "creator@example.com",
        permissions={
            "proxy_hosts": {
                "create": True,
                "read": True,
                "update": False,
                "delete": False,
            }
        },
    )

    assert creator.may("proxy_hosts", action="create")
    assert creator.may("proxy_hosts", action="read")
    assert not creator.may("proxy_hosts", action="update")
    assert not creator.may("proxy_hosts", action="delete")
    assert not creator.may("certificates", action="read")


def test_session_refresh_expiry_and_invalid_token() -> None:
    store = TokenStore(session_ttl_seconds=60)
    principal = Principal(1, "admin@example.com", is_admin=True)
    token, expires = store.issue_session(principal, now=100)
    assert expires == 160
    assert store.verify(token, now=159) == principal
    replacement, replacement_expiry = store.refresh_session(token, now=120)
    assert replacement != token
    assert replacement_expiry == 180
    with pytest.raises(ValueError, match="invalid token"):
        store.verify(token, now=121)
    with pytest.raises(ValueError, match="expired"):
        store.verify(replacement, now=180)


def test_personal_access_token_is_one_time_revealed_hashed_revocable_and_expiring() -> None:
    store = TokenStore()
    principal = Principal(7, "service@example.com", scopes=frozenset({"proxy:write"}))
    record, plaintext = store.create_pat(
        name="deployment", principal=principal, expires_at=200, now=100
    )
    assert plaintext.startswith(f"pwyrm_{record.id}_")
    assert record.token_hash.startswith("$argon2id$")
    assert plaintext not in record.token_hash
    assert store.verify(plaintext, now=150) == principal
    assert record.last_used_at == 150
    assert store.revoke_pat(record.id, now=160)
    assert not store.revoke_pat(record.id, now=161)
    with pytest.raises(ValueError, match="invalid token"):
        store.verify(plaintext, now=170)

    _, expiring = store.create_pat(name="short", principal=principal, expires_at=300, now=200)
    with pytest.raises(ValueError, match="expired"):
        store.verify(expiring, now=300)


def test_sessions_and_personal_tokens_survive_repository_restart(tmp_path) -> None:
    repository = SQLiteRepository(tmp_path / "identity.sqlite")
    principal = Principal(7, "service@example.com", scopes=frozenset({"user", "proxy:write"}))
    first = TokenStore(repository=repository)
    session, _ = first.issue_session(principal, now=100)
    record, personal = first.create_pat(
        name="automation", principal=principal, expires_at=500, now=100
    )

    restarted = TokenStore(repository=repository)
    assert restarted.verify(session, now=101) == principal
    assert restarted.verify(personal, now=101) == principal
    assert restarted.get_pat(record.id).last_used_at == 101
    assert restarted.revoke_session(session)
    assert restarted.revoke_pat(record.id, now=102)

    final = TokenStore(repository=repository)
    with pytest.raises(ValueError, match="invalid token"):
        final.verify(session, now=103)
    with pytest.raises(ValueError, match="invalid token"):
        final.verify(personal, now=103)


def test_totp_matches_rfc_vector_and_rejects_invalid_codes() -> None:
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert totp_code(secret, at=59, digits=8) == "94287082"
    assert verify_totp(secret, "94287082", at=59, digits=8, window=0)
    assert not verify_totp(secret, "94287081", at=59, digits=8, window=0)
    assert not verify_totp(secret, "not-code", at=59, digits=8)
    assert len(generate_totp_secret()) >= 26


def test_backup_codes_are_one_use() -> None:
    codes, stored = generate_backup_codes(count=3)
    hashes = list(stored)
    assert len(set(codes)) == 3
    assert all(value.startswith("$argon2id$") for value in hashes)
    assert consume_backup_code(codes[0], hashes)
    assert not consume_backup_code(codes[0], hashes)
    assert not consume_backup_code("wrong", hashes)
    assert len(hashes) == 2


def test_mfa_recovery_rotation_revokes_previous_backup_codes() -> None:
    store = MFAStore(MemoryRepository(), Fernet.generate_key())
    enrollment = store.begin(7)
    assert store.confirm(7, totp_code(enrollment["secret"]))

    replacement = store.regenerate_backup_codes(7, enrollment["backup_codes"][0])

    assert replacement is not None
    assert not store.verify(7, enrollment["backup_codes"][1])
    assert store.verify(7, replacement[0])
    assert not store.verify(7, replacement[0])
