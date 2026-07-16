from portwyrm.tables import (
    CredentialStore,
    MFAEnrollmentStore,
    PATStore,
    PrincipalStore,
)
from portwyrm.tables.mfa import MFARecoveryCodeStore


def _operations(table: type) -> set[str]:
    return {spec.alias for spec in table.TABLE_PROFILE.ops} | {
        spec.alias for spec in getattr(table, "__tigrbl_ops__", ())
    }


def test_identity_tables_expose_password_mfa_and_pat_lifecycles() -> None:
    assert {"register", "resolve", "update_identity"} <= _operations(PrincipalStore)
    assert {"authenticate", "change_password", "set_password"} <= _operations(
        CredentialStore
    )
    assert {"begin", "confirm", "verify", "disable"} <= _operations(MFAEnrollmentStore)
    assert _operations(PATStore) == {
        "read",
        "list",
        "issue",
        "refresh",
        "rotate",
        "revoke",
        "verify",
    }
    assert _operations(MFARecoveryCodeStore) == set()
