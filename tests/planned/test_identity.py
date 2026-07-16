from portwyrm.tables import CredentialStore, MFAEnrollmentStore, PATStore, PrincipalStore


def test_identity_tables_expose_password_mfa_and_pat_lifecycles() -> None:
    assert {"register", "resolve", "update_identity"} <= set(PrincipalStore.ops.by_alias)
    assert {"authenticate", "change_password", "set_password"} <= set(
        CredentialStore.ops.by_alias
    )
    assert {"begin", "confirm", "verify", "disable"} <= set(MFAEnrollmentStore.ops.by_alias)
    assert {"issue", "refresh", "rotate", "revoke", "verify"} <= set(PATStore.ops.by_alias)
