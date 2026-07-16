from portwyrm.tables import CertificateStore


def test_certificate_lifecycle_is_an_executable_table_contract() -> None:
    profile = {spec.alias for spec in CertificateStore.TABLE_PROFILE.ops}
    declared = {spec.alias for spec in CertificateStore.__tigrbl_ops__}
    operations = profile | declared
    assert {"create", "read", "update", "replace", "delete", "list"} <= operations
    assert {"validate", "upload", "request", "renew", "download", "remove"} <= operations
