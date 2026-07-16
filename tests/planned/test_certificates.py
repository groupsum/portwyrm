from portwyrm.tables import CertificateStore


def test_certificate_lifecycle_is_an_executable_table_contract() -> None:
    assert {"create_compat", "update_compat", "delete_compat", "compat_read", "compat_list"} <= set(
        CertificateStore.ops.by_alias
    )
