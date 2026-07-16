from portwyrm.tables import AuditEventStore, GenerationStore, SettingStore


def test_operational_state_is_owned_by_tables() -> None:
    assert "record" in AuditEventStore.ops.by_alias
    assert "reconcile" in GenerationStore.ops.by_alias
    assert {"create", "read", "update", "delete", "list"} <= set(SettingStore.ops.by_alias)
