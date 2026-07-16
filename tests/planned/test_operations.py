from portwyrm.tables import AuditEventStore, GenerationStore, SettingStore


def _operations(table: type) -> set[str]:
    profile = {spec.alias for spec in table.TABLE_PROFILE.ops}
    declared = {spec.alias for spec in getattr(table, "__tigrbl_ops__", ())}
    return profile | declared


def test_operational_state_is_owned_by_tables() -> None:
    assert _operations(AuditEventStore) == {"read", "list", "record"}
    generation_ops = _operations(GenerationStore)
    assert {"record", "reconcile", "stage", "activate"} <= generation_ops
    assert {"update", "replace", "delete"}.isdisjoint(generation_ops)
    assert _operations(SettingStore) == {
        "create",
        "read",
        "update",
        "replace",
        "delete",
        "list",
    }
