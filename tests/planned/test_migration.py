from portwyrm.tables import SchemaMigrationStore


def test_schema_migration_has_plan_apply_and_failure_recording() -> None:
    assert {"plan", "apply", "record_failure"} <= set(SchemaMigrationStore.ops.by_alias)
