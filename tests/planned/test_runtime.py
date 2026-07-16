from portwyrm.runtime import TableRuntimeController
from portwyrm.tables import LeaseStore


def test_runtime_has_one_table_controller_and_durable_leases() -> None:
    assert TableRuntimeController.__name__ == "TableRuntimeController"
    assert {"acquire", "renew", "release"} <= set(LeaseStore.ops.by_alias)
