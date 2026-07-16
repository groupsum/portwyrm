from portwyrm.tables import RoutingHostStore


def test_routing_aggregate_exposes_normalized_compatibility_operations() -> None:
    assert {
        "create_compat",
        "update_compat",
        "delete_compat",
        "compat_read",
        "compat_list",
        "preview",
    } <= set(RoutingHostStore.ops.by_alias)
