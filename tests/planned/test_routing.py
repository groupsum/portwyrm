from portwyrm.tables import RoutingHostStore


def test_routing_aggregate_exposes_normalized_compatibility_operations() -> None:
    profile = {spec.alias for spec in RoutingHostStore.TABLE_PROFILE.ops}
    declared = {spec.alias for spec in RoutingHostStore.__tigrbl_ops__}
    operations = profile | declared
    assert {"create", "read", "update", "replace", "delete", "list"} <= operations
    assert {"enable", "disable", "preview", "validate"} <= operations
    assert not operations & {
        "create_compat",
        "update_compat",
        "delete_compat",
        "compat_read",
        "compat_list",
    }
