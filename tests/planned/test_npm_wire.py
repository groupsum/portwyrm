from portwyrm.api.compat import COLLECTIONS


def test_npm_wire_surface_covers_all_managed_collections() -> None:
    assert set(COLLECTIONS) == {
        "proxy-hosts",
        "certificates",
        "access-lists",
        "redirection-hosts",
        "dead-hosts",
        "streams",
        "users",
        "settings",
    }
