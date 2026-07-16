from portwyrm.config import PortwyrmSettings, engine_from_settings


def test_persistence_profiles_resolve_to_tigrbl_engine_specs(tmp_path) -> None:
    assert engine_from_settings(PortwyrmSettings(backend="memory"))["mode"] == "memory"
    assert (
        engine_from_settings(
            PortwyrmSettings(backend="sqlite", sqlite_path=tmp_path / "db.sqlite")
        )["kind"]
        == "sqlite"
    )
    assert engine_from_settings(PortwyrmSettings(backend="postgres"))["kind"] == "postgres"
    assert engine_from_settings(PortwyrmSettings(backend="mysql")).spec.kind == "mysql"
