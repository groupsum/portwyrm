from pathlib import Path

from tigrbl import TigrblApp

from portwyrm.api.compat.transport import CompatibilityTigrblApp, PortwyrmApp, PortwyrmRouter
from portwyrm.config import PortwyrmSettings, engine_from_settings
from portwyrm.tables import PORTWYRM_TABLES


def test_app_and_router_are_derived_from_public_tigrbl_factories() -> None:
    assert issubclass(CompatibilityTigrblApp, PortwyrmApp)
    assert issubclass(PortwyrmApp, TigrblApp)
    assert PortwyrmRouter.__name__ == "RouterWithSpec"
    assert len(PORTWYRM_TABLES) == 31


def test_deployment_profiles_are_tigrbl_engine_specs(tmp_path: Path) -> None:
    memory = engine_from_settings(PortwyrmSettings(backend="memory"))
    sqlite = engine_from_settings(
        PortwyrmSettings(backend="sqlite", sqlite_path=tmp_path / "portwyrm.sqlite")
    )
    postgres = engine_from_settings(
        PortwyrmSettings(
            backend="postgres",
            database_host="db",
            database_name="control",
            database_user="portwyrm",
            database_password="secret",
        )
    )
    mysql = engine_from_settings(
        PortwyrmSettings(
            backend="mysql",
            database_host="db",
            database_name="control",
            database_user="portwyrm",
            database_password="secret",
        )
    )
    assert memory == {"kind": "sqlite", "async": False, "mode": "memory"}
    assert sqlite["kind"] == "sqlite" and sqlite["path"].endswith("portwyrm.sqlite")
    assert postgres["kind"] == "postgres" and postgres["db"] == "control"
    assert mysql.spec.kind == "mysql"


def test_database_compose_profiles_use_the_settings_contract() -> None:
    root = Path(__file__).parents[2]
    for name, host, port in (
        ("compose.mysql.yaml", "mysql", "3306"),
        ("compose.postgresql.yaml", "postgres", "5432"),
    ):
        compose = (root / "deploy" / name).read_text(encoding="utf-8")
        assert f"PORTWYRM_DATABASE_HOST: {host}" in compose
        assert f"PORTWYRM_DATABASE_PORT: {port}" in compose
        assert "PORTWYRM_DATABASE_NAME: portwyrm" in compose
        assert "PORTWYRM_DATABASE_USER: portwyrm" in compose
        assert "PORTWYRM_MYSQL_HOST" not in compose
        assert "PORTWYRM_POSTGRES_HOST" not in compose
