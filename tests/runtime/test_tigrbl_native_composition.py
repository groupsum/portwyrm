from pathlib import Path

from portwyrm.api.compat.transport import CompatibilityTigrblApp, PortwyrmAppSpec
from portwyrm.persistence import MemoryRepository, MySQLRepository, SQLiteRepository
from portwyrm.tables.engine import engine_for_repository
from portwyrm.tables.models import PortwyrmTable, PortwyrmTableSpec


def test_app_and_tables_publish_declarative_specs() -> None:
    assert issubclass(CompatibilityTigrblApp, PortwyrmAppSpec)
    assert "bulk_create" in PortwyrmTableSpec.OPS
    assert PortwyrmTable.OPS == PortwyrmTableSpec.OPS


def test_repository_profiles_translate_only_to_engine_specs(tmp_path: Path) -> None:
    assert engine_for_repository(MemoryRepository())["kind"] == "sqlite"
    assert engine_for_repository(SQLiteRepository(tmp_path / "db.sqlite"))["path"].endswith(
        "db.sqlite"
    )
    repository = object.__new__(MySQLRepository)
    repository.backend_name = "mysql"
    repository.config = {
        "host": "db",
        "user": "portwyrm",
        "password": "secret",
        "database": "control",
    }
    mysql = engine_for_repository(repository)
    assert mysql["kind"] == "mysql"
    assert mysql["db"] == "control"
    assert mysql["pwd"] == "secret"
