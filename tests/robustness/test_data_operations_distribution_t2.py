from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from portwyrm.migration import import_npm, preflight_npm
from portwyrm.operations import (
    AuditLog,
    HealthService,
    LogRotator,
    Settings,
    Upgrade,
    UpgradeManager,
)
from portwyrm.operations.runtime import repository_config_from_environment
from portwyrm.persistence import (
    ConflictError,
    FileBlobStore,
    FilesystemRepository,
    HybridRepository,
    MemoryRepository,
    MySQLRepository,
    PersistenceError,
    PostgreSQLRepository,
    SQLiteRepository,
    export_bundle,
    import_bundle,
    preview_import,
    validate_bundle,
)
from portwyrm.persistence.base import checksum


@pytest.fixture(params=["memory", "sqlite", "filesystem"])
def durable_repository(request: pytest.FixtureRequest, tmp_path: Path):
    if request.param == "memory":
        return MemoryRepository()
    if request.param == "sqlite":
        return SQLiteRepository(tmp_path / "state.sqlite")
    return FilesystemRepository(tmp_path / "state")


def test_transactions_rollback_all_mutations(durable_repository: Any) -> None:
    with durable_repository.transaction() as tx:
        tx.upsert("settings", {"id": "existing", "value": "before"})

    with pytest.raises(RuntimeError, match="abort"), durable_repository.transaction() as tx:
        tx.upsert("settings", {"id": "existing", "value": "after"})
        tx.upsert("settings", {"id": "new", "value": True})
        raise RuntimeError("abort")

    with durable_repository.transaction() as tx:
        assert tx.get("settings", "existing") == {"id": "existing", "value": "before"}
        assert tx.get("settings", "new") is None


@pytest.mark.parametrize("backend", ["memory", "sqlite", "filesystem"])
def test_concurrent_writers_do_not_lose_distinct_records(backend: str, tmp_path: Path) -> None:
    if backend == "memory":
        repository = MemoryRepository()
    elif backend == "sqlite":
        repository = SQLiteRepository(tmp_path / "concurrent.sqlite")
    else:
        repository = FilesystemRepository(tmp_path / "concurrent-files")
    barrier = threading.Barrier(8)

    def write(index: int) -> None:
        barrier.wait()
        with repository.transaction() as tx:
            tx.upsert("proxy_hosts", {"id": index, "domain_names": [f"{index}.example.test"]})

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(write, range(8)))

    with repository.transaction() as tx:
        assert [record["id"] for record in tx.list("proxy_hosts")] == list(range(8))


def test_filesystem_snapshot_rejects_corruption_and_unknown_schema(tmp_path: Path) -> None:
    repository = FilesystemRepository(tmp_path / "filesystem")
    with repository.transaction() as tx:
        tx.upsert("settings", {"id": "theme", "value": "dark"})
    envelope = json.loads(repository.snapshot_path.read_text(encoding="utf-8"))

    envelope["records"]["settings"]["theme"]["value"] = "tampered"
    repository.snapshot_path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(PersistenceError, match="checksum mismatch"), repository.transaction():
        pass

    content = {"generation": envelope["generation"], "records": envelope["records"]}
    envelope.update(schema_version="portwyrm.filesystem.v999", checksum=checksum(content))
    repository.snapshot_path.write_text(json.dumps(envelope), encoding="utf-8")
    with pytest.raises(PersistenceError, match=r"unsupported.*version"), repository.transaction():
        pass


def test_bundle_tampering_conflicts_and_preview_are_fail_closed(tmp_path: Path) -> None:
    source = MemoryRepository()
    with source.transaction() as tx:
        tx.upsert("settings", {"id": "mode", "value": "source"})
    bundle = export_bundle(source)
    tampered = json.loads(json.dumps(bundle))
    tampered["records"][0]["resource"]["value"] = "attacker"
    with pytest.raises(ValueError, match="checksum mismatch"):
        validate_bundle(tampered)

    target = SQLiteRepository(tmp_path / "target.sqlite")
    with target.transaction() as tx:
        tx.upsert("settings", {"id": "mode", "value": "target"})
    with pytest.raises(ConflictError):
        preview_import(target, bundle)
    with pytest.raises(ConflictError):
        import_bundle(target, bundle)
    with target.transaction() as tx:
        assert tx.get("settings", "mode")["value"] == "target"

    assert preview_import(target, bundle, replace=True)["replaced"] == 1
    with target.transaction() as tx:
        assert tx.get("settings", "mode")["value"] == "target"


def test_hybrid_blob_paths_cannot_escape_store_and_metadata_rolls_back(tmp_path: Path) -> None:
    hybrid = HybridRepository(MemoryRepository(), FileBlobStore(tmp_path / "blobs"))
    with pytest.raises(PersistenceError, match="invalid blob name"):
        hybrid.blobs.put("../private-key.pem", b"secret")
    with pytest.raises(RuntimeError), hybrid.transaction() as tx:
        tx.upsert("certificates", {"id": 4, "secret_ref": "certificates/4.pem"})
        raise RuntimeError("metadata failure")
    with hybrid.transaction() as tx:
        assert tx.get("certificates", 4) is None


class _RecordingCursor:
    def __init__(self, connection: _RecordingConnection) -> None:
        self.connection = connection
        self.rows: list[tuple[Any, ...]] = []
        self.rowcount = 0

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        self.connection.statements.append((" ".join(sql.split()), params))

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self.rows

    def fetchone(self) -> tuple[Any, ...] | None:
        return self.rows[0] if self.rows else None


class _RecordingConnection:
    def __init__(self) -> None:
        self.statements: list[tuple[str, tuple[Any, ...]]] = []
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0

    def cursor(self) -> _RecordingCursor:
        return _RecordingCursor(self)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closes += 1


@pytest.mark.parametrize(
    ("repository_type", "expected_type", "upsert_fragment"),
    [
        (PostgreSQLRepository, "payload TEXT", "ON CONFLICT(collection, resource_id)"),
        (MySQLRepository, "payload LONGTEXT", "ON DUPLICATE KEY UPDATE"),
    ],
)
def test_dbapi_backend_contract_and_failure_rollback(
    repository_type: type[Any], expected_type: str, upsert_fragment: str
) -> None:
    connections: list[_RecordingConnection] = []

    def connect() -> _RecordingConnection:
        connection = _RecordingConnection()
        connections.append(connection)
        return connection

    repository = repository_type(connect_factory=connect)
    assert expected_type in connections[0].statements[0][0]
    assert connections[0].commits == connections[0].closes == 1

    with repository.transaction() as tx:
        tx.upsert("settings", {"id": "mode", "value": "strict"})
    assert upsert_fragment in connections[1].statements[0][0]
    assert connections[1].commits == connections[1].closes == 1

    with pytest.raises(RuntimeError), repository.transaction() as tx:
        tx.upsert("settings", {"id": "broken"})
        raise RuntimeError("database operation failed")
    assert connections[2].commits == 0
    assert connections[2].rollbacks == connections[2].closes == 1


def test_npm_migration_quarantines_invalid_data_and_is_idempotent() -> None:
    report = preflight_npm(
        {
            "user": [{"id": 1, "email": "owner@example.test"}],
            "certificate": [{"id": 10}, {"id": 10}, {"is_deleted": 0}],
            "proxy_host": [
                {"id": 20, "certificate_id": 10, "owner_user_id": 1},
                {"id": 21, "certificate_id": 999},
                {"id": 22, "is_deleted": True},
            ],
            "future_table": [{"id": 99}],
        }
    )
    reasons = {item.reason for item in report.quarantine}
    assert {"duplicate id", "missing id", "soft-deleted source record"} <= reasons
    assert any("does not resolve" in reason for reason in reasons)
    assert report.warnings == ["unsupported source table ignored: future_table"]

    target = MemoryRepository()
    first = import_npm(target, report, dry_run=False)
    second = import_npm(target, report, dry_run=False)
    assert first.created == report.importable
    assert second.unchanged == report.importable
    assert second.created == second.replaced == 0


def test_npm_migration_conflicts_do_not_replace_without_authorization() -> None:
    report = preflight_npm({"setting": [{"id": "theme", "value": "source"}]})
    target = MemoryRepository()
    Settings(target).set("theme", "target")

    result = import_npm(target, report, dry_run=False)
    assert result.quarantined == 1
    assert Settings(target).get("theme") == "target"
    replaced = import_npm(target, report, dry_run=False, replace=True)
    assert replaced.replaced == 1
    assert Settings(target).get("theme") == "source"


def test_recursive_audit_redaction_never_persists_credentials() -> None:
    audit = AuditLog(MemoryRepository())
    event = audit.append(
        "configuration.updated",
        actor="admin",
        details={
            "password": "hunter2",
            "nested": {"apiToken": "abc", "safe": "visible"},
            "credentials": [{"username": "dns", "secret": "def"}],
            "private-key": "pem",
        },
    )
    serialized_details = json.dumps(event["details"])
    assert "hunter2" not in serialized_details
    assert "abc" not in serialized_details and "def" not in serialized_details
    assert event["details"]["nested"]["safe"] == "visible"
    assert event["details"]["credentials"] == "[REDACTED]"


def test_health_isolates_repository_and_dependency_failures() -> None:
    class BrokenRepository:
        backend_name = "broken"

        def transaction(self) -> Any:
            raise OSError("database unavailable")

    def broken_check() -> bool:
        raise TimeoutError("nginx timed out")

    report = HealthService(
        BrokenRepository(), {"nginx": broken_check, "filesystem": lambda: {"free": 0}}
    ).ready()
    assert report["status"] == "degraded"
    assert report["components"]["database"] == {"status": "failed", "error": "OSError"}
    assert report["components"]["nginx"] == {"status": "failed", "error": "TimeoutError"}
    assert report["components"]["filesystem"]["status"] == "ok"


def test_log_rotation_is_bounded_and_preserves_generation_order(tmp_path: Path) -> None:
    log = tmp_path / "access.log"
    log.write_text("current", encoding="utf-8")
    (tmp_path / "access.log.1").write_text("previous", encoding="utf-8")
    (tmp_path / "access.log.2").write_text("oldest", encoding="utf-8")
    assert LogRotator(log, max_bytes=1, backups=2).rotate_if_needed()
    assert (tmp_path / "access.log.1").read_text(encoding="utf-8") == "current"
    assert (tmp_path / "access.log.2").read_text(encoding="utf-8") == "previous"
    assert not log.exists()

    disposable = tmp_path / "error.log"
    disposable.write_text("oversized", encoding="utf-8")
    assert LogRotator(disposable, max_bytes=1, backups=0).rotate_if_needed()
    assert not disposable.exists()


def test_failed_upgrade_rolls_back_and_can_be_retried() -> None:
    repository = MemoryRepository()
    attempts = 0

    def unreliable(tx: Any) -> None:
        nonlocal attempts
        attempts += 1
        tx.upsert("settings", {"id": "partial", "value": attempts})
        if attempts == 1:
            raise RuntimeError("upgrade interrupted")

    manager = UpgradeManager(repository, [Upgrade(1, "unreliable", unreliable)])
    with pytest.raises(RuntimeError, match="interrupted"):
        manager.run()
    with repository.transaction() as tx:
        assert tx.get("settings", "partial") is None
        assert tx.list("system_migrations") == []
    assert manager.run() == [1]
    assert manager.run() == []


def test_runtime_identity_configuration_and_container_artifacts_are_consistent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PORTWYRM_DB_BACKEND", "postgresql")
    monkeypatch.setenv("PORTWYRM_POSTGRES_HOST", "db.internal")
    monkeypatch.setenv("PORTWYRM_POSTGRES_PORT", "6543")
    monkeypatch.setenv("PORTWYRM_POSTGRES_DATABASE", "control")
    config = repository_config_from_environment()
    assert config["backend"] == "postgresql"
    assert config["postgresql"]["host"] == "db.internal"
    assert config["postgresql"]["port"] == 6543
    assert config["postgresql"]["dbname"] == "control"

    root = Path(__file__).parents[2]
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    compose = (root / "compose.yaml").read_text(encoding="utf-8")
    supervisor = (root / "deploy/entrypoint.py").read_text(encoding="utf-8")
    workflow = (root / ".github/workflows/container.yml").read_text(encoding="utf-8")
    assert "PORTWYRM_DB_BACKEND=sqlite" in dockerfile
    assert 'VOLUME ["/data", "/etc/letsencrypt"]' in dockerfile
    assert "EXPOSE 80 81 443" in dockerfile
    assert "HEALTHCHECK" in dockerfile and "/health/ready" in dockerfile
    assert "portwyrm-data:/data" in compose
    assert "portwyrm-certificates:/etc/letsencrypt" in compose
    assert 'subprocess.Popen(["nginx"' in supervisor
    assert '"portwyrm.operations.runtime"' in supervisor
    assert "linux/amd64,linux/arm64" in workflow
    assert "provenance: mode=max" in workflow and "sbom: true" in workflow
