"""Live external database conformance checks used by the release workflow."""

from __future__ import annotations

import os

import pytest

from portwyrm.persistence import MySQLRepository, PostgreSQLRepository


@pytest.mark.parametrize("backend", ["postgresql", "mysql"])
def test_live_external_database_transaction_and_restart_contract(backend: str) -> None:
    if os.getenv("PORTWYRM_RUN_DATABASE_TESTS") != "1":
        pytest.skip("set PORTWYRM_RUN_DATABASE_TESTS=1 to run live database conformance")
    if backend == "postgresql":
        config = {
            "host": os.getenv("PORTWYRM_TEST_POSTGRES_HOST", "127.0.0.1"),
            "port": int(os.getenv("PORTWYRM_TEST_POSTGRES_PORT", "5432")),
            "dbname": "portwyrm",
            "user": "portwyrm",
            "password": "portwyrm-test",
        }
        repository_type = PostgreSQLRepository
    else:
        config = {
            "host": os.getenv("PORTWYRM_TEST_MYSQL_HOST", "127.0.0.1"),
            "port": int(os.getenv("PORTWYRM_TEST_MYSQL_PORT", "3306")),
            "database": "portwyrm",
            "user": "portwyrm",
            "password": "portwyrm-test",
        }
        repository_type = MySQLRepository

    repository = repository_type(config)
    with repository.transaction() as tx:
        tx.delete("release_probe", backend)
        tx.upsert("release_probe", {"id": backend, "value": "committed"})
    with pytest.raises(RuntimeError), repository.transaction() as tx:
        tx.upsert("release_probe", {"id": backend, "value": "rolled-back"})
        raise RuntimeError("rollback probe")
    restarted = repository_type(config)
    with restarted.transaction() as tx:
        assert tx.get("release_probe", backend) == {"id": backend, "value": "committed"}
