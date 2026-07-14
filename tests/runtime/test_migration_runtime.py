from __future__ import annotations

import sqlite3
from pathlib import Path

from portwyrm.migration import import_npm, preflight_npm, preflight_npm_sqlite
from portwyrm.persistence import MemoryRepository


def test_npm_preflight_preserves_ids_metadata_and_quarantines_invalid_references() -> None:
    source = {
        "user": [{"id": 1, "email": "admin@example.test"}],
        "certificate": [{"id": 161, "domain_names": '["example.test"]'}],
        "proxy_host": [
            {
                "id": 7,
                "certificate_id": 161,
                "domain_names": '["app.example.test"]',
                "meta": '{"managed_by":"npmctl","owner":"edge","resource_id":"proxy.app"}',
            },
            {"id": 8, "certificate_id": 999, "domain_names": '["broken.example.test"]'},
            {"id": 9, "is_deleted": 1, "domain_names": '["deleted.example.test"]'},
        ],
    }
    report = preflight_npm(source)

    assert report.importable == 3
    assert [item.source_id for item in report.quarantine] == ["9", "8"]
    proxy = report.records["proxy_hosts"][0]
    assert proxy["id"] == 7
    assert proxy["meta"]["managed_by"] == "npmctl"

    target = MemoryRepository()
    preview = import_npm(target, report)
    assert preview.created == 3
    assert preview.dry_run is True
    with target.transaction() as tx:
        assert tx.collections() == ()

    result = import_npm(target, report, dry_run=False)
    assert result.created == 3
    with target.transaction() as tx:
        assert tx.get("proxy_hosts", 7)["meta"]["resource_id"] == "proxy.app"
        assert tx.get("certificates", 161)["id"] == 161


def test_read_only_sqlite_preflight(tmp_path: Path) -> None:
    path = tmp_path / "npm.sqlite"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE user (id INTEGER PRIMARY KEY, email TEXT, is_deleted INTEGER)")
    connection.execute("INSERT INTO user VALUES (1, 'admin@example.test', 0)")
    connection.commit()
    connection.close()

    report = preflight_npm_sqlite(path)
    assert report.source_kind == "sqlite"
    assert report.records["users"] == [{"id": 1, "email": "admin@example.test", "is_deleted": 0}]
