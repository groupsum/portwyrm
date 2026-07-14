from __future__ import annotations

from pathlib import Path

import pytest

from portwyrm.persistence import (
    FileBlobStore,
    FilesystemRepository,
    HybridRepository,
    MemoryRepository,
    SQLiteRepository,
    export_bundle,
    import_bundle,
    preview_import,
    validate_bundle,
)


@pytest.fixture(params=["memory", "sqlite", "filesystem"])
def repository(request: pytest.FixtureRequest, tmp_path: Path):
    if request.param == "memory":
        return MemoryRepository()
    if request.param == "sqlite":
        return SQLiteRepository(tmp_path / "state.sqlite")
    return FilesystemRepository(tmp_path / "state")


def test_repository_contract_and_transaction_rollback(repository) -> None:
    with repository.transaction() as tx:
        tx.upsert(
            "proxy_hosts", {"id": 7, "domain_names": ["app.example.test"], "meta": {"owner": "a"}}
        )
    with repository.transaction() as tx:
        assert tx.get("proxy_hosts", 7)["meta"]["owner"] == "a"
        assert tx.collections() == ("proxy_hosts",)

    with pytest.raises(RuntimeError), repository.transaction() as tx:
        tx.upsert("proxy_hosts", {"id": 8})
        raise RuntimeError("rollback")
    with repository.transaction() as tx:
        assert tx.get("proxy_hosts", 8) is None


def test_versioned_bundle_round_trip_and_preview(tmp_path: Path) -> None:
    source = MemoryRepository()
    with source.transaction() as tx:
        tx.upsert("certificates", {"id": 161, "meta": {"managed_by": "npmctl", "owner": "edge"}})
    bundle = export_bundle(source)
    validate_bundle(bundle)

    target = SQLiteRepository(tmp_path / "target.sqlite")
    assert preview_import(target, bundle) == {"created": 1, "replaced": 0, "unchanged": 0}
    assert import_bundle(target, bundle) == {"created": 1, "replaced": 0, "unchanged": 0}
    assert preview_import(target, bundle) == {"created": 0, "replaced": 0, "unchanged": 1}


def test_hybrid_repository_keeps_metadata_and_blobs_separate(tmp_path: Path) -> None:
    blobs = FileBlobStore(tmp_path / "blobs")
    hybrid = HybridRepository(MemoryRepository(), blobs)
    with hybrid.transaction() as tx:
        tx.upsert("certificates", {"id": 1, "secret_ref": "certificates/1.pem"})
    blobs.put("certificates/1.pem", b"certificate")

    assert blobs.get("certificates/1.pem") == b"certificate"
    with hybrid.transaction() as tx:
        assert tx.get("certificates", 1)["secret_ref"] == "certificates/1.pem"
