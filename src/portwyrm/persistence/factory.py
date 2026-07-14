"""Environment-friendly persistence adapter selection."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .base import ConfigurationError, Repository
from .dbapi import MySQLRepository, PostgreSQLRepository
from .filesystem import FileBlobStore, FilesystemRepository
from .hybrid import HybridRepository
from .memory import MemoryRepository
from .sqlite import SQLiteRepository


def create_repository(config: Mapping[str, Any]) -> Repository:
    backend = str(config.get("backend", "sqlite")).lower()
    data_root = Path(str(config.get("data_root", "/data")))
    if backend == "memory":
        return MemoryRepository()
    if backend == "sqlite":
        return SQLiteRepository(config.get("sqlite_path", data_root / "portwyrm.sqlite"))
    if backend == "filesystem":
        return FilesystemRepository(config.get("filesystem_root", data_root / "repository"))
    if backend == "mysql":
        return MySQLRepository(config.get("mysql", {}))
    if backend == "postgresql":
        return PostgreSQLRepository(config.get("postgresql", {}))
    if backend == "hybrid":
        metadata_config = dict(config.get("metadata", {}))
        metadata_config.setdefault("data_root", data_root)
        metadata = create_repository(metadata_config)
        blobs = FileBlobStore(config.get("blob_root", data_root / "blobs"))
        return HybridRepository(metadata, blobs)
    raise ConfigurationError(f"unknown persistence backend: {backend}")
