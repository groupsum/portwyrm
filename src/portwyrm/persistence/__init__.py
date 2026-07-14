"""Persistence adapters and portable state bundles."""

from .base import BlobStore, ConfigurationError, ConflictError, PersistenceError, Repository
from .bundle import BUNDLE_VERSION, export_bundle, import_bundle, preview_import, validate_bundle
from .dbapi import MySQLRepository, PostgreSQLRepository
from .factory import create_repository
from .filesystem import FileBlobStore, FilesystemRepository
from .hybrid import HybridRepository
from .memory import MemoryRepository
from .sqlite import SQLiteRepository

__all__ = [
    "BUNDLE_VERSION",
    "BlobStore",
    "ConfigurationError",
    "ConflictError",
    "FileBlobStore",
    "FilesystemRepository",
    "HybridRepository",
    "MemoryRepository",
    "MySQLRepository",
    "PersistenceError",
    "PostgreSQLRepository",
    "Repository",
    "SQLiteRepository",
    "create_repository",
    "export_bundle",
    "import_bundle",
    "preview_import",
    "validate_bundle",
]
