"""Hybrid metadata-plus-blob deployment profile."""

from __future__ import annotations

from contextlib import AbstractContextManager

from .base import BlobStore, Repository, Transaction


class HybridRepository:
    backend_name = "hybrid"

    def __init__(self, metadata: Repository, blobs: BlobStore) -> None:
        self.metadata = metadata
        self.blobs = blobs

    def transaction(self) -> AbstractContextManager[Transaction]:
        return self.metadata.transaction()
