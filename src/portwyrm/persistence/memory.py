"""Process-local transactional repository."""

from __future__ import annotations

import copy
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from .base import MappingTransaction, Resource


class MemoryRepository:
    backend_name = "memory"

    def __init__(self) -> None:
        self._state: dict[str, dict[str, Resource]] = {}
        self._lock = threading.RLock()

    @contextmanager
    def transaction(self) -> Iterator[MappingTransaction]:
        with self._lock:
            candidate = copy.deepcopy(self._state)
            tx = MappingTransaction(candidate)
            yield tx
            self._state = candidate
