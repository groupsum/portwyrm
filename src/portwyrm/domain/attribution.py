"""Attribution carried from an initiating request into internal operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class OperationAttribution:
    """Identify both the initiator and the component executing derived work."""

    principal: Any | None = None
    executor_kind: str = "service"
    executor_name: str = "Portwyrm reconciler"
    correlation_id: str = ""

    @classmethod
    def reconciliation(cls, principal: Any | None = None) -> OperationAttribution:
        return cls(principal=principal, correlation_id=uuid4().hex)

    def details(self) -> dict[str, str]:
        return {
            "executor_kind": self.executor_kind,
            "executor_name": self.executor_name,
            "correlation_id": self.correlation_id or uuid4().hex,
        }


__all__ = ["OperationAttribution"]
