"""Canonical ownership metadata used by npmctl and native callers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from portwyrm.errors import DomainValidationError, OwnershipError


@dataclass(frozen=True, slots=True)
class Ownership:
    """Ownership identity preserved verbatim in the resource ``meta`` object."""

    managed_by: str
    owner: str
    resource_id: str

    def __post_init__(self) -> None:
        for field_name, value in (
            ("managed_by", self.managed_by),
            ("owner", self.owner),
            ("resource_id", self.resource_id),
        ):
            if not isinstance(value, str) or not value.strip():
                raise DomainValidationError(f"ownership {field_name} must be a non-empty string")

    @classmethod
    def from_meta(cls, meta: Mapping[str, Any]) -> Ownership | None:
        keys = ("managed_by", "owner", "resource_id")
        present = [key in meta for key in keys]
        if not any(present):
            return None
        if not all(present):
            raise DomainValidationError("ownership metadata must contain all three canonical keys")
        return cls(*(meta[key] for key in keys))

    def apply_to(self, meta: Mapping[str, Any] | None = None) -> dict[str, Any]:
        result = dict(meta or {})
        result.update(
            managed_by=self.managed_by,
            owner=self.owner,
            resource_id=self.resource_id,
        )
        return result

    def assert_mutable_by(
        self,
        *,
        managed_by: str,
        owner: str,
        adopt: bool = False,
    ) -> None:
        if self.managed_by == managed_by and self.owner == owner:
            return
        if adopt:
            return
        raise OwnershipError(
            f"resource is owned by {self.managed_by}/{self.owner}; explicit adoption is required"
        )


def assert_owner_scoped_prune(
    resources: list[Ownership | None], *, managed_by: str, owner: str
) -> None:
    """Fail closed when a prune selection contains foreign or unmanaged resources."""

    for ownership in resources:
        if ownership is None:
            raise OwnershipError("unmanaged resources cannot be pruned implicitly")
        ownership.assert_mutable_by(managed_by=managed_by, owner=owner)
