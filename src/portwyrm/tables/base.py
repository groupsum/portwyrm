"""Shared Tigrbl table profiles and column contracts."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Final

from tigrbl import ForeignKeySpec, RestTable, TableBase, TableProfileSpec
from tigrbl.factories.column import IO, F, S
from tigrbl.factories.column import acol as _acol
from tigrbl.orm.mixins import Timestamped
from tigrbl.types import JSON, Integer

MUTABLE: Final = IO(
    in_verbs=("create", "update", "replace"),
    out_verbs=("read", "list"),
    mutable_verbs=("create", "update", "replace"),
)
READ_ONLY: Final = IO(
    out_verbs=("read", "list"),
    mutable_verbs=("read", "list"),
)

# The OLTP column collector snapshots inherited mixin descriptors before concrete
# table overrides are materialized. Tighten the shared mixin descriptors up front
# so canonical replace never treats lifecycle timestamps as writable fields.
for _timestamp_name in ("created_at", "updated_at"):
    Timestamped.__tigrbl_colspecs__[_timestamp_name].io = READ_ONLY


def acol(
    type_: Any | None = None,
    *constraints: Any,
    storage: S | None = None,
    field: F | None = None,
    io: IO | None = None,
    **storage_options: Any,
) -> Any:
    """Declare a Portwyrm column through Tigrbl's public column contract."""

    if storage is not None:
        return _acol(storage=storage, field=field, io=io)
    foreign_key = next(
        (getattr(item, "target_fullname", None) for item in constraints if item is not None),
        None,
    )
    if foreign_key:
        storage_options["fk"] = ForeignKeySpec(str(foreign_key))
    resolved = type_() if isinstance(type_, type) else type_
    py_type = getattr(resolved, "python_type", Any)
    return _acol(
        storage=S(type_=type_, **storage_options),
        field=field or F(py_type=py_type),
        io=io or MUTABLE,
    )


def rest_profile(*targets: str, kind: str) -> TableProfileSpec:
    """Return a strict single-row REST profile containing only ``targets``."""

    selected = tuple(spec for spec in RestTable.TABLE_PROFILE.ops if spec.target in targets)
    return replace(
        RestTable.TABLE_PROFILE,
        kind=kind,
        ops=selected,
        custom=True,
        namespace="portwyrm",
    )


MANAGED_PROFILE: Final = rest_profile(
    "create", "read", "update", "replace", "delete", "list", kind="portwyrm_managed"
)
READ_ONLY_PROFILE: Final = rest_profile("read", "list", kind="portwyrm_read_only")
APPEND_ONLY_PROFILE: Final = rest_profile("create", "read", "list", kind="portwyrm_append_only")
NO_CRUD_PROFILE: Final = TableProfileSpec(
    kind="portwyrm_operations_only",
    role="concrete",
    ops=(),
    custom=True,
    namespace="portwyrm",
)


class PortwyrmTable(TableBase, Timestamped):
    """Base for internal tables whose authority is expressed by named operations."""

    __abstract__ = True
    __allow_unmapped__ = True
    TABLE_PROFILE = NO_CRUD_PROFILE

    id = acol(
        storage=S(type_=Integer, primary_key=True, autoincrement=True),
        field=F(py_type=int),
        io=READ_ONLY,
    )
    metadata_json = acol(
        storage=S(type_=JSON, nullable=False, default=dict),
        field=F(py_type=dict),
        io=MUTABLE,
    )


class ManagedPortwyrmTable(RestTable, Timestamped):
    """Strict single-row CRUD profile for operator-managed resources."""

    __abstract__ = True
    __allow_unmapped__ = True
    TABLE_PROFILE = MANAGED_PROFILE

    id = acol(
        storage=S(type_=Integer, primary_key=True, autoincrement=True),
        field=F(py_type=int),
        io=READ_ONLY,
    )
    metadata_json = acol(
        storage=S(type_=JSON, nullable=False, default=dict),
        field=F(py_type=dict),
        io=MUTABLE,
    )


__all__ = [
    "APPEND_ONLY_PROFILE",
    "MANAGED_PROFILE",
    "MUTABLE",
    "NO_CRUD_PROFILE",
    "READ_ONLY",
    "READ_ONLY_PROFILE",
    "ManagedPortwyrmTable",
    "PortwyrmTable",
    "acol",
    "rest_profile",
]
