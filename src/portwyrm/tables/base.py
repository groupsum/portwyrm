"""Shared Tigrbl table bases and lifecycle hooks."""

from __future__ import annotations

from tigrbl import TableBase
from tigrbl.factories.table import defineTableSpec
from tigrbl.orm.mixins import Timestamped
from tigrbl.types import JSON, Column, Integer


class PortwyrmTable(TableBase, Timestamped):
    """Base for internal tables with no implicit public operation profile."""

    __abstract__ = True
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True, autoincrement=True)
    metadata_json = Column(JSON, nullable=False, default=dict)


ManagedTableSpec = defineTableSpec(
    ops=(
        "create",
        "read",
        "update",
        "replace",
        "delete",
        "list",
        "bulk_create",
        "bulk_update",
        "bulk_replace",
        "bulk_delete",
    )
)


class ManagedPortwyrmTable(TableBase, Timestamped, ManagedTableSpec):
    """REST bulk CRUD profile for operator-managed, non-secret resources."""

    __abstract__ = True
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True, autoincrement=True)
    metadata_json = Column(JSON, nullable=False, default=dict)
