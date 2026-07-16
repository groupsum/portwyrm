"""Primitives used inside Tigrbl operation and schema hooks.

Collection modules import this boundary instead of coupling their declarative
table surface to the kernel's validation and query implementation packages.
"""

from pydantic import ConfigDict, field_validator, model_validator
from sqlalchemy import delete, select, update

__all__ = [
    "ConfigDict",
    "delete",
    "field_validator",
    "model_validator",
    "select",
    "update",
]
