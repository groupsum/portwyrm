"""Composition helpers shared by API factories and container startup."""

from __future__ import annotations

from portwyrm.operations.runtime import repository_config_from_environment
from portwyrm.persistence import Repository, create_repository


def create_default_repository() -> Repository:
    """Create the configured durable repository.

    Memory persistence remains available through ``PORTWYRM_DB_BACKEND=memory``
    but is never selected implicitly for an installed server.
    """

    return create_repository(repository_config_from_environment())
