"""Stable application errors shared by table, runtime, and compatibility layers."""


class DomainValidationError(ValueError):
    """A persisted or rendered resource violates a canonical invariant."""


class CollisionError(DomainValidationError):
    """A hostname or listening port collides with another resource."""


class OwnershipError(PermissionError):
    """A caller attempted to mutate a resource owned by another controller."""


class AuthorizationError(PermissionError):
    """A principal lacks authority for the requested collection operation."""


__all__ = [
    "AuthorizationError",
    "CollisionError",
    "DomainValidationError",
    "OwnershipError",
]
