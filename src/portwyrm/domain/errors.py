"""Domain errors with stable, API-independent meanings."""


class DomainValidationError(ValueError):
    """A resource violates a canonical invariant."""


class CollisionError(DomainValidationError):
    """A hostname or listening port collides with another resource."""


class OwnershipError(PermissionError):
    """A caller attempted to mutate a resource owned by another controller."""
