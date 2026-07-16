"""Late-bound identity service proxy for application composition."""

from typing import Any


class IdentityStoreProxy:
    def __init__(self, target: Any) -> None:
        self.target = target

    def bind(self, target: Any) -> None:
        self.target = target

    def __getattr__(self, name: str) -> Any:
        return getattr(self.target, name)
