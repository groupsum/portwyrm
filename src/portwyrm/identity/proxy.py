"""Late-bound identity service proxy for application composition."""

from typing import Any


class IdentityStoreProxy:
    def __init__(self, target: Any = None) -> None:
        self.target = target

    def bind(self, target: Any) -> None:
        self.target = target

    def __getattr__(self, name: str) -> Any:
        if self.target is None:
            raise RuntimeError("identity store proxy is not bound")
        return getattr(self.target, name)
