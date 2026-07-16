"""Late-bound application service proxy."""

from typing import Any


class ApplicationServiceProxy:
    def __init__(self, target: Any) -> None:
        object.__setattr__(self, "target", target)

    def bind(self, target: Any) -> None:
        object.__setattr__(self, "target", target)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.target, name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self.target, name, value)
