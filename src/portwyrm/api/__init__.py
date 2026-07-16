"""Public API factories without eager composition-root side effects."""

from typing import Any

__all__ = ["CompatibilityService", "create_app", "create_compat_app"]


def __getattr__(name: str) -> Any:
    if name == "create_app":
        from portwyrm.api.app import create_app

        return create_app
    if name in {"CompatibilityService", "create_compat_app"}:
        from portwyrm.api.compat import CompatibilityService, create_compat_app

        return {
            "CompatibilityService": CompatibilityService,
            "create_compat_app": create_compat_app,
        }[name]
    raise AttributeError(name)
