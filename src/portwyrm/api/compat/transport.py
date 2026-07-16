"""Isolated request binding for the frozen npm-compatible wire surface."""

from __future__ import annotations

import inspect
import re
from collections.abc import Callable
from typing import Any, cast

from tigrbl import HTTPException, Request, Response
from tigrbl.factories.app import deriveApp
from tigrbl.factories.router import deriveRouter


async def _resolve_dependency(dependency: Callable[..., Any], request: Request) -> Any:
    """Resolve the small dependency surface used by the compatibility facade."""
    kwargs: dict[str, Any] = {}
    for name, parameter in inspect.signature(dependency).parameters.items():
        annotation = parameter.annotation
        if name in {"request", "_request"} or getattr(annotation, "__name__", None) == "Request":
            kwargs[name] = request
    value = dependency(**kwargs)
    return await value if inspect.isawaitable(value) else value


def _coerce_path_value(value: str, annotation: Any) -> Any:
    if annotation is int or annotation == "int":
        try:
            return int(value)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="invalid path parameter") from exc
    return value


def _path_pattern(path: str) -> re.Pattern[str]:
    expression = re.sub(
        r"\{([A-Za-z_][A-Za-z0-9_]*)\}",
        lambda match: f"(?P<{match.group(1)}>[^/]+)",
        path.rstrip("/") or "/",
    )
    return re.compile(f"^{expression}/?$")


def _compat_endpoint(
    handler: Callable[..., Any], *, path: str, status_code: int
) -> Callable[..., Any]:
    """Adapt legacy callable signatures to Tigrbl's explicit request context."""
    signature = inspect.signature(handler)
    path_pattern = _path_pattern(path)

    async def endpoint(request: Request) -> Any:

        kwargs: dict[str, Any] = {}
        injected_response: Response | None = None
        path_params = dict(getattr(request, "path_params", {}) or {})
        match = path_pattern.match(request.path)
        if match is not None:
            path_params.update(match.groupdict())
        payload_loaded = False
        payload: Any = None

        for name, parameter in signature.parameters.items():
            if name in path_params:
                kwargs[name] = _coerce_path_value(path_params[name], parameter.annotation)
                continue

            dependency = getattr(parameter.default, "dependency", None)
            if callable(dependency):
                kwargs[name] = await _resolve_dependency(dependency, request)
                continue

            annotation_name = getattr(parameter.annotation, "__name__", None)
            if name in {"request", "_request"} or annotation_name == "Request":
                kwargs[name] = request
                continue
            if name == "response" or annotation_name == "Response":
                injected_response = Response()
                kwargs[name] = injected_response
                continue
            if name == "payload":
                if not payload_loaded:
                    try:
                        payload = request.json_sync()
                    except (TypeError, ValueError) as exc:
                        raise HTTPException(status_code=422, detail="invalid JSON payload") from exc
                    payload_loaded = True
                if not isinstance(payload, dict):
                    raise HTTPException(status_code=422, detail="JSON object required")
                kwargs[name] = payload
                continue

            query_value = request.query_param(name)
            if query_value is not None:
                kwargs[name] = query_value
            elif parameter.default is inspect.Parameter.empty:
                raise HTTPException(status_code=422, detail=f"{name} is required")

        result = handler(**kwargs)
        if inspect.isawaitable(result):
            result = await result
        if isinstance(result, Response):
            return result

        headers = dict(injected_response.headers) if injected_response is not None else None
        if status_code == 204:
            return Response(status_code=status_code, headers=headers)
        if injected_response is not None or status_code != 200:
            return Response.from_json(result, status_code=status_code, headers=headers)
        return result

    endpoint.__name__ = getattr(handler, "__name__", "compat_endpoint")
    endpoint.__doc__ = getattr(handler, "__doc__", None)
    return endpoint


class _CompatibilityRouteMixin:
    """Bind compatibility callables through Tigrbl request contexts."""

    def add_route(
        self,
        path: str,
        endpoint: Any,
        *,
        methods: list[str] | tuple[str, ...],
        **kwargs: Any,
    ) -> None:
        status_code = int(kwargs.get("status_code") or 200)
        parent = cast(Any, super())
        parent.add_route(
            path,
            _compat_endpoint(endpoint, path=path, status_code=status_code),
            methods=methods,
            **kwargs,
        )

    def route(self, path: str, *, methods: Any, **kwargs: Any) -> Callable[[Any], Any]:
        def decorator(endpoint: Any) -> Any:
            self.add_route(path, endpoint, methods=methods, **kwargs)
            return endpoint

        return decorator


PortwyrmRouter = deriveRouter(name="portwyrm-router")


class CompatibilityTigrblRouter(_CompatibilityRouteMixin, PortwyrmRouter):
    """Tigrbl router for the frozen compatibility surface."""


PortwyrmApp = deriveApp(
    title="Portwyrm",
    description="Self-hosted reverse-proxy control plane",
    version="0.1.0a0",
    execution_backend="auto",
)


class CompatibilityTigrblApp(_CompatibilityRouteMixin, PortwyrmApp):
    """Tigrbl app that binds the frozen npmctl facade during migration."""

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        async def core(core_scope: dict[str, Any], core_receive: Any, core_send: Any) -> None:
            await super(CompatibilityTigrblApp, self).__call__(core_scope, core_receive, core_send)

        wrapped: Any = core
        for middleware_class, options in reversed(self._middlewares):
            wrapped = middleware_class(wrapped, **(options or {}))
        await wrapped(scope, receive, send)
