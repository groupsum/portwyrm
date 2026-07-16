"""Tigrbl-owned HTTP policy middleware for the Portwyrm control plane."""

from __future__ import annotations

import hmac
import os
from collections.abc import Awaitable, Callable
from typing import Any

from tigrbl import JSONResponse, Middleware, Request

ASGIReceive = Callable[[], Awaitable[dict[str, Any]]]
ASGISend = Callable[[dict[str, Any]], Awaitable[None]]


class ControlPlaneHTTPMiddleware(Middleware):
    """Enforce browser CSRF, security headers, and typed domain errors."""

    async def asgi(
        self,
        scope: dict[str, Any],
        receive: ASGIReceive,
        send: ASGISend,
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        request = Request.from_scope(scope, receive)
        session_cookie = request.cookies.get("portwyrm_session")
        if (
            session_cookie
            and request.method in {"POST", "PUT", "PATCH", "DELETE"}
            and request.path not in {"/api/v2/browser/login", "/api/v2/browser/2fa"}
        ):
            cookie_csrf = request.cookies.get("portwyrm_csrf")
            header_csrf = request.headers.get("x-csrf-token")
            if (
                not cookie_csrf
                or not header_csrf
                or not hmac.compare_digest(cookie_csrf, header_csrf)
            ):
                await JSONResponse({"detail": "CSRF validation failed"}, status_code=403)(
                    scope, receive, send
                )
                return

        async def secured_send(message: dict[str, Any]) -> None:
            if message.get("type") == "http.response.start":
                headers: list[tuple[bytes, bytes]] = []
                for key, value in message.get("headers", ()):
                    if key.lower() != b"set-cookie" or b", portwyrm_" not in value:
                        headers.append((key, value))
                        continue
                    for cookie in value.split(b", portwyrm_"):
                        normalized = (
                            cookie if cookie.startswith(b"portwyrm_") else b"portwyrm_" + cookie
                        )
                        headers.append((key, normalized))
                headers.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (
                            b"x-frame-options",
                            os.getenv("PORTWYRM_X_FRAME_OPTIONS", "DENY").encode("latin-1"),
                        ),
                        (b"referrer-policy", b"same-origin"),
                    ]
                )
                if request.path.startswith("/api"):
                    headers.append((b"cache-control", b"no-store"))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, secured_send)
