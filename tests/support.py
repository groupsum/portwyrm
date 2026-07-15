"""Framework-neutral ASGI client used by Portwyrm tests."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx


class TestClient:
    """Small synchronous facade over HTTPX's ASGI transport."""

    __test__ = False

    def __init__(self, app: Any) -> None:
        self.app = app
        self.cookies = httpx.Cookies()

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        follow_redirects = bool(kwargs.pop("follow_redirects", True))

        async def send() -> httpx.Response:
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
                cookies=self.cookies,
                follow_redirects=follow_redirects,
            ) as client:
                return await client.request(method, url, **kwargs)

        response = asyncio.run(send())
        self.cookies.update(response.cookies)
        return response

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("DELETE", url, **kwargs)
