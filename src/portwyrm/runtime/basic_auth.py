"""Private Basic Auth verifier for opted-in hosts."""

from __future__ import annotations

import asyncio
import base64
import hmac
import os
import re
import secrets
import time
from collections import OrderedDict
from pathlib import Path

import bcrypt

CACHE_HOST_ENV = "PORTWYRM_BASIC_AUTH_CACHE_HOST"
VERIFIER_PORT = 8091
VERIFIER_LOCATION = "/.portwyrm/basic-auth"
BCRYPT_HASH = re.compile(rb"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")


class BasicAuthCache:
    def __init__(self, root: Path, *, ttl: float = 60, capacity: int = 1024) -> None:
        self.root = root
        self.ttl = ttl
        self.capacity = capacity
        self.key = secrets.token_bytes(32)
        self.accepted: OrderedDict[bytes, float] = OrderedDict()
        self.pending: dict[bytes, asyncio.Task[int]] = {}

    async def authorize(self, policy: Path, header: bytes) -> int:
        scheme, _, encoded = header.partition(b" ")
        if scheme.lower() != b"basic" or len(encoded) > 2048:
            return 401
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except ValueError:
            return 401
        username, separator, password = decoded.partition(b":")
        if not separator or not username or b"\0" in decoded:
            return 401
        try:
            credentials = policy.read_bytes()
        except FileNotFoundError:
            return 401

        digest = hmac.digest(
            self.key, b"\0".join((policy.name.encode(), credentials, decoded)), "sha256"
        )
        if self.accepted.get(digest, 0) > time.monotonic():
            self.accepted.move_to_end(digest)
            return 204

        hashes = dict(line.split(b":", 1) for line in credentials.splitlines() if b":" in line)
        password_hash = hashes.get(username, b"")
        if not BCRYPT_HASH.fullmatch(password_hash):
            return 401
        task = self.pending.get(digest)
        if task is None:
            if len(self.pending) >= 32:
                return 503
            task = asyncio.create_task(
                self.verify(digest, policy, credentials, password[:72], password_hash)
            )
            self.pending[digest] = task
        status = await asyncio.shield(task)
        # A reload may publish a new policy while this request awaits bcrypt.
        try:
            return status if policy.read_bytes() == credentials else 401
        except FileNotFoundError:
            return 401

    async def verify(
        self, digest: bytes, policy: Path, credentials: bytes, password: bytes, password_hash: bytes
    ) -> int:
        try:
            if not await asyncio.to_thread(bcrypt.checkpw, password, password_hash):
                return 401
            if policy.read_bytes() != credentials:
                return 401
            self.accepted[digest] = time.monotonic() + self.ttl
            self.accepted.move_to_end(digest)
            while len(self.accepted) > self.capacity:
                self.accepted.popitem(last=False)
            return 204
        except (FileNotFoundError, ValueError):
            return 401
        finally:
            self.pending.pop(digest, None)

    async def __call__(self, scope, receive, send) -> None:
        host_id = scope["path"].removeprefix("/")
        headers = [value for name, value in scope["headers"] if name == b"authorization"]
        status = 401
        if re.fullmatch(r"[0-9]+", host_id) and len(headers) == 1:
            policy = self.root / "current" / "access" / f"cached-proxy-{host_id}"
            status = await self.authorize(policy, headers[0])
        result_headers = [(b"cache-control", b"no-store")]
        if status == 401:
            result_headers.append((b"www-authenticate", b'Basic realm="Authorization required"'))
        await send({"type": "http.response.start", "status": status, "headers": result_headers})
        await send({"type": "http.response.body", "body": b""})


def create_verifier() -> BasicAuthCache:
    return BasicAuthCache(Path(os.environ.get("PORTWYRM_NGINX_ROOT", "/data/nginx")))
