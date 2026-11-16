from __future__ import annotations

import asyncio
import base64
import threading
from pathlib import Path

import bcrypt

from portwyrm.runtime.basic_auth import BasicAuthCache


def _header(password: bytes) -> bytes:
    return b"Basic " + base64.b64encode(b"alice:" + password)


def _publish(policy: Path, password: bytes) -> None:
    temporary = policy.with_suffix(".next")
    temporary.write_bytes(b"alice:" + bcrypt.hashpw(password, bcrypt.gensalt(rounds=4)) + b"\n")
    temporary.replace(policy)


def test_cache_coalesces_success_and_rotation_invalidates_it(tmp_path, monkeypatch) -> None:
    async def run() -> None:
        policy = tmp_path / "cached-proxy-1"
        _publish(policy, b"old")
        verifier = BasicAuthCache(tmp_path)
        checkpw = bcrypt.checkpw
        calls = []

        def check(password: bytes, password_hash: bytes) -> bool:
            calls.append(password)
            return checkpw(password, password_hash)

        monkeypatch.setattr(bcrypt, "checkpw", check)
        assert (
            await asyncio.gather(*(verifier.authorize(policy, _header(b"old")) for _ in range(8)))
            == [204] * 8
        )
        assert await verifier.authorize(policy, _header(b"old")) == 204
        assert calls == [b"old"]

        _publish(policy, b"new")
        assert await verifier.authorize(policy, _header(b"old")) == 401
        assert await verifier.authorize(policy, _header(b"old")) == 401
        assert calls == [b"old"] * 3
        assert await verifier.authorize(policy, _header(b"new")) == 204
        policy.unlink()
        assert await verifier.authorize(policy, _header(b"new")) == 401

    asyncio.run(run)


def test_rotation_during_bcrypt_rejects_the_inflight_credential(tmp_path, monkeypatch) -> None:
    async def run() -> None:
        policy = tmp_path / "cached-proxy-1"
        _publish(policy, b"old")
        verifier = BasicAuthCache(tmp_path)
        started, finish = threading.Event(), threading.Event()
        checkpw = bcrypt.checkpw

        def pause(password: bytes, password_hash: bytes) -> bool:
            started.set()
            assert finish.wait(timeout=5)
            return checkpw(password, password_hash)

        monkeypatch.setattr(bcrypt, "checkpw", pause)
        task = asyncio.create_task(verifier.authorize(policy, _header(b"old")))
        try:
            assert await asyncio.to_thread(started.wait, 5)
            _publish(policy, b"new")
        finally:
            finish.set()
        assert await task == 401
        assert not verifier.accepted

    asyncio.run(run)
