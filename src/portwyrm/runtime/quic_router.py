"""Opaque QUIC Initial/SNI router managed by Portwyrm.

Only the public QUIC Initial keys are derived to inspect ClientHello. TLS is
never completed here; Tigrcorn remains the QUIC/TLS/WebTransport endpoint.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import logging
import os
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LOGGER = logging.getLogger("portwyrm.quic_router")
_V1 = 0x00000001
_V2 = 0x6B3343CF
_SALTS = {
    _V1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    _V2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
}


class QuicParseError(ValueError):
    pass


def _varint(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise QuicParseError("truncated QUIC varint")
    size = 1 << (data[offset] >> 6)
    if offset + size > len(data):
        raise QuicParseError("truncated QUIC varint")
    value = data[offset] & 0x3F
    for byte in data[offset + 1 : offset + size]:
        value = (value << 8) | byte
    return value, offset + size


def _hkdf_expand(secret: bytes, info: bytes, length: int) -> bytes:
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(secret, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def _label(secret: bytes, label: str, length: int) -> bytes:
    encoded = b"tls13 " + label.encode()
    info = length.to_bytes(2, "big") + bytes([len(encoded)]) + encoded + b"\x00"
    return _hkdf_expand(secret, info, length)


def _initial_keys(version: int, dcid: bytes) -> tuple[bytes, bytes, bytes]:
    salt = _SALTS.get(version)
    if salt is None:
        raise QuicParseError(f"unsupported QUIC version 0x{version:08x}")
    initial = hmac.new(salt, dcid, hashlib.sha256).digest()
    client = _label(initial, "client in", 32)
    prefix = "quicv2 " if version == _V2 else "quic "
    return (
        _label(client, prefix + "key", 16),
        _label(client, prefix + "iv", 12),
        _label(client, prefix + "hp", 16),
    )


def decrypt_initial(datagram: bytes) -> bytes:
    if len(datagram) < 40 or not datagram[0] & 0x80:
        raise QuicParseError("not a QUIC long-header packet")
    version = int.from_bytes(datagram[1:5], "big")
    offset = 5
    dcid_len = datagram[offset]
    offset += 1
    dcid = datagram[offset : offset + dcid_len]
    offset += dcid_len
    if offset >= len(datagram):
        raise QuicParseError("truncated destination connection id")
    scid_len = datagram[offset]
    offset += 1 + scid_len
    token_len, offset = _varint(datagram, offset)
    offset += token_len
    packet_length, pn_offset = _varint(datagram, offset)
    packet_end = pn_offset + packet_length
    if packet_end > len(datagram) or pn_offset + 20 > packet_end:
        raise QuicParseError("truncated QUIC Initial packet")
    key, iv, hp = _initial_keys(version, dcid)
    sample = datagram[pn_offset + 4 : pn_offset + 20]
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(sample)
    first = datagram[0] ^ (mask[0] & 0x0F)
    packet_number_length = (first & 0x03) + 1
    packet_number_bytes = bytes(
        datagram[pn_offset + index] ^ mask[index + 1] for index in range(packet_number_length)
    )
    packet_number = int.from_bytes(packet_number_bytes, "big")
    header = bytearray(datagram[: pn_offset + packet_number_length])
    header[0] = first
    header[pn_offset : pn_offset + packet_number_length] = packet_number_bytes
    nonce = bytearray(iv)
    encoded_number = packet_number.to_bytes(len(iv), "big")
    for index, byte in enumerate(encoded_number):
        nonce[index] ^= byte
    ciphertext = datagram[pn_offset + packet_number_length : packet_end]
    try:
        return AESGCM(key).decrypt(bytes(nonce), ciphertext, bytes(header))
    except Exception as exc:
        raise QuicParseError("unable to decrypt QUIC Initial") from exc


def initial_connection_ids(datagram: bytes) -> tuple[bytes, bytes]:
    """Return destination and source connection IDs from a QUIC long header."""
    if len(datagram) < 7 or not datagram[0] & 0x80:
        raise QuicParseError("not a QUIC long-header packet")
    offset = 5
    dcid_length = datagram[offset]
    offset += 1
    dcid = datagram[offset : offset + dcid_length]
    offset += dcid_length
    if offset >= len(datagram):
        raise QuicParseError("truncated destination connection id")
    scid_length = datagram[offset]
    offset += 1
    scid = datagram[offset : offset + scid_length]
    if len(dcid) != dcid_length or len(scid) != scid_length:
        raise QuicParseError("truncated QUIC connection id")
    return dcid, scid


def crypto_fragments(plaintext: bytes) -> dict[int, bytes]:
    offset = 0
    fragments: dict[int, bytes] = {}
    while offset < len(plaintext):
        frame_type, offset = _varint(plaintext, offset)
        if frame_type in {0, 1}:
            continue
        if frame_type == 6:
            crypto_offset, offset = _varint(plaintext, offset)
            length, offset = _varint(plaintext, offset)
            if offset + length > len(plaintext):
                raise QuicParseError("truncated QUIC CRYPTO frame")
            fragments[crypto_offset] = plaintext[offset : offset + length]
            offset += length
            continue
        break
    return fragments


def assemble_crypto(fragments: dict[int, bytes]) -> bytes:
    assembled = bytearray()
    for fragment_offset, fragment in sorted(fragments.items()):
        if fragment_offset > len(assembled):
            break
        overlap = len(assembled) - fragment_offset
        if overlap < len(fragment):
            assembled.extend(fragment[overlap:])
    return bytes(assembled)


def parse_client_hello(crypto: bytes) -> tuple[str, tuple[str, ...]]:
    if len(crypto) < 4 or crypto[0] != 1:
        raise QuicParseError("QUIC CRYPTO data does not start with ClientHello")
    length = int.from_bytes(crypto[1:4], "big")
    body = crypto[4 : 4 + length]
    if len(body) != length:
        raise QuicParseError("fragmented ClientHello is not yet complete")
    offset = 34
    session_length = body[offset]
    offset += 1 + session_length
    cipher_length = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2 + cipher_length
    compression_length = body[offset]
    offset += 1 + compression_length
    extensions_length = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    end = offset + extensions_length
    server_name = ""
    alpns: list[str] = []
    while offset + 4 <= end:
        extension_type = int.from_bytes(body[offset : offset + 2], "big")
        extension_length = int.from_bytes(body[offset + 2 : offset + 4], "big")
        value = body[offset + 4 : offset + 4 + extension_length]
        offset += 4 + extension_length
        if extension_type == 0 and len(value) >= 5:
            name_length = int.from_bytes(value[3:5], "big")
            server_name = value[5 : 5 + name_length].decode("ascii").casefold().rstrip(".")
        elif extension_type == 16 and len(value) >= 2:
            cursor = 2
            while cursor < len(value):
                item_length = value[cursor]
                cursor += 1
                alpns.append(value[cursor : cursor + item_length].decode("ascii"))
                cursor += item_length
    if not server_name:
        raise QuicParseError("ClientHello does not contain SNI")
    return server_name, tuple(alpns)


def inspect_sni(datagram: bytes) -> tuple[str, tuple[str, ...]]:
    return parse_client_hello(assemble_crypto(crypto_fragments(decrypt_initial(datagram))))


@dataclass(frozen=True, slots=True)
class Route:
    server_name: str
    target: str
    target_port: int
    alpn: str = "h3"
    idle_timeout_seconds: int = 1800


@dataclass(slots=True)
class Session:
    upstream: asyncio.DatagramTransport
    timeout: int
    client_scid: bytes
    last_seen: float = field(default_factory=time.monotonic)


class UpstreamProtocol(asyncio.DatagramProtocol):
    def __init__(self, listener: QuicRouter, client: tuple[Any, ...]) -> None:
        self.listener = listener
        self.client = client

    def datagram_received(self, data: bytes, _addr: tuple[Any, ...]) -> None:
        if self.listener.transport is not None:
            self.listener.transport.sendto(data, self.client)
        session = self.listener.sessions.get(self.client)
        if session is not None:
            session.last_seen = time.monotonic()


class QuicRouter(asyncio.DatagramProtocol):
    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path
        self.transport: asyncio.DatagramTransport | None = None
        self.sessions: dict[tuple[Any, ...], Session] = {}
        self.pending: dict[tuple[Any, ...], list[bytes]] = {}
        self.pending_crypto: dict[tuple[Any, ...], dict[int, bytes]] = {}
        self.pending_seen: dict[tuple[Any, ...], float] = {}
        self.opening: set[tuple[Any, ...]] = set()
        self.routes: dict[str, Route] = {}
        self._config_mtime = -1.0
        self._tasks: set[asyncio.Task[Any]] = set()

    def _spawn(self, coroutine: Any) -> None:
        task = asyncio.create_task(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        self.reload()
        self._spawn(self._reaper())

    def connection_lost(self, _exc: Exception | None) -> None:
        for task in self._tasks:
            task.cancel()
        for session in self.sessions.values():
            session.upstream.close()

    def reload(self) -> None:
        try:
            modified = self.config_path.stat().st_mtime
            if modified == self._config_mtime:
                return
            document = json.loads(self.config_path.read_text(encoding="utf-8"))
            routes: dict[str, Route] = {}
            for listener in document.get("listeners", []):
                for raw in listener.get("routes", []):
                    route = Route(**raw)
                    routes[route.server_name.casefold().rstrip(".")] = route
            self.routes = routes
            self._config_mtime = modified
            LOGGER.info("loaded %d QUIC passthrough routes", len(routes))
        except (OSError, ValueError, TypeError) as exc:
            LOGGER.warning("retaining previous QUIC routes: %s", exc)

    def datagram_received(self, data: bytes, addr: tuple[Any, ...]) -> None:
        self.reload()
        session = self.sessions.get(addr)
        if session is not None:
            try:
                _dcid, client_scid = initial_connection_ids(data)
                server_name, alpns = inspect_sni(data)
            except (QuicParseError, IndexError, UnicodeError):
                session.last_seen = time.monotonic()
                session.upstream.sendto(data)
                return
            if client_scid != session.client_scid:
                route = self.routes.get(server_name)
                if route is None or route.alpn not in alpns:
                    LOGGER.warning("dropping QUIC Initial for unconfigured SNI %s", server_name)
                    return
                session.upstream.close()
                self.sessions.pop(addr, None)
                self.pending[addr] = [data]
                self.pending_crypto.pop(addr, None)
                self.pending_seen[addr] = time.monotonic()
                self.opening.add(addr)
                self._spawn(self._open(addr, route, client_scid))
                return
            session.last_seen = time.monotonic()
            session.upstream.sendto(data)
            return
        if addr in self.opening:
            queue = self.pending.setdefault(addr, [])
            if len(queue) < 8:
                queue.append(data)
            return
        if addr not in self.pending and len(self.pending) >= 2048:
            LOGGER.warning("dropping QUIC Initial because the pending-session limit was reached")
            return
        queue = self.pending.setdefault(addr, [])
        self.pending_seen[addr] = time.monotonic()
        if len(queue) >= 8:
            self.pending.pop(addr, None)
            self.pending_crypto.pop(addr, None)
            self.pending_seen.pop(addr, None)
            return
        queue.append(data)
        try:
            fragments = crypto_fragments(decrypt_initial(data))
            pending_crypto = self.pending_crypto.setdefault(addr, {})
            pending_crypto.update(fragments)
            server_name, alpns = parse_client_hello(assemble_crypto(pending_crypto))
        except (QuicParseError, IndexError, UnicodeError):
            return
        self.pending_crypto.pop(addr, None)
        self.pending_seen.pop(addr, None)
        route = self.routes.get(server_name)
        if route is None or route.alpn not in alpns:
            LOGGER.warning("dropping QUIC Initial for unconfigured SNI %s", server_name)
            self.pending.pop(addr, None)
            return
        self.opening.add(addr)
        _dcid, client_scid = initial_connection_ids(data)
        self._spawn(self._open(addr, route, client_scid))

    async def _open(self, addr: tuple[Any, ...], route: Route, client_scid: bytes) -> None:
        try:
            if addr in self.sessions:
                return
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: UpstreamProtocol(self, addr), remote_addr=(route.target, route.target_port)
            )
            self.sessions[addr] = Session(
                upstream=transport,
                timeout=route.idle_timeout_seconds,  # type: ignore[arg-type]
                client_scid=client_scid,
            )
            self.pending_crypto.pop(addr, None)
            self.pending_seen.pop(addr, None)
            for datagram in self.pending.pop(addr, []):
                transport.sendto(datagram)  # type: ignore[attr-defined]
        except (OSError, ValueError) as exc:
            LOGGER.warning("unable to open QUIC upstream for %s: %s", route.server_name, exc)
            self.pending.pop(addr, None)
            self.pending_crypto.pop(addr, None)
            self.pending_seen.pop(addr, None)
        finally:
            self.opening.discard(addr)

    async def _reaper(self) -> None:
        while True:
            await asyncio.sleep(15)
            now = time.monotonic()
            for addr, last_seen in tuple(self.pending_seen.items()):
                if now - last_seen > 10:
                    self.pending.pop(addr, None)
                    self.pending_crypto.pop(addr, None)
                    self.pending_seen.pop(addr, None)
            for addr, session in tuple(self.sessions.items()):
                if now - session.last_seen > session.timeout:
                    session.upstream.close()
                    self.sessions.pop(addr, None)


async def serve(config_path: Path, host: str, port: int) -> None:
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(
        lambda: QuicRouter(config_path), local_addr=(host, port), family=socket.AF_INET
    )
    await asyncio.Future()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Portwyrm opaque QUIC/SNI router")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=443)
    args = parser.parse_args(argv)
    logging.basicConfig(level=os.getenv("PORTWYRM_LOG_LEVEL", "INFO"))
    asyncio.run(serve(args.config, args.host, args.port))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
