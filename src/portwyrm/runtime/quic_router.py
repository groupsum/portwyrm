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
_DEFAULT_RECEIVE_BUFFER_BYTES = 8 * 1024 * 1024
_MIN_RECEIVE_BUFFER_BYTES = 64 * 1024
_MAX_RECEIVE_BUFFER_BYTES = 128 * 1024 * 1024
_CONFIG_RELOAD_INTERVAL_SECONDS = 1.0
_FIRST_UPSTREAM_PAUSE_TIMEOUT_SECONDS = 0.25


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
    client: tuple[Any, ...]
    client_scid: bytes
    server_cids: set[bytes] = field(default_factory=set)
    last_seen: float = field(default_factory=time.monotonic)
    opened_at: float = field(default_factory=time.monotonic)
    upstream_datagrams_received: int = 0


class UpstreamProtocol(asyncio.DatagramProtocol):
    def __init__(
        self,
        listener: QuicRouter,
        session_key: tuple[tuple[Any, ...], bytes],
    ) -> None:
        self.listener = listener
        self.session_key = session_key

    def datagram_received(self, data: bytes, _addr: tuple[Any, ...]) -> None:
        session = self.listener.sessions.get(self.session_key)
        if session is None:
            return
        session.upstream_datagrams_received += 1
        if session.upstream_datagrams_received == 1:
            LOGGER.info(
                "first upstream QUIC datagram client=%s:%s odcid=%s response_ms=%.1f bytes=%d",
                session.client[0],
                session.client[1],
                self.session_key[1].hex(),
                (time.monotonic() - session.opened_at) * 1000,
                len(data),
            )
        self.listener._register_server_connection_id(self.session_key, data)
        if self.listener.transport is not None:
            self.listener.transport.sendto(data, session.client)
        if session.upstream_datagrams_received == 1:
            self.listener._release_ingress_pause(self.session_key, reason="response")
        session.last_seen = time.monotonic()

    def error_received(self, exc: Exception) -> None:
        LOGGER.warning("QUIC upstream socket error session=%r: %s", self.session_key, exc)


class QuicRouter(asyncio.DatagramProtocol):
    def __init__(self, config_path: Path) -> None:
        self.config_path = config_path
        self.transport: asyncio.DatagramTransport | None = None
        self.sessions: dict[tuple[tuple[Any, ...], bytes], Session] = {}
        self.sessions_by_addr: dict[tuple[Any, ...], set[tuple[tuple[Any, ...], bytes]]] = {}
        self.sessions_by_server_cid: dict[bytes, tuple[tuple[Any, ...], bytes]] = {}
        self._server_cid_length_counts: dict[int, int] = {}
        self._server_cid_lengths: tuple[int, ...] = ()
        self.pending: dict[tuple[tuple[Any, ...], bytes], list[bytes]] = {}
        self.pending_crypto: dict[tuple[tuple[Any, ...], bytes], dict[int, bytes]] = {}
        self.pending_seen: dict[tuple[tuple[Any, ...], bytes], float] = {}
        self.pending_started: dict[tuple[tuple[Any, ...], bytes], float] = {}
        self.opening: set[tuple[tuple[Any, ...], bytes]] = set()
        self.routes: dict[str, Route] = {}
        self._config_mtime = -1.0
        self._tasks: set[asyncio.Task[Any]] = set()
        self._awaiting_first_upstream: set[tuple[tuple[Any, ...], bytes]] = set()
        self._ingress_pause_timers: dict[tuple[tuple[Any, ...], bytes], asyncio.TimerHandle] = {}

    def _spawn(self, coroutine: Any) -> None:
        task = asyncio.create_task(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        self.reload()
        self._spawn(self._config_reloader())
        self._spawn(self._reaper())

    def connection_lost(self, _exc: Exception | None) -> None:
        for task in self._tasks:
            task.cancel()
        for timer in self._ingress_pause_timers.values():
            timer.cancel()
        self._ingress_pause_timers.clear()
        self._awaiting_first_upstream.clear()
        for session in self.sessions.values():
            session.upstream.close()

    def error_received(self, exc: Exception) -> None:
        LOGGER.warning("QUIC listener socket error: %s", exc)

    @staticmethod
    def _session_key(addr: tuple[Any, ...], initial_dcid: bytes) -> tuple[tuple[Any, ...], bytes]:
        """Identify an opening connection by its client-chosen destination CID.

        Chromium commonly sends an empty source CID. The original destination
        CID is still client-selected and unique, so it can distinguish multiple
        connections sharing one UDP address until server-issued CIDs are known.
        """
        return addr, initial_dcid

    def _add_session(
        self,
        key: tuple[tuple[Any, ...], bytes],
        session: Session,
    ) -> None:
        self.sessions[key] = session
        self.sessions_by_addr.setdefault(session.client, set()).add(key)
        for server_cid in tuple(session.server_cids):
            self._index_server_connection_id(key, server_cid)

    def _remove_session(
        self,
        key: tuple[tuple[Any, ...], bytes],
        *,
        close: bool = True,
    ) -> Session | None:
        session = self.sessions.pop(key, None)
        if session is None:
            return None
        self._release_ingress_pause(key, reason="session-removed")
        keys = self.sessions_by_addr.get(session.client)
        if keys is not None:
            keys.discard(key)
            if not keys:
                self.sessions_by_addr.pop(session.client, None)
        for server_cid in tuple(session.server_cids):
            if self.sessions_by_server_cid.get(server_cid) == key:
                self.sessions_by_server_cid.pop(server_cid, None)
                self._remove_server_cid_length(len(server_cid))
        if close:
            session.upstream.close()
        return session

    def _pause_ingress_for_first_upstream(
        self,
        key: tuple[tuple[Any, ...], bytes],
    ) -> None:
        if key in self._awaiting_first_upstream:
            return
        self._awaiting_first_upstream.add(key)
        if len(self._awaiting_first_upstream) == 1 and self.transport is not None:
            self.transport.pause_reading()
        self._ingress_pause_timers[key] = asyncio.get_running_loop().call_later(
            _FIRST_UPSTREAM_PAUSE_TIMEOUT_SECONDS,
            self._release_ingress_pause,
            key,
            "timeout",
        )
        LOGGER.info(
            "paused public QUIC ingress awaiting first upstream response odcid=%s",
            key[1].hex(),
        )

    def _release_ingress_pause(
        self,
        key: tuple[tuple[Any, ...], bytes],
        reason: str,
    ) -> None:
        if key not in self._awaiting_first_upstream:
            return
        self._awaiting_first_upstream.discard(key)
        timer = self._ingress_pause_timers.pop(key, None)
        if timer is not None:
            timer.cancel()
        if not self._awaiting_first_upstream and self.transport is not None:
            self.transport.resume_reading()
        LOGGER.info(
            "resumed public QUIC ingress after first upstream wait odcid=%s reason=%s",
            key[1].hex(),
            reason,
        )

    def _register_server_connection_id(
        self,
        key: tuple[tuple[Any, ...], bytes],
        datagram: bytes,
    ) -> None:
        if not datagram or not datagram[0] & 0x80:
            return
        try:
            _dcid, server_scid = initial_connection_ids(datagram)
        except QuicParseError:
            return
        if not server_scid:
            return
        session = self.sessions.get(key)
        if session is None:
            return
        self._index_server_connection_id(key, server_scid)

    def _index_server_connection_id(
        self,
        key: tuple[tuple[Any, ...], bytes],
        server_scid: bytes,
    ) -> None:
        session = self.sessions.get(key)
        if session is None:
            return
        owner = self.sessions_by_server_cid.get(server_scid)
        if owner is not None and owner != key:
            LOGGER.warning(
                "ignoring duplicate upstream QUIC connection id %s",
                server_scid.hex(),
            )
            return
        if owner == key:
            return
        session.server_cids.add(server_scid)
        self.sessions_by_server_cid[server_scid] = key
        length = len(server_scid)
        self._server_cid_length_counts[length] = self._server_cid_length_counts.get(length, 0) + 1
        self._server_cid_lengths = tuple(sorted(self._server_cid_length_counts, reverse=True))

    def _remove_server_cid_length(self, length: int) -> None:
        count = self._server_cid_length_counts.get(length, 0)
        if count <= 1:
            self._server_cid_length_counts.pop(length, None)
        else:
            self._server_cid_length_counts[length] = count - 1
        self._server_cid_lengths = tuple(sorted(self._server_cid_length_counts, reverse=True))

    def _session_for_datagram(
        self,
        data: bytes,
        addr: tuple[Any, ...],
    ) -> tuple[tuple[Any, ...], bytes] | None:
        if not data:
            return None
        if data[0] & 0x80:
            try:
                dcid, _client_scid = initial_connection_ids(data)
            except QuicParseError:
                return None
            key = self.sessions_by_server_cid.get(dcid)
            if key is not None:
                session = self.sessions.get(key)
                if session is not None and session.client == addr:
                    return key
            key = self._session_key(addr, dcid)
            if key in self.sessions:
                return key
            return None

        keys = self.sessions_by_addr.get(addr, set())
        for length in self._server_cid_lengths:
            key = self.sessions_by_server_cid.get(data[1 : 1 + length])
            if key is not None and key in keys:
                return key

        if len(keys) == 1:
            return next(iter(keys))
        return None

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
        session_key = self._session_for_datagram(data, addr)
        if session_key is not None:
            session = self.sessions.get(session_key)
            if session is None:
                return
            session.last_seen = time.monotonic()
            session.upstream.sendto(data)
            return

        if not data or not data[0] & 0x80:
            if len(self.sessions_by_addr.get(addr, set())) > 1:
                LOGGER.warning(
                    "dropping ambiguous QUIC short-header packet from %s:%s",
                    addr[0],
                    addr[1],
                )
            return
        try:
            initial_dcid, client_scid = initial_connection_ids(data)
        except QuicParseError:
            return
        session_key = self._session_key(addr, initial_dcid)

        if session_key in self.opening:
            queue = self.pending.setdefault(session_key, [])
            if len(queue) < 8:
                queue.append(data)
            return
        if session_key not in self.pending and len(self.pending) >= 2048:
            LOGGER.warning("dropping QUIC Initial because the pending-session limit was reached")
            return
        queue = self.pending.setdefault(session_key, [])
        self.pending_started.setdefault(session_key, time.monotonic())
        self.pending_seen[session_key] = time.monotonic()
        if len(queue) >= 8:
            self.pending.pop(session_key, None)
            self.pending_crypto.pop(session_key, None)
            self.pending_seen.pop(session_key, None)
            self.pending_started.pop(session_key, None)
            return
        queue.append(data)
        try:
            fragments = crypto_fragments(decrypt_initial(data))
            pending_crypto = self.pending_crypto.setdefault(session_key, {})
            pending_crypto.update(fragments)
            server_name, alpns = parse_client_hello(assemble_crypto(pending_crypto))
        except (QuicParseError, IndexError, UnicodeError):
            return
        self.pending_crypto.pop(session_key, None)
        self.pending_seen.pop(session_key, None)
        route = self.routes.get(server_name)
        if route is None or route.alpn not in alpns:
            LOGGER.warning("dropping QUIC Initial for unconfigured SNI %s", server_name)
            self.pending.pop(session_key, None)
            self.pending_started.pop(session_key, None)
            return
        self.opening.add(session_key)
        self._spawn(self._open(session_key, addr, route, client_scid, initial_dcid))

    async def _open(
        self,
        session_key: tuple[tuple[Any, ...], bytes],
        addr: tuple[Any, ...],
        route: Route,
        client_scid: bytes,
        initial_dcid: bytes,
    ) -> None:
        started_at = self.pending_started.get(session_key, time.monotonic())
        socket_started_at = time.monotonic()
        try:
            if session_key in self.sessions:
                return
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: UpstreamProtocol(self, session_key),
                remote_addr=(route.target, route.target_port),
            )
            opened_at = time.monotonic()
            self._add_session(
                session_key,
                Session(
                    upstream=transport,
                    timeout=route.idle_timeout_seconds,  # type: ignore[arg-type]
                    client=addr,
                    client_scid=client_scid,
                    opened_at=opened_at,
                ),
            )
            queued_datagrams = len(self.pending.get(session_key, []))
            LOGGER.info(
                "opened QUIC route client=%s:%s scid=%s odcid=%s "
                "target=%s:%s concurrent=%d route_ms=%.1f socket_ms=%.1f queued=%d",
                addr[0],
                addr[1],
                client_scid.hex(),
                initial_dcid.hex(),
                route.target,
                route.target_port,
                len(self.sessions_by_addr.get(addr, set())),
                (opened_at - started_at) * 1000,
                (opened_at - socket_started_at) * 1000,
                queued_datagrams,
            )
            self.pending_crypto.pop(session_key, None)
            self.pending_seen.pop(session_key, None)
            self.pending_started.pop(session_key, None)
            self._pause_ingress_for_first_upstream(session_key)
            for datagram in self.pending.pop(session_key, []):
                transport.sendto(datagram)  # type: ignore[attr-defined]
        except (OSError, ValueError) as exc:
            LOGGER.warning("unable to open QUIC upstream for %s: %s", route.server_name, exc)
            self.pending.pop(session_key, None)
            self.pending_crypto.pop(session_key, None)
            self.pending_seen.pop(session_key, None)
            self.pending_started.pop(session_key, None)
            self._release_ingress_pause(session_key, reason="open-failed")
        finally:
            self.opening.discard(session_key)

    async def _reaper(self) -> None:
        while True:
            await asyncio.sleep(15)
            now = time.monotonic()
            for session_key, last_seen in tuple(self.pending_seen.items()):
                if now - last_seen > 10:
                    self.pending.pop(session_key, None)
                    self.pending_crypto.pop(session_key, None)
                    self.pending_seen.pop(session_key, None)
                    self.pending_started.pop(session_key, None)
            for session_key, session in tuple(self.sessions.items()):
                if now - session.last_seen > session.timeout:
                    self._remove_session(session_key)

    async def _config_reloader(self) -> None:
        while True:
            await asyncio.sleep(_CONFIG_RELOAD_INTERVAL_SECONDS)
            self.reload()


def listener_receive_buffer_bytes() -> int:
    raw = os.getenv("PORTWYRM_QUIC_RCVBUF_BYTES", str(_DEFAULT_RECEIVE_BUFFER_BYTES))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("PORTWYRM_QUIC_RCVBUF_BYTES must be an integer") from exc
    if not _MIN_RECEIVE_BUFFER_BYTES <= value <= _MAX_RECEIVE_BUFFER_BYTES:
        raise ValueError(
            "PORTWYRM_QUIC_RCVBUF_BYTES must be between "
            f"{_MIN_RECEIVE_BUFFER_BYTES} and {_MAX_RECEIVE_BUFFER_BYTES}"
        )
    return value


def create_listener_socket(
    host: str,
    port: int,
    receive_buffer_bytes: int,
    *,
    reuse_port: bool = False,
) -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if reuse_port:
            if not hasattr(socket, "SO_REUSEPORT"):
                raise RuntimeError("SO_REUSEPORT is unavailable on this platform")
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, receive_buffer_bytes)
        listener.bind((host, port))
        listener.setblocking(False)
    except Exception:
        listener.close()
        raise
    effective = listener.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    log = LOGGER.info if effective >= receive_buffer_bytes else LOGGER.warning
    log(
        "QUIC listener receive buffer requested=%d effective=%d host=%s port=%d",
        receive_buffer_bytes,
        effective,
        host,
        listener.getsockname()[1],
    )
    return listener


async def serve(config_path: Path, host: str, port: int, *, reuse_port: bool = False) -> None:
    loop = asyncio.get_running_loop()
    listener = create_listener_socket(
        host,
        port,
        listener_receive_buffer_bytes(),
        reuse_port=reuse_port,
    )
    try:
        await loop.create_datagram_endpoint(lambda: QuicRouter(config_path), sock=listener)
    except Exception:
        listener.close()
        raise
    await asyncio.Future()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Portwyrm opaque QUIC/SNI router")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--reuse-port", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=os.getenv("PORTWYRM_LOG_LEVEL", "INFO"))
    asyncio.run(serve(args.config, args.host, args.port, reuse_port=args.reuse_port))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
