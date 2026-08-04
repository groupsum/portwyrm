from __future__ import annotations

import json
from pathlib import Path

import pytest

from portwyrm.api import create_app
from portwyrm.config import PortwyrmSettings
from portwyrm.runtime.nginx import NginxRenderer
from portwyrm.runtime.quic_router import (
    _initial_keys,
    assemble_crypto,
    parse_client_hello,
)
from portwyrm.tables.quic_passthrough import (
    QuicPassthroughRouteStore,
    canonical_server_name,
)
from tests.support import TestClient


def _client_hello(server_name: str, alpns: tuple[str, ...] = ("h3",)) -> bytes:
    name = server_name.encode("ascii")
    sni_name = b"\x00" + len(name).to_bytes(2, "big") + name
    sni_value = len(sni_name).to_bytes(2, "big") + sni_name
    sni = b"\x00\x00" + len(sni_value).to_bytes(2, "big") + sni_value
    protocols = b"".join(bytes([len(item)]) + item.encode("ascii") for item in alpns)
    alpn_value = len(protocols).to_bytes(2, "big") + protocols
    alpn = b"\x00\x10" + len(alpn_value).to_bytes(2, "big") + alpn_value
    extensions = sni + alpn
    body = (
        b"\x03\x03"
        + bytes(32)
        + b"\x00"
        + b"\x00\x02\x13\x01"
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    return b"\x01" + len(body).to_bytes(3, "big") + body


def test_quic_v1_initial_keys_match_rfc_9001() -> None:
    key, iv, header_protection = _initial_keys(1, bytes.fromhex("8394c8f03e515708"))

    assert key.hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert iv.hex() == "fa044b2f42a3fd3b46fb255c"
    assert header_protection.hex() == "9f50449e04a0e810283a1e9933adedd2"


def test_client_hello_parser_extracts_sni_and_h3_alpn() -> None:
    assert parse_client_hello(_client_hello("Present.Example.")) == (
        "present.example",
        ("h3",),
    )


def test_crypto_reassembly_accepts_fragmented_and_overlapping_client_hello() -> None:
    hello = _client_hello("present.example")

    assembled = assemble_crypto({17: hello[17:], 0: hello[:23]})

    assert assembled == hello
    assert parse_client_hello(assembled) == ("present.example", ("h3",))


def test_renderer_emits_deterministic_hostname_routes() -> None:
    first = QuicPassthroughRouteStore.RuntimeRoute(
        id=2,
        server_name="video.example",
        target="video-backend",
        target_port=4443,
    )
    second = QuicPassthroughRouteStore.RuntimeRoute(
        id=1,
        server_name="present.example",
        target="presentation-backend",
        target_port=4443,
    )

    document = json.loads(
        NginxRenderer().render(quic_passthrough_hosts=[first, second]).files["quic/routes.json"]
    )

    assert document == {
        "version": 1,
        "listeners": [
            {
                "listen_address": "0.0.0.0",
                "incoming_port": 443,
                "routes": [
                    {
                        "alpn": "h3",
                        "idle_timeout_seconds": 1800,
                        "server_name": "present.example",
                        "target": "presentation-backend",
                        "target_port": 4443,
                    },
                    {
                        "alpn": "h3",
                        "idle_timeout_seconds": 1800,
                        "server_name": "video.example",
                        "target": "video-backend",
                        "target_port": 4443,
                    },
                ],
            }
        ],
    }


@pytest.mark.parametrize("value", ["localhost", "https://video.example", "bad name"])
def test_quic_server_name_rejects_non_dns_hosts(value: str) -> None:
    with pytest.raises(ValueError):
        canonical_server_name(value)


def test_native_quic_capability_and_crud_contract(tmp_path: Path) -> None:
    settings = PortwyrmSettings(
        backend="sqlite",
        data_root=tmp_path,
        sqlite_path=tmp_path / "quic-api.sqlite",
    )
    client = TestClient(create_app(settings=settings))
    assert (
        client.post(
            "/api/setup",
            json={"email": "quic@example.test", "password": "a strong admin password"},
        ).status_code
        == 201
    )
    login = client.post(
        "/api/tokens",
        json={"identity": "quic@example.test", "secret": "a strong admin password"},
    )
    headers = {"Authorization": f"Bearer {login.json()['result']['token']}"}

    capability = client.get("/api/v2/capabilities").json()["quic_sni_passthrough"]
    assert capability["supported"] is True
    assert capability["tls_termination"] is False

    payload = {
        "listen_address": "0.0.0.0",
        "incoming_port": 443,
        "server_name": "present.example",
        "alpn": "h3",
        "target_kind": "docker",
        "target": "presentation-backend",
        "target_port": 4443,
        "idle_timeout_seconds": 1800,
        "enabled": True,
        "meta": {
            "managed_by": "wyrmctl",
            "owner": "presentation-demo",
            "resource_id": "quic.presentation",
        },
    }
    created = client.post("/api/v2/quic-passthrough-hosts", headers=headers, json=payload)
    assert created.status_code == 201, created.text
    resource_id = created.json()["id"]
    assert (
        client.get("/api/v2/quic-passthrough-hosts", headers=headers).json()[0]["id"] == resource_id
    )
    assert (
        client.get(f"/api/v2/quic-passthrough-hosts/{resource_id}", headers=headers).status_code
        == 200
    )

    updated = client.put(
        f"/api/v2/quic-passthrough-hosts/{resource_id}",
        headers=headers,
        json={**payload, "target": "presentation-backend-v2"},
    )
    assert updated.json()["target"] == "presentation-backend-v2"
    assert client.delete(
        f"/api/v2/quic-passthrough-hosts/{resource_id}", headers=headers
    ).json() == {"deleted": True}
    assert client.get("/api/v2/quic-passthrough-hosts", headers=headers).json() == []
