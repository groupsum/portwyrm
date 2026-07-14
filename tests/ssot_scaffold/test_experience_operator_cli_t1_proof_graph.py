from pathlib import Path

from fastapi.testclient import TestClient

from portwyrm.api import create_app
from portwyrm.persistence import SQLiteRepository


def test_operator_cli_control_plane_is_persistent_and_reachable(tmp_path: Path) -> None:
    database = tmp_path / "operator-cli.sqlite"
    client = TestClient(create_app(SQLiteRepository(database)))
    assert (
        client.post(
            "/api/setup",
            json={"email": "cli@example.test", "password": "correct-password"},
        ).status_code
        == 201
    )
    login = client.post(
        "/api/tokens",
        json={"identity": "cli@example.test", "secret": "correct-password", "scope": "user"},
    )
    assert login.status_code == 200

    restarted = TestClient(create_app(SQLiteRepository(database)))
    assert restarted.get("/health/ready").status_code == 200
    assert restarted.get("/api/").json()["status"] == "OK"
