from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _run(database: Path, expression: str) -> subprocess.CompletedProcess[str]:
    program = f"""
from pathlib import Path
from portwyrm.api import create_app
from portwyrm.config import PortwyrmSettings
from tests.support import TestClient
settings = PortwyrmSettings(backend='sqlite', sqlite_path=Path({str(database)!r}))
client = TestClient(create_app(settings=settings))
response = {expression}
print(response.status_code)
"""
    return subprocess.run(
        [sys.executable, "-c", program],
        check=False,
        capture_output=True,
        text=True,
    )


def test_operator_cli_control_plane_is_persistent_and_reachable(tmp_path: Path) -> None:
    database = tmp_path / "operator-cli.sqlite"
    setup = _run(
        database,
        "client.post('/api/setup', "
        "json={'email':'cli@example.test','password':'correct-password'})",
    )
    assert setup.returncode == 0 and setup.stdout.strip() == "201", setup.stderr
    login = _run(
        database,
        "client.post('/api/tokens', "
        "json={'identity':'cli@example.test','secret':'correct-password'})",
    )
    assert login.returncode == 0 and login.stdout.strip() == "200", login.stderr
