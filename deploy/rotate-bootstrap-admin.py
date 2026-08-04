"""Rotate Portwyrm's one-time bootstrap password into a local automation credential."""

from __future__ import annotations

import json
import os
import secrets
import stat
import urllib.request
from pathlib import Path

BOOTSTRAP = Path("/data/bootstrap-admin.json")
AUTOMATION = Path("/data/deployment-admin.json")
BASE_URL = "http://127.0.0.1:81"


def _json_request(
    path: str,
    payload: dict[str, str],
    *,
    bearer: str | None = None,
) -> tuple[int, dict[str, object]]:
    headers = {"Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    request = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        body = response.read()
        return response.status, json.loads(body) if body else {}


def main() -> int:
    if AUTOMATION.exists():
        return 0
    bootstrap = json.loads(BOOTSTRAP.read_text(encoding="utf-8"))
    email = str(bootstrap["email"])
    current_password = str(bootstrap["password"])
    new_password = secrets.token_urlsafe(36)
    status, login = _json_request(
        "/api/tokens",
        {"identity": email, "secret": current_password, "scope": "user"},
    )
    if status != 200:
        raise RuntimeError(f"bootstrap login failed with HTTP {status}")
    result = login.get("result")
    bearer = result.get("token") if isinstance(result, dict) else None
    if not isinstance(bearer, str) or not bearer:
        raise RuntimeError("bootstrap login did not issue a bearer token")
    status, _ = _json_request(
        "/api/v2/browser/password",
        {"current_password": current_password, "new_password": new_password},
        bearer=bearer,
    )
    if status != 204:
        raise RuntimeError(f"bootstrap password rotation failed with HTTP {status}")
    temporary = AUTOMATION.with_suffix(".tmp")
    temporary.write_text(
        json.dumps({"email": email, "password": new_password}) + "\n", encoding="utf-8"
    )
    os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
    temporary.replace(AUTOMATION)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
