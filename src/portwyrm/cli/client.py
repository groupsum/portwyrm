"""Small standard-library HTTP client used by the operator CLI."""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def document(value: str | None) -> dict[str, Any]:
    """Load a JSON object from an inline value or a filesystem path."""

    if value is None:
        return {}
    path = Path(value)
    source = path.read_text(encoding="utf-8") if path.is_file() else value
    parsed = json.loads(source)
    if not isinstance(parsed, dict):
        raise ValueError("JSON document must be an object")
    return parsed


def request(
    args: argparse.Namespace,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> Any:
    """Send one authenticated request and decode its JSON response."""

    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"Accept": "application/json"}
    token = getattr(args, "token", None) or os.getenv("PORTWYRM_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    outgoing = urllib.request.Request(
        f"{args.url.rstrip('/')}{path}", data=body, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(outgoing, timeout=args.timeout) as response:
            content = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"Portwyrm returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot reach Portwyrm at {args.url}: {exc.reason}") from exc
    return json.loads(content) if content else None


def resource_path(collection: str, resource_id: str | None = None) -> str:
    """Return the NPM-compatible route for a resource collection."""

    prefix = "/api" if collection in {"users", "settings"} else "/api/nginx"
    path = f"{prefix}/{collection}"
    return f"{path}/{resource_id}" if resource_id is not None else path
