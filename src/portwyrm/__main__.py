"""Portwyrm command-line client and server entry point."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import uvicorn


def _document(value: str | None) -> dict[str, Any]:
    if value is None:
        return {}
    path = Path(value)
    source = path.read_text(encoding="utf-8") if path.is_file() else value
    parsed = json.loads(source)
    if not isinstance(parsed, dict):
        raise ValueError("JSON document must be an object")
    return parsed


def _request(
    args: argparse.Namespace,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> Any:
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"Accept": "application/json"}
    token = getattr(args, "token", None) or os.getenv("PORTWYRM_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        f"{args.url.rstrip('/')}{path}", data=body, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:
            content = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"Portwyrm returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot reach Portwyrm at {args.url}: {exc.reason}") from exc
    return json.loads(content) if content else None


def _resource_path(collection: str, resource_id: str | None = None) -> str:
    prefix = "/api" if collection in {"users", "settings"} else "/api/nginx"
    path = f"{prefix}/{collection}"
    return f"{path}/{resource_id}" if resource_id is not None else path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="portwyrm", description="Portwyrm operator CLI")
    subparsers = parser.add_subparsers(dest="command")

    serve = subparsers.add_parser("serve", help="run the API and UIX server")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", default=81, type=int)
    serve.add_argument("--reload", action="store_true")

    def remote(name: str, help_text: str) -> argparse.ArgumentParser:
        command = subparsers.add_parser(name, help=help_text)
        command.add_argument("--url", default=os.getenv("PORTWYRM_URL", "http://127.0.0.1:81"))
        command.add_argument("--timeout", type=float, default=10)
        command.add_argument("--token")
        return command

    remote("status", "show API, setup, and readiness status")
    login = remote("login", "authenticate and print a bearer token")
    login.add_argument("--email", required=True)
    login.add_argument("--password", required=True)
    setup = remote("setup", "create the initial administrator")
    setup.add_argument("--email", required=True)
    setup.add_argument("--password", required=True)
    schema = remote("schema", "print the compatibility OpenAPI schema")
    del schema

    for name in ("list", "get", "create", "update", "delete"):
        command = remote(name, f"{name} a control-plane resource")
        command.add_argument("collection")
        if name in {"get", "update", "delete"}:
            command.add_argument("resource_id")
        if name in {"create", "update"}:
            command.add_argument("--data", required=True, help="JSON object or path to JSON file")
    return parser


def run(args: argparse.Namespace) -> Any:
    if args.command in {None, "serve"}:
        uvicorn.run(
            "portwyrm.api:create_app",
            factory=True,
            host=getattr(args, "host", "0.0.0.0"),
            port=getattr(args, "port", 81),
            reload=getattr(args, "reload", False),
        )
        return None
    if args.command == "status":
        return {
            "api": _request(args, "GET", "/api/"),
            "setup": _request(args, "GET", "/api/setup"),
            "readiness": _request(args, "GET", "/health/ready"),
        }
    if args.command == "login":
        return _request(
            args,
            "POST",
            "/api/tokens",
            {"identity": args.email, "secret": args.password, "scope": "user"},
        )
    if args.command == "setup":
        return _request(
            args, "POST", "/api/setup", {"email": args.email, "password": args.password}
        )
    if args.command == "schema":
        return _request(args, "GET", "/api/schema")
    path = _resource_path(args.collection, getattr(args, "resource_id", None))
    methods = {"list": "GET", "get": "GET", "create": "POST", "update": "PUT", "delete": "DELETE"}
    payload = (
        _document(getattr(args, "data", None)) if args.command in {"create", "update"} else None
    )
    return _request(args, methods[args.command], path, payload)


def main(argv: list[str] | None = None) -> None:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0].startswith("-"):
        arguments.insert(0, "serve")
    try:
        result = run(_parser().parse_args(arguments))
        if result is not None:
            print(json.dumps(result, indent=2, sort_keys=True))
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"portwyrm: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
