"""Remote control-plane commands."""

from __future__ import annotations

import argparse
from typing import Any

from portwyrm.cli.client import document, request, resource_path


def run_remote(args: argparse.Namespace) -> Any:
    if args.command == "status":
        return {
            "api": request(args, "GET", "/api/"),
            "setup": request(args, "GET", "/api/setup"),
            "readiness": request(args, "GET", "/health/ready"),
        }
    if args.command == "login":
        return request(
            args,
            "POST",
            "/api/tokens",
            {"identity": args.email, "secret": args.password, "scope": "user"},
        )
    if args.command == "setup":
        return request(
            args, "POST", "/api/setup", {"email": args.email, "password": args.password}
        )
    if args.command == "schema":
        return request(args, "GET", "/api/schema")
    path = resource_path(args.collection, getattr(args, "resource_id", None))
    methods = {"list": "GET", "get": "GET", "create": "POST", "update": "PUT", "delete": "DELETE"}
    payload = (
        document(getattr(args, "data", None))
        if args.command in {"create", "update"}
        else None
    )
    return request(args, methods[args.command], path, payload)
