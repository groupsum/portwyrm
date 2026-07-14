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
        return request(args, "POST", "/api/setup", {"email": args.email, "password": args.password})
    if args.command == "schema":
        return request(args, "GET", "/api/schema")
    if args.command == "export":
        return request(args, "GET", "/api/v2/export")
    if args.command == "import":
        endpoint = "/api/v2/import" if args.apply else "/api/v2/import/preview"
        suffix = "?replace=true" if args.replace else ""
        return request(args, "POST", endpoint + suffix, document(args.data))
    if args.command in {"npm-preflight", "npm-import"}:
        endpoint = (
            "/api/v2/migration/npm/preflight"
            if args.command == "npm-preflight"
            else "/api/v2/migration/npm/import"
        )
        query = []
        if args.command == "npm-import":
            query.extend(
                [
                    f"dry_run={'false' if args.apply else 'true'}",
                    f"replace={str(args.replace).lower()}",
                ]
            )
        suffix = f"?{'&'.join(query)}" if query else ""
        return request(args, "POST", endpoint + suffix, {"source": document(args.data)})
    path = resource_path(args.collection, getattr(args, "resource_id", None))
    methods = {"list": "GET", "get": "GET", "create": "POST", "update": "PUT", "delete": "DELETE"}
    payload = (
        document(getattr(args, "data", None)) if args.command in {"create", "update"} else None
    )
    return request(args, methods[args.command], path, payload)
