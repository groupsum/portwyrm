"""Argument parser construction for the Portwyrm CLI."""

from __future__ import annotations

import argparse
import os


def build_parser() -> argparse.ArgumentParser:
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
    remote("schema", "print the compatibility OpenAPI schema")

    for name in ("list", "get", "create", "update", "delete"):
        command = remote(name, f"{name} a control-plane resource")
        command.add_argument("collection")
        if name in {"get", "update", "delete"}:
            command.add_argument("resource_id")
        if name in {"create", "update"}:
            command.add_argument("--data", required=True, help="JSON object or path to JSON file")
    return parser
