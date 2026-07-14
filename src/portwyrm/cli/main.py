"""CLI orchestration and process exit behavior."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from portwyrm.cli.commands.remote import run_remote
from portwyrm.cli.commands.server import run_server
from portwyrm.cli.parser import build_parser


def run(args: argparse.Namespace) -> Any:
    if args.command in {None, "serve"}:
        run_server(args)
        return None
    return run_remote(args)


def main(argv: list[str] | None = None) -> None:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0].startswith("-"):
        arguments.insert(0, "serve")
    try:
        result = run(build_parser().parse_args(arguments))
        if result is not None:
            print(json.dumps(result, indent=2, sort_keys=True))
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"portwyrm: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
