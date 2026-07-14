"""Local server command."""

from __future__ import annotations

import argparse

import uvicorn


def run_server(args: argparse.Namespace) -> None:
    uvicorn.run(
        "portwyrm.api:create_app",
        factory=True,
        host=getattr(args, "host", "0.0.0.0"),
        port=getattr(args, "port", 81),
        reload=getattr(args, "reload", False),
    )
