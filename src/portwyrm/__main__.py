"""Compatibility entrypoint for ``python -m portwyrm`` and the console script."""

from portwyrm.cli.client import document as _document
from portwyrm.cli.client import request as _request
from portwyrm.cli.client import resource_path as _resource_path
from portwyrm.cli.main import main, run
from portwyrm.cli.parser import build_parser as _parser

__all__ = ["_document", "_parser", "_request", "_resource_path", "main", "run"]


if __name__ == "__main__":
    main()
