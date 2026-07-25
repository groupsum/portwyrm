# Secure unmatched-host default evidence

Date: 2026-07-25

## Contract

- Requests whose Host header does not match an active proxy, redirect, or dead host receive Nginx status 444 by default.
- The default listener closes the connection without an HTTP response and does not disclose that Portwyrm is running.
- The optional congratulations mode remains available and explicitly declares text/plain instead of inheriting application/octet-stream.
- Configured routing hosts continue to render their dedicated server blocks independently of the unmatched-host default.

## Verification

- uv run ruff check .: passed.
- uv run pytest tests/runtime/test_nginx_runtime.py -q --basetemp=.tmp/pytest-default-site: 11 passed.
- uv run pytest --basetemp=.tmp/pytest-default-site-full: 225 passed, 3 opt-in integration tests skipped.
- Regression coverage asserts that the default configuration contains return 444, contains no congratulations body, and that an explicitly selected congratulations mode includes default_type text/plain.

The skipped tests require PostgreSQL or real-container opt-in environment flags and are unchanged by this renderer-default repair.
