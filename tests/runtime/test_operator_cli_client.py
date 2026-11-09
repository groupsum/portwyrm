from __future__ import annotations

import io
import urllib.request

import pytest

from portwyrm.cli.client import request
from portwyrm.cli.parser import build_parser


@pytest.mark.parametrize(
    ("token_args", "env_token", "expected"),
    [
        (["--token", "cli-token"], "env-token", "Bearer cli-token"),
        ([], "env-token", "Bearer env-token"),
        ([], None, None),
    ],
)
def test_request_uses_cli_token_before_environment(
    monkeypatch: pytest.MonkeyPatch,
    token_args: list[str],
    env_token: str | None,
    expected: str | None,
) -> None:
    if env_token is None:
        monkeypatch.delenv("PORTWYRM_TOKEN", raising=False)
    else:
        monkeypatch.setenv("PORTWYRM_TOKEN", env_token)

    def fake_urlopen(outgoing: urllib.request.Request, *, timeout: float) -> io.BytesIO:
        assert outgoing.get_header("Authorization") == expected
        return io.BytesIO(b'{"ok": true}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    args = build_parser().parse_args(["schema", "--url", "http://example.test", *token_args])

    assert request(args, "GET", "/api/schema") == {"ok": True}
