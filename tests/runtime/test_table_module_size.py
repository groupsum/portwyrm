"""Maintain focused table modules with a hard source-line ceiling."""

from pathlib import Path


def test_identity_credential_and_session_modules_stay_below_400_lines() -> None:
    tables = Path(__file__).parents[2] / "src" / "portwyrm" / "tables"
    modules = ("identities.py", "credentials.py", "sessions.py", "principals.py")
    oversized = {
        module: len((tables / module).read_text(encoding="utf-8").splitlines())
        for module in modules
        if len((tables / module).read_text(encoding="utf-8").splitlines()) > 400
    }
    assert oversized == {}
