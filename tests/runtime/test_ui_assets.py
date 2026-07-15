from __future__ import annotations

import re
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from portwyrm.uix import mount_uix


def test_compiled_console_is_packaged_and_accessible() -> None:
    app = FastAPI()
    mount_uix(app)
    client = TestClient(app)
    page = client.get("/ui/")
    assert page.status_code == 200
    assert '<html lang="en">' in page.text
    assert '<div id="root"></div>' in page.text
    script_match = re.search(r'src="(/ui/assets/[^"]+\.js)"', page.text)
    style_match = re.search(r'href="(/ui/assets/[^"]+\.css)"', page.text)
    assert script_match is not None
    assert style_match is not None

    script = client.get(script_match.group(1))
    stylesheet = client.get(style_match.group(1))
    assert script.status_code == 200
    assert script.headers["content-type"].startswith("text/javascript")
    assert stylesheet.status_code == 200
    assert stylesheet.headers["content-type"].startswith("text/css")
    assert "/api/v2/browser/login" in script.text
    assert "/api/nginx/" in script.text and "proxy-hosts" in script.text
    assert "Discard unsaved changes?" in script.text
    assert "Password: write-only" in script.text
    assert "Preview configuration to apply" in script.text
    assert "Compare any two applied versions" in script.text
    assert "IP address, DNS name, or Docker service/container" in script.text
    assert "side-by-side-code-diff" in script.text
    assert "Updated at" in script.text
    assert "/api/v2/system/status" in script.text
    assert "/api/v2/tokens" in script.text
    assert "Create access token" in script.text
    assert "Copy this token now" in script.text
    assert "Portwyrm stores only its secure hash" in script.text
    token_source = (
        Path(__file__).parents[2] / "frontend" / "src" / "components" / "AccessTokensModal.tsx"
    ).read_text(encoding="utf-8")
    assert "setSecret(null)" in token_source
    assert "Access token management is not available" not in script.text
    assert "Config:" in script.text
    assert "Applied Gen:" not in script.text
    assert "scrollbar-color" in stylesheet.text
    assert "GEMINI_API_KEY" not in script.text
    assert client.get("/ui/app.js").status_code == 404


def test_data_tables_do_not_reserve_an_actions_header() -> None:
    components = Path(__file__).parents[2] / "frontend" / "src" / "components"
    for filename in ("HostsView.tsx", "UsersView.tsx", "CertificatesView.tsx"):
        source = (components / filename).read_text(encoding="utf-8")
        assert '>Actions</th>' not in source

    hosts_source = (components / "HostsView.tsx").read_text(encoding="utf-8")
    for label in ("Owner", "Source", "Target", "Cert", "Access", "Status", "Updated at"):
        assert label in hosts_source


def test_root_redirects_to_console() -> None:
    app = FastAPI()
    mount_uix(app)
    response = TestClient(app).get("/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "/ui/"
