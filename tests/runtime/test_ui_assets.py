from __future__ import annotations

import re

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
    assert "scrollbar-color" in stylesheet.text
    assert "GEMINI_API_KEY" not in script.text
    assert client.get("/ui/app.js").status_code == 404


def test_root_redirects_to_console() -> None:
    app = FastAPI()
    mount_uix(app)
    response = TestClient(app).get("/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "/ui/"
