from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from portwyrm.uix import mount_uix


def test_no_build_console_is_packaged_and_accessible() -> None:
    app = FastAPI()
    mount_uix(app)
    client = TestClient(app)
    page = client.get("/ui/")
    assert page.status_code == 200
    assert "Skip to content" in page.text
    assert "System Health" in page.text
    assert 'aria-live="polite"' in page.text
    assert client.get("/ui/app.js").status_code == 200
    stylesheet = client.get("/ui/styles.css")
    assert stylesheet.status_code == 200
    assert "[hidden]{display:none!important}" in stylesheet.text


def test_root_redirects_to_console() -> None:
    app = FastAPI()
    mount_uix(app)
    response = TestClient(app).get("/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "/ui/"
