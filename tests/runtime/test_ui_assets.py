from __future__ import annotations

import re
from pathlib import Path

from tigrbl import TigrblApp
from tigrbl.factories.engine import mem

from portwyrm.api import create_app
from portwyrm.config import PortwyrmSettings
from portwyrm.uix import mount_uix
from tests.support import TestClient


def test_compiled_console_is_packaged_and_accessible() -> None:
    app = TigrblApp(mount_system=False)
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

    for favicon_path in (
        "/ui/favicon.ico",
        "/ui/favicon-16x16.png",
        "/ui/favicon-32x32.png",
        "/ui/apple-touch-icon.png",
    ):
        assert f'href="{favicon_path}"' in page.text
        favicon = client.get(favicon_path)
        assert favicon.status_code == 200
        assert favicon.headers["content-type"].startswith("image/")

    script = client.get(script_match.group(1))
    stylesheet = client.get(style_match.group(1))
    assert script.status_code == 200
    assert script.headers["content-type"].startswith("text/javascript")
    assert stylesheet.status_code == 200
    assert stylesheet.headers["content-type"].startswith("text/css")
    assert "/api/v2/browser/login" in script.text
    assert "/api/v2/browser/password" in script.text
    assert "Change the temporary password" in script.text
    assert "Password changed. Sign in with your new password." in script.text
    assert script.text.count("/api/setup") >= 2
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
    assert "access-tokens" in script.text
    assert "Copy this token now" in script.text
    assert "Portwyrm stores only its secure hash" in script.text
    token_source = (
        Path(__file__).parents[2] / "frontend" / "src" / "components" / "AccessTokensModal.tsx"
    ).read_text(encoding="utf-8")
    assert "setSecret(null)" in token_source
    assert 'role="dialog"' not in token_source
    assert '<table className="w-full min-w-[760px]' in token_source
    assert '>Manage</th>' in token_source
    assert "Production npmctl" not in token_source
    assert "Create scoped credentials for npmctl" not in token_source
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
        assert ">Actions</th>" not in source

    hosts_source = (components / "HostsView.tsx").read_text(encoding="utf-8")
    for label in ("Owner", "Source", "Target", "Cert", "Access", "Status", "Updated at"):
        assert label in hosts_source

    audit_source = (components / "AuditView.tsx").read_text(encoding="utf-8")
    assert ">Summary</th>" not in audit_source
    assert audit_source.index(">Resource</th>") < audit_source.index(">Action</th>")
    assert "colSpan={6}" in audit_source


def test_host_provenance_distinguishes_automation_humans_and_system_resources() -> None:
    root = Path(__file__).parents[2] / "frontend" / "src"
    provenance = (root / "utils" / "provenance.ts").read_text(encoding="utf-8")
    store = (root / "store" / "index.ts").read_text(encoding="utf-8")
    hosts = (root / "components" / "HostsView.tsx").read_text(encoding="utf-8")
    audit_source = (root / "components" / "AuditView.tsx").read_text(encoding="utf-8")

    assert "row.meta?.managed_by === 'npmctl'" not in store
    assert "if (managedBy) return {kind: 'automation', managedBy}" in provenance
    assert "if (ownerId) return {kind: 'human', managedBy: null}" in provenance
    assert "return {kind: 'unassigned', managedBy: null}" in provenance
    assert "provenanceKind: provenance.kind" in store
    assert "provenanceCaption(" in hosts
    assert "row.actor_name" in store
    assert "`@${String(rawActor).replace(/^@/, '')}`" in store
    assert ".sort((left: AuditLog, right: AuditLog)" in store
    assert "actor || 'System'" in store
    assert "'Unattributed'" not in store
    assert "Executed by {selectedLog.executor}" in audit_source


def test_root_redirects_to_console() -> None:
    app = TigrblApp(mount_system=False)
    mount_uix(app)
    response = TestClient(app).get("/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "/ui/"


def test_composed_initialized_application_serves_console() -> None:
    app = create_app(settings=PortwyrmSettings(backend="memory"), engine=mem(async_=False))
    response = TestClient(app).get("/ui/")
    assert response.status_code == 200
    assert '<div id="root"></div>' in response.text
