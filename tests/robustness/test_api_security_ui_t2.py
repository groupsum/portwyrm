"""Adversarial API policy and compiled-UI assurance coverage."""

import asyncio
from pathlib import Path

import pytest
from tigrbl import HTTPException

from portwyrm.api import create_app
from portwyrm.config import PortwyrmSettings


def test_non_admin_cannot_inject_raw_nginx_but_admin_can() -> None:
    async def run() -> None:
        app = create_app(settings=PortwyrmSettings(backend="memory"))
        host = await app.core.RoutingHostStore.create(
            {
                "kind": "proxy",
                "domain_names": ["policy.example.test"],
                "forward_scheme": "http",
                "forward_host": "backend",
                "forward_port": 8080,
                "target_kind": "dns",
            }
        )
        editor = {
            "is_admin": False,
            "permissions": {"proxy_hosts": "manage"},
            "visibility": "all",
        }
        with pytest.raises(HTTPException, match="advanced Nginx configuration requires"):
            await app.core.RoutingHostStore.update(
                {"id": host["id"], "advanced_config": "return 418;"},
                ctx={"principal": editor},
            )
        updated = await app.core.RoutingHostStore.update(
            {"id": host["id"], "advanced_config": "client_max_body_size 32m;"},
            ctx={"principal": {"is_admin": True}},
        )
        assert updated["advanced_config"] == "client_max_body_size 32m;"

    asyncio.run(run())


def test_operator_filters_have_accessible_names_in_source() -> None:
    components = Path(__file__).parents[2] / "frontend" / "src" / "components"
    source = "\n".join(path.read_text(encoding="utf-8") for path in components.glob("*.tsx"))
    assert 'aria-label="Filter' in source or 'aria-label="Search' in source
