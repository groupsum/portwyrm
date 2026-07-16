"""Runtime bootstrap operations shared by packaged and container entrypoints."""

from __future__ import annotations

import os

from portwyrm.api.compat.resources import TableResources


async def seed_demo_proxy_host(resources: TableResources) -> None:
    """Create or repair the opt-in, DNS-free local Docker demonstration route."""

    domain = os.getenv("PORTWYRM_DEMO_HOST", "").strip().lower()
    if not domain:
        return
    payload = {
        "domain_names": [domain],
        "forward_scheme": "http",
        "forward_host": "127.0.0.1",
        "forward_port": 81,
        "enabled": 1,
        "certificate_id": 0,
        "access_list_id": 0,
        "allow_websocket_upgrade": 1,
        "caching_enabled": 0,
        "block_exploits": 0,
        "http2_support": 0,
        "ssl_forced": 0,
        "hsts_enabled": 0,
        "meta": {
            "managed_by": "portwyrm-demo",
            "owner": "portwyrm-demo",
            "resource_id": f"proxy-host:{domain}",
            "purpose": "local reverse-proxy demonstration",
        },
    }
    existing = next(
        (
            row
            for row in await resources.list_resources("proxy_hosts")
            if row.get("meta", {}).get("managed_by") == "portwyrm-demo"
            or domain in row.get("domain_names", [])
        ),
        None,
    )
    if existing is None:
        await resources.create_resource("proxy_hosts", payload)
    else:
        await resources.update_resource("proxy_hosts", existing["id"], payload)


__all__ = ["seed_demo_proxy_host"]
