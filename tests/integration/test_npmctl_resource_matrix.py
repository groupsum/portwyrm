from __future__ import annotations

import asyncio

from portwyrm.api import create_app
from portwyrm.api.compat.resources import TableResources
from portwyrm.config import PortwyrmSettings


def test_npmctl_resource_matrix_covers_non_proxy_collections(tmp_path) -> None:
    async def run() -> None:
        app = create_app(`n            settings=PortwyrmSettings(backend="sqlite", data_root=tmp_path, sqlite_path=tmp_path / "matrix.sqlite"))
        resources = TableResources(app)
        admin = await resources.bootstrap_admin(
            "matrix-admin@example.test", "a strong admin password"
        )
        actor = await resources.authenticate("matrix-admin@example.test", "a strong admin password")
        assert actor is not None

        redirect = await resources.create_resource(
            "redirection_hosts",
            {
                "domain_names": ["redirect.matrix.example.test"],
                "forward_domain_name": "destination.example.test",
                "forward_http_code": 302,
                "enabled": 1,
            },
            actor=actor,
        )
        dead = await resources.create_resource(
            "dead_hosts",
            {"domain_names": ["dead.matrix.example.test"], "enabled": 1},
            actor=actor,
        )
        stream = await resources.create_resource(
            "streams",
            {
                "incoming_port": 19091,
                "forwarding_host": "backend",
                "forwarding_port": 9091,
                "target_kind": "dns",
                "tcp_forwarding": True,
                "enabled": 1,
            },
            actor=actor,
        )
        setting = await resources.create_resource(
            "settings", {"key": "matrix.mode", "value": {"enabled": True}}, actor=actor
        )
        user = await resources.create_resource(
            "users",
            {
                "email": "matrix-user@example.test",
                "password": "a user password",
                "name": "Matrix User",
                "nickname": "matrix",
            },
            actor=actor,
        )

        assert (
            await resources.get_resource("redirection_hosts", redirect["id"])
        )["kind"] == "redirect"
        assert (await resources.get_resource("dead_hosts", dead["id"]))["kind"] == "dead"
        assert (await resources.get_resource("streams", stream["id"]))["incoming_port"] == 19091
        assert (
            await resources.get_resource("settings", setting["id"])
        )["value"] == {"enabled": True}
        assert (
            await resources.get_resource("users", user["id"])
        )["email"] == "matrix-user@example.test"

        changed_redirect = await resources.update_resource(
            "redirection_hosts", redirect["id"], {"forward_http_code": 301}, actor=actor
        )
        changed_stream = await resources.set_enabled(
            "streams", stream["id"], enabled=False, actor=actor
        )
        changed_user = await resources.update_resource(
            "users", user["id"], {"nickname": "updated-matrix"}, actor=actor
        )
        assert changed_redirect["forward_http_code"] == 301
        assert not bool(changed_stream["enabled"])
        assert changed_user["nickname"] == "updated-matrix"

        for collection, resource in (
            ("redirection_hosts", redirect),
            ("dead_hosts", dead),
            ("streams", stream),
            ("settings", setting),
        ):
            assert await resources.delete_resource(collection, resource["id"], actor=actor)
            assert await resources.get_resource(collection, resource["id"]) is None

        assert admin["email"] == "matrix-admin@example.test"

    asyncio.run(run())