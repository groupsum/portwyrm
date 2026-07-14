from __future__ import annotations

import pytest

from portwyrm.service import Actor, Conflict, ControlPlane, NotFound

OWNER = Actor(id=2, email="operator@example.com", owner="groupsum")


def proxy(domain: str, *, owner: str = "groupsum") -> dict[str, object]:
    return {
        "domain_names": [domain],
        "forward_scheme": "http",
        "forward_host": "upstream",
        "forward_port": 8080,
        "enabled": 1,
        "meta": {"managed_by": "npmctl", "owner": owner, "resource_id": domain},
    }


def test_stable_ids_metadata_and_soft_delete() -> None:
    service = ControlPlane()
    created = service.create("proxy-hosts", proxy("one.example"), actor=OWNER)
    assert created["id"] == 1
    assert created["meta"] == proxy("one.example")["meta"]
    assert service.delete("proxy-hosts", 1, actor=OWNER)
    with pytest.raises(NotFound):
        service.get("proxy-hosts", 1)
    assert service.create("proxy-hosts", proxy("two.example"), actor=OWNER)["id"] == 2


def test_casefolded_cross_family_domain_collision() -> None:
    service = ControlPlane()
    service.create("proxy-hosts", proxy("App.Example"), actor=OWNER)
    with pytest.raises(Conflict, match="domain already"):
        service.create(
            "dead-hosts",
            {"domain_names": ["app.example"], "enabled": 1},
            actor=OWNER,
        )


def test_foreign_resources_are_hidden_and_cannot_be_pruned() -> None:
    service = ControlPlane()
    row = service.create("proxy-hosts", proxy("foreign.example", owner="another-team"))
    assert service.list("proxy-hosts", actor=OWNER) == []
    with pytest.raises(NotFound):
        service.get("proxy-hosts", row["id"], actor=OWNER)
    with pytest.raises(NotFound):
        service.delete("proxy-hosts", row["id"], actor=OWNER, prune=True)


def test_invalid_inputs_and_audit_redaction() -> None:
    service = ControlPlane()
    with pytest.raises(Exception, match="forward_port"):
        service.create("proxy-hosts", {**proxy("bad.example"), "forward_port": 0})
    token = service.create(
        "access-tokens",
        {"name": "deploy", "secret": "never-log-me", "meta": {}},
        actor=OWNER,
    )
    event = service.audit_since()[-1]
    assert token["secret"] == "never-log-me"
    assert event["meta"]["secret"] == "[redacted]"


def test_preserved_compatibility_ids_advance_allocator() -> None:
    service = ControlPlane()
    imported = service.create("certificates", {"id": 187, "nice_name": "legacy"}, preserve_id=True)
    assert imported["id"] == 187
    assert service.create("certificates", {"nice_name": "next"})["id"] == 188
