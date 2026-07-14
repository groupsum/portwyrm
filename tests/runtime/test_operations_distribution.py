from __future__ import annotations

from pathlib import Path

from portwyrm.operations import (
    AuditLog,
    HealthService,
    LogRotator,
    Settings,
    Upgrade,
    UpgradeManager,
)
from portwyrm.persistence import MemoryRepository


def test_audit_settings_health_and_upgrades(tmp_path: Path) -> None:
    repository = MemoryRepository()
    settings = Settings(repository)
    assert settings.get("default-site", "404") == "404"
    settings.set("default-site", "welcome")
    assert settings.get("default-site") == "welcome"

    audit = AuditLog(repository)
    audit.append("token.created", actor="admin", details={"token": "secret", "name": "automation"})
    assert audit.list()[0]["details"] == {"token": "[REDACTED]", "name": "automation"}
    assert HealthService(repository, {"nginx": lambda: True}).ready()["status"] == "ok"
    assert HealthService(repository, {"nginx": lambda: False}).ready()["status"] == "degraded"

    manager = UpgradeManager(
        repository,
        [Upgrade(1, "seed", lambda tx: tx.upsert("settings", {"id": "seeded", "value": True}))],
    )
    assert manager.run() == [1]
    assert manager.run() == []

    log = tmp_path / "portwyrm.log"
    log.write_text("12345", encoding="utf-8")
    assert LogRotator(log, max_bytes=5, backups=2).rotate_if_needed() is True
    assert (tmp_path / "portwyrm.log.1").read_text(encoding="utf-8") == "12345"


def test_distribution_assets_define_supervision_health_and_supply_chain() -> None:
    root = Path(__file__).parents[2]
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    workflow = (root / ".github/workflows/container.yml").read_text(encoding="utf-8")
    compose = (root / "compose.yaml").read_text(encoding="utf-8")

    assert "ENTRYPOINT" in dockerfile
    assert "HEALTHCHECK" in dockerfile
    assert "EXPOSE 80 81 443" in dockerfile
    assert "linux/amd64,linux/arm64" in workflow
    assert "provenance: mode=max" in workflow
    assert "sbom: true" in workflow
    assert '"81:81"' in compose
