from pathlib import Path


def test_container_distribution_declares_runtime_and_health_contract() -> None:
    dockerfile = (Path(__file__).parents[2] / "Dockerfile").read_text(encoding="utf-8")
    assert "HEALTHCHECK" in dockerfile
    assert "EXPOSE 80 81 443" in dockerfile
    assert 'ENTRYPOINT ["python", "/app/deploy/entrypoint.py"]' in dockerfile
