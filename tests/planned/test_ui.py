from pathlib import Path


def test_operator_ui_is_built_from_real_api_sources_without_mock_fixtures() -> None:
    root = Path(__file__).parents[2] / "frontend" / "src"
    sources = "\n".join(
        path.read_text(encoding="utf-8")
        for pattern in ("*.ts", "*.tsx")
        for path in root.rglob(pattern)
    )
    assert "/api/nginx/" in sources
    assert "INITIAL_HOSTS" not in sources
    assert "INITIAL_USERS" not in sources
