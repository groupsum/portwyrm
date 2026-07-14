from __future__ import annotations

import importlib
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = ROOT / "src" / "portwyrm"

CAPABILITY_PACKAGES = (
    "api",
    "api.compat",
    "api.native",
    "application",
    "certificates",
    "cli",
    "domain",
    "identity",
    "migration",
    "operations",
    "persistence",
    "runtime",
    "uix",
)


def test_capability_packages_are_explicit_and_importable() -> None:
    for dotted_name in CAPABILITY_PACKAGES:
        package = PACKAGE_ROOT.joinpath(*dotted_name.split("."))
        assert package.is_dir(), dotted_name
        assert (package / "__init__.py").is_file(), dotted_name
        assert importlib.import_module(f"portwyrm.{dotted_name}") is not None


def test_legacy_root_modules_and_ui_collision_are_absent() -> None:
    for relative_path in ("service.py", "persistent.py", "mfa.py", "ui.py", "ui"):
        assert not (PACKAGE_ROOT / relative_path).exists(), relative_path


def test_uix_assets_are_owned_and_packaged_by_uix() -> None:
    static = PACKAGE_ROOT / "uix" / "static"
    assert {path.name for path in static.iterdir()} == {"app.js", "index.html", "styles.css"}

    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = configuration["tool"]["setuptools"]["package-data"]
    assert package_data == {"portwyrm.uix": ["static/*.html", "static/*.css", "static/*.js"]}
