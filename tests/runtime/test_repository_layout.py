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
    "certificates",
    "cli",
    "config",
    "domain",
    "identity",
    "migration",
    "runtime",
    "tables",
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
    for removed_package in ("application", "operations", "persistence"):
        assert not (PACKAGE_ROOT / removed_package).exists(), removed_package


def test_uix_assets_are_owned_and_packaged_by_uix() -> None:
    static = PACKAGE_ROOT / "uix" / "static"
    assert {path.name for path in static.iterdir()} == {
        "apple-touch-icon.png",
        "assets",
        "favicon-16x16.png",
        "favicon-32x32.png",
        "favicon.ico",
        "index.html",
        "portwyrm-mark.png",
    }
    assets = {path.suffix for path in (static / "assets").iterdir()}
    assert assets == {".js", ".css"}

    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = configuration["tool"]["setuptools"]["package-data"]
    assert package_data == {
        "portwyrm.uix": [
            "static/*.html",
            "static/*.css",
            "static/*.js",
            "static/*.png",
            "static/*.ico",
            "static/assets/*.css",
            "static/assets/*.js",
        ]
    }
