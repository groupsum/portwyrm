from portwyrm import __version__


def test_version_is_pre_alpha() -> None:
    assert __version__ == "0.1.0a0"
