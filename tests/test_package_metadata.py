from importlib.metadata import version

import epok_auth


def test_runtime_version_matches_distribution_metadata() -> None:
    assert epok_auth.__version__ == version("epok-auth")
