from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "publish.py"
SPEC = importlib.util.spec_from_file_location("epok_auth_publish", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
publish = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = publish
SPEC.loader.exec_module(publish)


def test_parse_secret_text_accepts_comments_and_quotes() -> None:
    token = publish.parse_secret_text('# local token\nUV_PUBLISH_TOKEN="pypi-example_token-123"\n')
    assert token == "pypi-example_token-123"


def test_parse_secret_text_rejects_unknown_keys() -> None:
    with pytest.raises(publish.ReleaseError, match="only UV_PUBLISH_TOKEN"):
        publish.parse_secret_text("OTHER_SECRET=nope")


def test_parse_secret_text_rejects_duplicates() -> None:
    with pytest.raises(publish.ReleaseError, match="only once"):
        publish.parse_secret_text("UV_PUBLISH_TOKEN=pypi-first\nUV_PUBLISH_TOKEN=pypi-second\n")


@pytest.mark.parametrize(
    ("mapping", "expected"),
    [
        ("127.0.0.1:49153\n", 49153),
        ("0.0.0.0:32768\n[::]:32768\n", 32768),
        ("[::1]:55000\n", 55000),
    ],
)
def test_parse_docker_port(mapping: str, expected: int) -> None:
    assert publish.parse_docker_port(mapping) == expected


def test_parse_docker_port_rejects_invalid_output() -> None:
    with pytest.raises(publish.ReleaseError, match="Could not parse"):
        publish.parse_docker_port("not-a-port")
