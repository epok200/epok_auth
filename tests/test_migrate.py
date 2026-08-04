from __future__ import annotations

from unittest.mock import Mock

import pytest

from epok_auth import migrate
from epok_auth.postgres import async_psycopg_url


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("postgresql://u:p@db/name", "postgresql+psycopg://u:p@db/name"),
        ("postgres://u:p@db/name", "postgresql+psycopg://u:p@db/name"),
        ("postgresql+psycopg://u:p@db/name", "postgresql+psycopg://u:p@db/name"),
    ],
)
def test_async_psycopg_url(source: str, expected: str) -> None:
    assert async_psycopg_url(source) == expected


def test_async_psycopg_url_rejects_other_databases() -> None:
    with pytest.raises(ValueError):
        async_psycopg_url("sqlite:///test.db")


def test_migration_commands_use_packaged_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    upgraded = Mock()
    downgraded = Mock()
    checked = Mock()
    monkeypatch.setattr(migrate.command, "upgrade", upgraded)
    monkeypatch.setattr(migrate.command, "downgrade", downgraded)
    monkeypatch.setattr(migrate.command, "check", checked)

    url = "postgresql://user:p%ss@db/tests"
    migrate.upgrade_database(url, "head")
    migrate.downgrade_database(url, "base")
    migrate.check_database(url)

    upgrade_config = upgraded.call_args.args[0]
    assert upgrade_config.get_main_option("script_location").endswith("epok_auth/migrations")
    assert upgrade_config.get_main_option("sqlalchemy.url") == (
        "postgresql+psycopg://user:p%ss@db/tests"
    )
    upgraded.assert_called_once_with(upgrade_config, "head")
    downgraded.assert_called_once()
    checked.assert_called_once()
