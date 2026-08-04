from __future__ import annotations

from importlib.resources import as_file, files

from alembic import command
from alembic.config import Config

from epok_auth.postgres.store import _async_psycopg_url


def upgrade_database(database_url: str, revision: str = "head") -> None:
    """Apply the packaged epok-auth Alembic migrations."""

    migration_root = files("epok_auth.migrations")
    with as_file(migration_root) as migration_path:
        config = Config()
        config.set_main_option("script_location", str(migration_path))
        config.set_main_option(
            "sqlalchemy.url",
            _async_psycopg_url(database_url).replace("%", "%%"),
        )
        command.upgrade(config, revision)
