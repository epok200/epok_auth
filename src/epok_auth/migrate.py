from collections.abc import Callable
from importlib.resources import as_file, files
from pathlib import Path

from alembic import command
from alembic.config import Config

from epok_auth.postgres import async_psycopg_url

MigrationCommand = Callable[[Config, str], None]


def _config(database_url: str, migration_path: Path) -> Config:
    config = Config()
    config.set_main_option("script_location", str(migration_path))
    config.set_main_option(
        "sqlalchemy.url",
        async_psycopg_url(database_url).replace("%", "%%"),
    )
    return config


def upgrade_database(database_url: str, revision: str = "head") -> None:
    """Apply packaged epok-auth migrations."""
    with as_file(files("epok_auth.migrations")) as migration_path:
        command.upgrade(_config(database_url, migration_path), revision)


def downgrade_database(database_url: str, revision: str = "base") -> None:
    """Downgrade the packaged epok-auth schema."""
    with as_file(files("epok_auth.migrations")) as migration_path:
        command.downgrade(_config(database_url, migration_path), revision)


def check_database(database_url: str) -> None:
    """Fail when model metadata and the migrated schema drift."""
    with as_file(files("epok_auth.migrations")) as migration_path:
        command.check(_config(database_url, migration_path))
