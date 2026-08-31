import os
from collections.abc import Iterator

import pytest
from alembic.util.exc import CommandError
from sqlalchemy.exc import ProgrammingError

psycopg = pytest.importorskip("psycopg")

from epok_auth.migrate import check_database, upgrade_database

pytestmark = pytest.mark.integration

DATABASE_URL = os.getenv("TEST_DATABASE_URL")
HOST_REVISION = "host_0001"
CURRENT_REVISION = "0005_account_activation"
VERSION_TABLE = "epok_auth_alembic_version"


def sync_url(url: str) -> str:
    return url.replace("postgresql+psycopg://", "postgresql://", 1)


@pytest.fixture(scope="session")
def database_url() -> str:
    if not DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL is required")
    return DATABASE_URL


@pytest.fixture(autouse=True)
def clean_migration_state(database_url: str) -> Iterator[None]:
    _reset_database(database_url)
    yield
    _reset_database(database_url)
    upgrade_database(database_url)


def test_migrations_preserve_the_host_alembic_history(database_url: str) -> None:
    _create_host_history(database_url)

    upgrade_database(database_url)
    check_database(database_url)

    with psycopg.connect(sync_url(database_url)) as connection:
        host_revision = _revision(connection, "alembic_version")
        epok_revision = _revision(connection, VERSION_TABLE)

    assert host_revision == HOST_REVISION
    assert epok_revision == CURRENT_REVISION


@pytest.mark.parametrize("legacy_revision", ["0001_initial", "0002_passkeys"])
def test_migrations_adopt_a_trusted_legacy_epok_history(
    database_url: str,
    legacy_revision: str,
) -> None:
    upgrade_database(database_url, legacy_revision)
    with psycopg.connect(sync_url(database_url), autocommit=True) as connection:
        connection.execute("ALTER TABLE public.epok_auth_alembic_version RENAME TO alembic_version")

    upgrade_database(database_url)

    with psycopg.connect(sync_url(database_url)) as connection:
        legacy_table = connection.execute(
            "SELECT to_regclass('public.alembic_version')"
        ).fetchone()[0]
        epok_revision = _revision(connection, VERSION_TABLE)
        google_table_exists = connection.execute(
            "SELECT to_regclass('epok_auth.external_identity') IS NOT NULL"
        ).fetchone()[0]

    assert legacy_table is None
    assert epok_revision == CURRENT_REVISION
    assert google_table_exists is True


@pytest.mark.parametrize(
    "legacy_revision",
    [HOST_REVISION, CURRENT_REVISION, "0002_passkeys"],
)
def test_migrations_reject_an_ambiguous_legacy_history(
    database_url: str,
    legacy_revision: str,
) -> None:
    with psycopg.connect(sync_url(database_url), autocommit=True) as connection:
        connection.execute("CREATE SCHEMA epok_auth")
    _create_host_history(database_url, legacy_revision)

    with pytest.raises(CommandError, match="without a trusted migration history"):
        upgrade_database(database_url)

    with psycopg.connect(sync_url(database_url)) as connection:
        host_revision = _revision(connection, "alembic_version")
        epok_table = connection.execute(
            "SELECT to_regclass('public.epok_auth_alembic_version')"
        ).fetchone()[0]

    assert host_revision == legacy_revision
    assert epok_table is None


def test_failed_upgrade_rolls_back_legacy_history_adoption(database_url: str) -> None:
    upgrade_database(database_url, "0002_passkeys")
    with psycopg.connect(sync_url(database_url), autocommit=True) as connection:
        connection.execute("ALTER TABLE public.epok_auth_alembic_version RENAME TO alembic_version")
        connection.execute(
            "ALTER TABLE epok_auth.user_account "
            "ADD COLUMN password_login_enabled BOOLEAN NOT NULL DEFAULT true"
        )

    with pytest.raises(ProgrammingError):
        upgrade_database(database_url)

    with psycopg.connect(sync_url(database_url)) as connection:
        legacy_revision = _revision(connection, "alembic_version")
        epok_table = connection.execute(
            "SELECT to_regclass('public.epok_auth_alembic_version')"
        ).fetchone()[0]

    assert legacy_revision == "0002_passkeys"
    assert epok_table is None


def _reset_database(database_url: str) -> None:
    with psycopg.connect(sync_url(database_url), autocommit=True) as connection:
        connection.execute("DROP SCHEMA IF EXISTS epok_auth CASCADE")
        connection.execute("DROP TABLE IF EXISTS public.epok_auth_alembic_version")
        connection.execute("DROP TABLE IF EXISTS public.alembic_version")


def _create_host_history(database_url: str, revision: str = HOST_REVISION) -> None:
    with psycopg.connect(sync_url(database_url), autocommit=True) as connection:
        connection.execute(
            "CREATE TABLE public.alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY)"
        )
        connection.execute(
            "INSERT INTO public.alembic_version (version_num) VALUES (%s)",
            (revision,),
        )


def _revision(connection, table_name: str) -> str:
    statement = psycopg.sql.SQL("SELECT version_num FROM public.{}").format(
        psycopg.sql.Identifier(table_name)
    )
    row = connection.execute(statement).fetchone()
    assert row is not None
    return str(row[0])
