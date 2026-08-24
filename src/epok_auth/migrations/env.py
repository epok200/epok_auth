import asyncio
from logging.config import fileConfig

from alembic import context
from alembic.util.exc import CommandError
from sqlalchemy import MetaData, pool, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from epok_auth.postgres.tables import SCHEMA, metadata

VERSION_TABLE = "epok_auth_alembic_version"
VERSION_TABLE_SCHEMA = "public"
LEGACY_VERSION_TABLE = "alembic_version"
VERSION_TABLES = frozenset({VERSION_TABLE, LEGACY_VERSION_TABLE})
INITIAL_SCHEMA_FINGERPRINT = {
    "user_account": frozenset({"id", "email", "password_hash", "status", "roles", "scopes"}),
    "refresh_session": frozenset(
        {"id", "user_id", "token_hash", "csrf_hash", "absolute_expires_at"}
    ),
    "security_event": frozenset({"id", "event_type", "event_metadata", "user_id", "session_id"}),
}
PASSKEY_SCHEMA_FINGERPRINT = INITIAL_SCHEMA_FINGERPRINT | {
    "passkey_credential": frozenset(
        {"id", "user_id", "credential_id", "public_key", "sign_count", "aaguid"}
    ),
    "passkey_challenge": frozenset(
        {"id", "purpose", "challenge", "origin", "user_id", "consumed_at"}
    ),
}
LEGACY_SCHEMA_FINGERPRINTS = {
    "0001_initial": INITIAL_SCHEMA_FINGERPRINT,
    "0002_passkeys": PASSKEY_SCHEMA_FINGERPRINT,
}
LEGACY_REVISIONS_SQL = text('SELECT version_num FROM "public"."alembic_version"')
SCHEMA_COLUMNS_SQL = text(
    "SELECT table_name, column_name FROM information_schema.columns "
    "WHERE table_schema = :schema_name"
)
ADOPT_LEGACY_SQL = text(
    'ALTER TABLE "public"."alembic_version" RENAME TO "epok_auth_alembic_version"'
)

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _comparison_metadata() -> MetaData:
    """Mirror the owned schema as PostgreSQL reflects it through search_path."""
    comparison = MetaData()
    for table in metadata.sorted_tables:
        # SQLAlchemy accepts None to clear a schema during cloning; its current
        # type signature exposes only str and RETAIN_SCHEMA.
        table.to_metadata(comparison, schema=None)  # pyright: ignore[reportArgumentType]
    return comparison


def _include_object(
    _object: object,
    name: str | None,
    type_: str,
    reflected: bool,
    _compare_to: object | None,
) -> bool:
    """Exclude migration histories, never application objects."""
    return not (type_ == "table" and reflected and name in VERSION_TABLES)


def _table_exists(connection: Connection, name: str) -> bool:
    qualified_name = f"{VERSION_TABLE_SCHEMA}.{name}"
    result = connection.execute(
        text("SELECT to_regclass(:qualified_name)"),
        {"qualified_name": qualified_name},
    )
    return result.scalar_one() is not None


def _schema_exists(connection: Connection) -> bool:
    result = connection.execute(
        text("SELECT to_regnamespace(:schema_name)"),
        {"schema_name": SCHEMA},
    )
    return result.scalar_one() is not None


def _legacy_revisions(connection: Connection) -> set[str] | None:
    if not _table_exists(connection, LEGACY_VERSION_TABLE):
        return None
    return {str(revision) for revision in connection.execute(LEGACY_REVISIONS_SQL).scalars()}


def _schema_matches(
    connection: Connection,
    expected: dict[str, frozenset[str]],
) -> bool:
    rows = connection.execute(SCHEMA_COLUMNS_SQL, {"schema_name": SCHEMA})
    actual: dict[str, set[str]] = {}
    for table_name, column_name in rows:
        actual.setdefault(str(table_name), set()).add(str(column_name))

    if actual.keys() != expected.keys():
        return False
    return all(columns <= actual[table_name] for table_name, columns in expected.items())


def _legacy_history_is_trusted(
    connection: Connection,
    revisions: set[str] | None,
) -> bool:
    if revisions is None or len(revisions) != 1:
        return False
    revision = next(iter(revisions))
    expected = LEGACY_SCHEMA_FINGERPRINTS.get(revision)
    return expected is not None and _schema_matches(connection, expected)


def _prepare_version_history(connection: Connection) -> None:
    if _table_exists(connection, VERSION_TABLE) or not _schema_exists(connection):
        return

    legacy_revisions = _legacy_revisions(connection)
    if not _legacy_history_is_trusted(connection, legacy_revisions):
        raise CommandError(
            "epok-auth found its schema without a trusted migration history. "
            "It will not modify public.alembic_version because that table may belong "
            "to the host application. Restore the epok-auth history before retrying."
        )

    connection.execute(ADOPT_LEGACY_SQL)


target_metadata = _comparison_metadata()


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_schemas=False,
        include_object=_include_object,
        version_table=VERSION_TABLE,
        version_table_schema=VERSION_TABLE_SCHEMA,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    # PostgreSQL omits the schema from same-schema foreign-key reflection. Treating
    # epok_auth as the default schema makes reflected and comparison metadata
    # canonical without hiding real foreign-key drift.
    #
    # Commit the session setup before the transaction that owns both legacy
    # history adoption and all subsequent migration DDL.
    connection.execute(text(f'SET search_path TO "{SCHEMA}", public'))
    connection.commit()
    connection.dialect.default_schema_name = SCHEMA
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        include_schemas=False,
        include_object=_include_object,
        version_table=VERSION_TABLE,
        version_table_schema=VERSION_TABLE_SCHEMA,
        compare_type=True,
    )
    with connection.begin():
        _prepare_version_history(connection)
        with context.begin_transaction():
            context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    try:
        async with connectable.connect() as connection:
            await connection.run_sync(do_run_migrations)
    finally:
        await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
