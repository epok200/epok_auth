import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import MetaData, pool, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from epok_auth.postgres.tables import SCHEMA, metadata

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
    """Exclude Alembic's own revision table, never application objects."""
    return not (type_ == "table" and reflected and name == "alembic_version")


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
        version_table_schema="public",
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    # PostgreSQL omits the schema from same-schema foreign-key reflection. Treating
    # epok_auth as the default schema makes reflected and comparison metadata
    # canonical without hiding real foreign-key drift.
    #
    # Executing SET starts an implicit SQLAlchemy transaction. Commit that session
    # setup first so Alembic owns and commits the subsequent transactional DDL.
    connection.execute(text(f'SET search_path TO "{SCHEMA}", public'))
    connection.commit()
    connection.dialect.default_schema_name = SCHEMA
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        include_schemas=False,
        include_object=_include_object,
        version_table_schema="public",
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
