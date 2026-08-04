from __future__ import annotations

import asyncio
import secrets
from typing import Annotated

import typer
from pydantic import ValidationError

from epok_auth.config import AuthSettings

app = typer.Typer(
    name="epok-auth",
    no_args_is_help=True,
    help="Manage epok-auth configuration, migrations, and the initial administrator.",
)


@app.command("generate-secret")
def generate_secret(
    bytes_count: Annotated[
        int,
        typer.Option("--bytes", min=32, max=128, help="Random bytes before URL-safe encoding."),
    ] = 48,
) -> None:
    """Generate a high-entropy JWT secret without persisting it."""
    typer.echo(secrets.token_urlsafe(bytes_count))


@app.command("check-config")
def check_config() -> None:
    """Validate environment configuration without printing secrets."""
    try:
        settings = _load_settings()
    except ValidationError as error:
        typer.echo("epok-auth configuration is invalid.", err=True)
        for item in error.errors(include_url=False, include_input=False):
            location = ".".join(str(part) for part in item["loc"])
            typer.echo(f"- {location or 'settings'}: {item['msg']}", err=True)
        raise typer.Exit(code=1) from error

    typer.echo("epok-auth configuration is valid.")
    typer.echo(f"environment={settings.environment.value}")
    typer.echo(f"issuer={settings.issuer}")
    typer.echo(f"audience={settings.audience}")
    typer.echo(f"trusted_origins={len(settings.trusted_origins)}")
    typer.echo(f"secure_cookies={str(settings.secure_cookies).lower()}")


@app.command("upgrade-db")
def upgrade_db(
    revision: Annotated[str, typer.Option(help="Alembic target revision.")] = "head",
) -> None:
    """Apply packaged PostgreSQL migrations."""
    from epok_auth.migrate import upgrade_database

    settings = _settings_with_database()
    database_url = settings.database_url
    if database_url is None:  # guarded by _settings_with_database
        raise typer.Exit(code=1)
    upgrade_database(database_url.get_secret_value(), revision=revision)
    typer.echo(f"epok-auth database upgraded to {revision}.")


@app.command("check-db")
def check_db() -> None:
    """Fail when packaged metadata and the migrated PostgreSQL schema drift."""
    from epok_auth.migrate import check_database

    settings = _settings_with_database()
    database_url = settings.database_url
    if database_url is None:  # guarded by _settings_with_database
        raise typer.Exit(code=1)
    check_database(database_url.get_secret_value())
    typer.echo("epok-auth database schema matches the packaged metadata.")


@app.command("create-admin")
def create_admin(
    email: Annotated[str, typer.Option(prompt=True, help="Administrator email.")],
    display_name: Annotated[str, typer.Option(prompt=True, help="Administrator display name.")],
    password: Annotated[
        str,
        typer.Option(
            prompt=True,
            hide_input=True,
            confirmation_prompt=True,
            help="Initial administrator password.",
        ),
    ],
) -> None:
    """Create the one allowed initial administrator."""
    settings = _settings_with_database()
    asyncio.run(_create_admin(settings, email=email, display_name=display_name, password=password))
    typer.echo("Initial administrator created.")


async def _create_admin(
    settings: AuthSettings,
    *,
    email: str,
    display_name: str,
    password: str,
) -> None:
    from epok_auth.postgres import PostgresAuthStore
    from epok_auth.service import AuthService

    database_url = settings.database_url
    if database_url is None:  # guarded by _settings_with_database; keeps typing explicit.
        raise RuntimeError("database_url is required")
    store = PostgresAuthStore.from_url(database_url.get_secret_value())
    try:
        await AuthService(store=store, settings=settings).create_admin(
            email=email,
            display_name=display_name,
            password=password,
        )
    finally:
        await store.aclose()


def _load_settings() -> AuthSettings:
    # BaseSettings obtains required values from the environment at runtime.
    return AuthSettings()  # pyright: ignore[reportCallIssue]


def _settings_with_database() -> AuthSettings:
    try:
        settings = _load_settings()
    except ValidationError as error:
        typer.echo("epok-auth configuration is invalid. Run `epok-auth check-config`.", err=True)
        raise typer.Exit(code=1) from error
    if settings.database_url is None:
        typer.echo("EPOK_AUTH_DATABASE_URL is required.", err=True)
        raise typer.Exit(code=1)
    return settings


if __name__ == "__main__":  # pragma: no cover
    app()
