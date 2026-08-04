from __future__ import annotations

from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from epok_auth import cli
from epok_auth.config import AuthSettings, Environment

runner = CliRunner()
SECRET = "cli-test-secret-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def valid_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "EPOK_AUTH_ENVIRONMENT": "test",
        "EPOK_AUTH_JWT_SECRET": SECRET,
        "EPOK_AUTH_ISSUER": "cli-tests",
        "EPOK_AUTH_AUDIENCE": "cli-tests-api",
        "EPOK_AUTH_DATABASE_URL": "postgresql://user:pass@db/tests",
        "EPOK_AUTH_SECURE_COOKIES": "false",
        "EPOK_AUTH_COOKIE_USE_HOST_PREFIX": "false",
        "EPOK_AUTH_TRUSTED_ORIGINS": "http://localhost:3000",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_generate_secret_outputs_high_entropy_value() -> None:
    result = runner.invoke(cli.app, ["generate-secret", "--bytes", "48"])
    assert result.exit_code == 0
    assert len(result.stdout.strip()) >= 64
    assert " " not in result.stdout.strip()


def test_check_config_reports_safe_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    valid_environment(monkeypatch)
    result = runner.invoke(cli.app, ["check-config"])
    assert result.exit_code == 0
    assert "configuration is valid" in result.stdout
    assert "environment=test" in result.stdout
    assert SECRET not in result.stdout
    assert "user:pass" not in result.stdout


def test_check_config_fails_without_printing_input(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EPOK_AUTH_JWT_SECRET", "private-but-short")
    result = runner.invoke(cli.app, ["check-config"])
    assert result.exit_code == 1
    assert "configuration is invalid" in result.output
    assert "private-but-short" not in result.output


def test_upgrade_and_check_db_delegate_to_migration_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid_environment(monkeypatch)
    upgraded = Mock()
    checked = Mock()
    import epok_auth.migrate

    monkeypatch.setattr(epok_auth.migrate, "upgrade_database", upgraded)
    monkeypatch.setattr(epok_auth.migrate, "check_database", checked)

    result = runner.invoke(cli.app, ["upgrade-db", "--revision", "head"])
    assert result.exit_code == 0
    upgraded.assert_called_once_with("postgresql://user:pass@db/tests", revision="head")

    result = runner.invoke(cli.app, ["check-db"])
    assert result.exit_code == 0
    checked.assert_called_once_with("postgresql://user:pass@db/tests")


def test_database_commands_require_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    valid_environment(monkeypatch)
    monkeypatch.delenv("EPOK_AUTH_DATABASE_URL")
    result = runner.invoke(cli.app, ["upgrade-db"])
    assert result.exit_code == 1
    assert "DATABASE_URL is required" in result.output


def test_create_admin_command_delegates_without_echoing_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid_environment(monkeypatch)
    called: dict[str, object] = {}

    async def fake_create(
        settings: AuthSettings,
        *,
        email: str,
        display_name: str,
        password: str,
    ) -> None:
        called.update(
            settings=settings,
            email=email,
            display_name=display_name,
            password=password,
        )

    monkeypatch.setattr(cli, "_create_admin", fake_create)
    result = runner.invoke(
        cli.app,
        [
            "create-admin",
            "--email",
            "admin@example.com",
            "--display-name",
            "Admin",
            "--password",
            "private password for command",
        ],
    )
    assert result.exit_code == 0
    assert called["email"] == "admin@example.com"
    assert isinstance(called["settings"], AuthSettings)
    assert "private password for command" not in result.output


@pytest.mark.asyncio
async def test_create_admin_closes_store(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = AuthSettings(
        environment=Environment.TEST,
        database_url="postgresql://user:pass@db/tests",
        jwt_secret=SECRET,
        issuer="tests",
        audience="tests-api",
        secure_cookies=False,
        cookie_use_host_prefix=False,
        trusted_origins=("http://localhost:3000",),
    )
    state = {"created": False, "closed": False}

    class Store:
        async def aclose(self) -> None:
            state["closed"] = True

    class StoreFactory:
        @classmethod
        def from_url(cls, url: str) -> Store:
            assert url == "postgresql://user:pass@db/tests"
            return Store()

    class Service:
        def __init__(self, *, store: Store, settings: AuthSettings) -> None:
            del store, settings

        async def create_admin(self, **kwargs: str) -> None:
            assert kwargs["password"] == "secret"
            state["created"] = True

    import epok_auth.postgres
    import epok_auth.service

    monkeypatch.setattr(epok_auth.postgres, "PostgresAuthStore", StoreFactory)
    monkeypatch.setattr(epok_auth.service, "AuthService", Service)
    await cli._create_admin(
        settings,
        email="admin@example.com",
        display_name="Admin",
        password="secret",
    )
    assert state == {"created": True, "closed": True}
