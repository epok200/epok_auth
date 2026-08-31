import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from epok_auth import load_auth_settings
from epok_auth.config import AuthSettings, Environment

SECRET = "strong-test-secret-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def make(**overrides: object) -> AuthSettings:
    values: dict[str, object] = {
        "environment": Environment.TEST,
        "jwt_secret": SECRET,
        "issuer": "test-issuer",
        "audience": "test-audience",
        "secure_cookies": False,
        "cookie_use_host_prefix": False,
        "trusted_origins": ("http://localhost:3000",),
    }
    values.update(overrides)
    return AuthSettings(**values)  # type: ignore[arg-type]


def test_development_factory_is_safe_for_local_http() -> None:
    settings = AuthSettings.development()
    assert settings.environment is Environment.DEVELOPMENT
    assert settings.secure_cookies is False
    assert settings.cookie_use_host_prefix is False
    assert "http://localhost:3000" in settings.trusted_origins
    assert settings.passkey_rp_id == "localhost"
    assert len(settings.jwt_secret.get_secret_value()) >= 32


def test_load_auth_settings_reads_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    for name in tuple(os.environ):
        if name.startswith("EPOK_AUTH_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("EPOK_AUTH_ENVIRONMENT", "test")
    monkeypatch.setenv("EPOK_AUTH_JWT_SECRET", SECRET)

    settings = load_auth_settings()

    assert settings.environment is Environment.TEST
    assert settings.jwt_secret.get_secret_value() == SECRET
    assert SECRET not in repr(settings)


def test_load_auth_settings_requires_jwt_secret(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    for name in tuple(os.environ):
        if name.startswith("EPOK_AUTH_"):
            monkeypatch.delenv(name)

    with pytest.raises(ValidationError, match="jwt_secret"):
        load_auth_settings()


@pytest.mark.parametrize(
    "secret",
    [
        "short",
        "change-me",
        "a" * 64,
        " valid-secret-with-high-entropy-0123456789-ABCDEF",
        "valid-secret-with-high-entropy-0123456789-ABCDEF\n",
    ],
)
def test_rejects_weak_or_ambiguous_secrets(secret: str) -> None:
    with pytest.raises(ValidationError):
        make(jwt_secret=secret)


def test_rejects_invalid_ttl_relationships() -> None:
    with pytest.raises(ValidationError, match="access TTL"):
        make(access_ttl_seconds=900, refresh_idle_ttl_seconds=900)
    with pytest.raises(ValidationError, match="absolute"):
        make(refresh_idle_ttl_seconds=7200, refresh_absolute_ttl_seconds=3600)


def test_rejects_invalid_password_bounds() -> None:
    with pytest.raises(ValidationError, match="password_min_length"):
        make(password_min_length=100, password_max_length=64)


def test_normalizes_origins_and_default_ports() -> None:
    settings = make(
        trusted_origins=(
            "HTTPS://Example.COM:443/",
            "http://localhost:80/",
            "https://example.org:8443",
        )
    )
    assert settings.trusted_origins == (
        "https://example.com",
        "http://localhost",
        "https://example.org:8443",
    )


@pytest.mark.parametrize(
    "origin",
    [
        "https://*.example.com",
        "http://example.com",
        "https://user:pass@example.com",
        "https://example.com/path",
        "https://example.com?query=yes",
        "https://example.com#fragment",
        "https://example.com:invalid",
    ],
)
def test_rejects_invalid_trusted_origins(origin: str) -> None:
    with pytest.raises((ValidationError, ValueError)):
        make(trusted_origins=(origin,))


def test_rejects_duplicate_canonical_origins() -> None:
    with pytest.raises(ValidationError, match="duplicates"):
        make(trusted_origins=("https://example.com", "https://EXAMPLE.com:443/"))


def test_cookie_security_invariants() -> None:
    with pytest.raises(ValidationError, match="SameSite=None"):
        make(cookie_same_site="none")
    with pytest.raises(ValidationError, match="cannot set Domain"):
        make(cookie_use_host_prefix=True, cookie_domain="example.com", secure_cookies=True)
    with pytest.raises(ValidationError, match="Path=/"):
        make(cookie_use_host_prefix=True, cookie_path="/auth", secure_cookies=True)
    with pytest.raises(ValidationError, match="different"):
        make(refresh_cookie_name="same", csrf_cookie_name="same")
    with pytest.raises(ValidationError, match="different"):
        make(email_link_cookie_name="epok_refresh")


def test_host_cookie_names_are_derived_without_double_prefix() -> None:
    settings = make(
        secure_cookies=True,
        cookie_use_host_prefix=True,
        refresh_cookie_name="__Host-refresh",
        csrf_cookie_name="csrf",
    )
    assert settings.effective_refresh_cookie_name == "__Host-refresh"
    assert settings.effective_csrf_cookie_name == "__Host-csrf"


def test_rejects_invalid_http_names_and_paths() -> None:
    with pytest.raises(ValidationError):
        make(csrf_header_name="bad header")
    with pytest.raises(ValidationError):
        make(cookie_path="auth")
    with pytest.raises(ValidationError):
        make(cookie_path="/auth\n")


def test_rejects_invalid_capability_defaults() -> None:
    with pytest.raises(ValidationError):
        make(admin_role="Admin User")
    with pytest.raises(ValidationError):
        make(default_user_role="")


@pytest.mark.parametrize(
    "field,value",
    [
        ("issuer", "   "),
        ("audience", "api\ncontrol"),
        ("google_client_id", "not-a-google-client"),
        ("google_client_id", "client id.apps.googleusercontent.com"),
    ],
)
def test_rejects_ambiguous_identity_configuration(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        make(**{field: value})


@pytest.mark.parametrize(
    "rp_id",
    [
        "https://example.com",
        "example.com:443",
        "example.com/path",
        "-example.com",
        "example..com",
        "example.com.\0",
    ],
)
def test_rejects_invalid_passkey_rp_ids(rp_id: str) -> None:
    with pytest.raises(ValidationError):
        make(passkey_rp_id=rp_id)


def test_normalizes_passkey_identity() -> None:
    settings = make(passkey_rp_id="LOGIN.Example.COM.", passkey_rp_name="  Colors  ")

    assert settings.passkey_rp_id == "login.example.com"
    assert settings.effective_passkey_rp_name == "Colors"

    with pytest.raises(ValidationError, match="printable"):
        make(passkey_rp_name="  ")


def test_production_fails_closed() -> None:
    base = {
        "environment": Environment.PRODUCTION,
        "jwt_secret": SECRET,
        "issuer": "colors-auth",
        "audience": "colors-api",
        "database_url": "postgresql://user:pass@db/colors",
        "trusted_origins": ("https://colors.example.com",),
    }
    settings = AuthSettings(**base)
    assert settings.secure_cookies
    assert settings.effective_refresh_cookie_name.startswith("__Host-")

    for override in (
        {"database_url": None},
        {"issuer": "epok-auth"},
        {"audience": "epok-auth-api"},
        {"secure_cookies": False, "cookie_use_host_prefix": False},
        {"cookie_use_host_prefix": False},
        {"require_origin": False},
        {"trusted_origins": ()},
        {"password_min_length": 12},
    ):
        values = dict(base)
        values.update(override)
        with pytest.raises(ValidationError):
            AuthSettings(**values)


def test_environment_values_are_stable() -> None:
    assert {item.value for item in Environment} == {"development", "test", "production"}


def test_email_link_urls_are_normalized_and_bound_to_trusted_origins() -> None:
    settings = make(
        trusted_origins=("https://app.example.com", "http://[::1]:3000"),
        email_link_login_url="HTTPS://APP.EXAMPLE.COM:443/login/",
        email_link_password_reset_url="https://app.example.com/reset",
        email_link_invitation_url="https://app.example.com/invitation",
    )

    assert settings.email_link_login_url == "https://app.example.com/login"
    assert settings.effective_email_link_cookie_name == "epok_email_link"
    assert settings.trusted_origins[-1] == "http://[::1]:3000"


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/login",
        "https://user:password@example.com/login",
        "https://example.com/login?token=bad",
        "https://example.com/login#token=bad",
        "https://example.com:invalid/login",
        "not-a-url",
    ],
)
def test_rejects_unsafe_email_link_urls(url: str) -> None:
    with pytest.raises(ValidationError):
        make(
            trusted_origins=("https://example.com",),
            email_link_login_url=url,
            email_link_password_reset_url="https://example.com/reset",
            email_link_invitation_url="https://example.com/invitation",
        )


def test_email_link_configuration_is_complete_trusted_and_retained() -> None:
    with pytest.raises(ValidationError, match="all email link"):
        make(email_link_login_url="http://localhost:3000/login")
    with pytest.raises(ValidationError, match="trusted origins"):
        make(
            email_link_login_url="https://app.example.com/login",
            email_link_password_reset_url="https://app.example.com/reset",
            email_link_invitation_url="https://app.example.com/invitation",
        )
    with pytest.raises(ValidationError, match="retention"):
        make(
            email_link_login_url="http://localhost:3000/login",
            email_link_password_reset_url="http://localhost:3000/reset",
            email_link_invitation_url="http://localhost:3000/invitation",
            email_link_invitation_ttl_seconds=600,
            email_link_retention_seconds=300,
        )
