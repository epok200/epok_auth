from uuid import uuid4

import pytest
from pydantic import ValidationError

from epok_auth.config import AuthSettings, Environment, GoogleAccountMode
from epok_auth.google import GoogleStore, GoogleTransaction
from epok_auth.google.models import GoogleChallenge, GoogleChallengePurpose, GoogleClaims
from epok_auth.google.service import GoogleLoginService
from epok_auth.service import AuthService
from epok_auth.testing import MemoryAuthStore
from tests.conftest import MutableClock
from tests.google.fakes import CLIENT_ID, ORIGIN, FakeGoogleVerifier

SECRET = "google-config-secret-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _settings(**overrides: object) -> AuthSettings:
    values = {
        "environment": Environment.TEST,
        "jwt_secret": SECRET,
        "issuer": "google-config-tests",
        "audience": "google-config-tests-api",
        "secure_cookies": False,
        "cookie_use_host_prefix": False,
        "trusted_origins": (ORIGIN,),
    }
    values.update(overrides)
    return AuthSettings(**values)  # type: ignore[arg-type]


def test_google_store_contracts_are_public() -> None:
    assert GoogleStore is not None
    assert GoogleTransaction is not None


def test_google_defaults_to_linked_only_without_affecting_base_install() -> None:
    settings = _settings()

    assert settings.google_client_id is None
    assert settings.google_account_mode is GoogleAccountMode.LINKED_ONLY
    assert settings.google_hosted_domains == ()


def test_google_service_requires_client_id() -> None:
    settings = _settings()
    store = MemoryAuthStore()
    auth = AuthService(store=store, settings=settings)

    with pytest.raises(ValueError, match="google_client_id"):
        GoogleLoginService(
            store=store,
            settings=settings,
            signer=auth.signer,
            verifier=FakeGoogleVerifier(),
            passwords=auth.passwords,
        )


def test_google_environment_settings_parse_mode_and_hosted_domains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("EPOK_AUTH_ENVIRONMENT", "test")
    monkeypatch.setenv("EPOK_AUTH_JWT_SECRET", SECRET)
    monkeypatch.setenv("EPOK_AUTH_ISSUER", "google-config-tests")
    monkeypatch.setenv("EPOK_AUTH_AUDIENCE", "google-config-tests-api")
    monkeypatch.setenv("EPOK_AUTH_SECURE_COOKIES", "false")
    monkeypatch.setenv("EPOK_AUTH_COOKIE_USE_HOST_PREFIX", "false")
    monkeypatch.setenv("EPOK_AUTH_TRUSTED_ORIGINS", ORIGIN)
    monkeypatch.setenv("EPOK_AUTH_GOOGLE_CLIENT_ID", f"  {CLIENT_ID}  ")
    monkeypatch.setenv("EPOK_AUTH_GOOGLE_ACCOUNT_MODE", "preauthorized")
    monkeypatch.setenv(
        "EPOK_AUTH_GOOGLE_HOSTED_DOMAINS",
        "Company.Example, xn--bcher-kva.example",
    )

    settings = AuthSettings()

    assert settings.google_client_id == CLIENT_ID
    assert settings.google_account_mode is GoogleAccountMode.PREAUTHORIZED
    assert settings.google_hosted_domains == (
        "company.example",
        "xn--bcher-kva.example",
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"google_client_id": "not-a-google-client"},
        {"google_hosted_domains": ("https://company.example",)},
        {"google_hosted_domains": ("company.example", "COMPANY.EXAMPLE")},
    ],
)
def test_google_configuration_rejects_ambiguous_values(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        _settings(**overrides)


def test_open_mode_rejects_the_administrative_default_role() -> None:
    with pytest.raises(ValidationError, match="administrative role"):
        _settings(
            google_account_mode=GoogleAccountMode.OPEN,
            admin_role="member",
            default_user_role="member",
        )


def test_google_sensitive_identity_values_are_hidden_from_dataclass_repr(
    clock: MutableClock,
) -> None:
    challenge = GoogleChallenge(
        id=uuid4(),
        purpose=GoogleChallengePurpose.LOGIN,
        nonce="private-nonce",
        origin=ORIGIN,
        client_id=CLIENT_ID,
        created_at=clock.value,
        expires_at=clock.value,
    )
    google_claims = GoogleClaims(
        issuer="https://accounts.google.com",
        subject="private-subject",
        email="person@gmail.com",
        email_verified=True,
    )

    assert "private-nonce" not in repr(challenge)
    assert "private-subject" not in repr(google_claims)
