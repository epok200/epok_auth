import smtplib
from datetime import UTC, datetime
from email.message import EmailMessage
from typing import ClassVar

import pytest
from pydantic import ValidationError

from epok_auth.email_links.models import AuthEmail, AuthEmailKind
from epok_auth.email_links.smtp import (
    SmtpEmailSender,
    SmtpSecurity,
    SmtpSettings,
    render_auth_email,
)
from epok_auth.errores import AuthError, AuthErrorCode


class FakeSmtp:
    instances: ClassVar[list["FakeSmtp"]] = []
    fail: ClassVar[bool] = False

    def __init__(self, host: str, port: int, **kwargs: object) -> None:
        self.host = host
        self.port = port
        self.kwargs = kwargs
        self.ehlo_calls = 0
        self.started_tls = False
        self.login_credentials: tuple[str, str] | None = None
        self.message: EmailMessage | None = None
        type(self).instances.append(self)

    def __enter__(self) -> "FakeSmtp":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def ehlo(self) -> None:
        self.ehlo_calls += 1

    def starttls(self, *, context: object) -> None:
        assert context is not None
        self.started_tls = True

    def login(self, username: str, password: str) -> None:
        self.login_credentials = (username, password)

    def send_message(self, message: EmailMessage) -> None:
        if self.fail:
            raise smtplib.SMTPException("provider secret detail")
        self.message = message


@pytest.fixture(autouse=True)
def reset_fake_smtp() -> None:
    FakeSmtp.instances.clear()
    FakeSmtp.fail = False


def settings(**overrides: object) -> SmtpSettings:
    values: dict[str, object] = {
        "host": "smtp.example.com",
        "from_address": "security@example.com",
        "username": "mailer@example.com",
        "password": "app-password-secret",
        "app_name": "Epok Security",
    }
    values.update(overrides)
    return SmtpSettings(**values)  # type: ignore[arg-type]


def login_email() -> AuthEmail:
    return AuthEmail(
        recipient="person@example.com",
        kind=AuthEmailKind.LOGIN,
        action_url="https://app.example.com/login#token=abc&next=safe",
        expires_at=datetime(2026, 8, 24, 12, 0, tzinfo=UTC),
    )


def test_renderer_builds_plain_and_escaped_html_without_secret_repr() -> None:
    configured = settings()
    message = render_auth_email(login_email(), configured)
    html_body = message.get_body(preferencelist=("html",))

    assert message["Subject"] == "Sign in to Epok Security"
    assert message["To"] == "person@example.com"
    assert "#token=abc&next=safe" in message.get_body(preferencelist=("plain",)).get_content()
    assert html_body is not None
    assert "#token=abc&amp;next=safe" in html_body.get_content()
    assert "app-password-secret" not in repr(configured)
    assert "abc" not in repr(login_email())
    assert "person@example.com" not in repr(login_email())


def test_renderer_supports_every_authentication_email_kind() -> None:
    configured = settings()
    for kind, expected in (
        (AuthEmailKind.LOGIN, "Sign in"),
        (AuthEmailKind.PASSWORD_RESET, "Reset"),
        (AuthEmailKind.INVITATION, "Activate"),
        (AuthEmailKind.PASSWORD_CHANGED, "password changed"),
    ):
        message = render_auth_email(
            AuthEmail(recipient="person@example.com", kind=kind),
            configured,
        )
        assert expected.casefold() in str(message["Subject"]).casefold()


@pytest.mark.parametrize(
    ("security", "smtp_class", "started_tls", "ehlo_calls"),
    [
        (SmtpSecurity.STARTTLS, "SMTP", True, 2),
        (SmtpSecurity.TLS, "SMTP_SSL", False, 0),
        (SmtpSecurity.NONE, "SMTP", False, 1),
    ],
)
async def test_sender_uses_expected_smtp_security_mode(
    monkeypatch: pytest.MonkeyPatch,
    security: SmtpSecurity,
    smtp_class: str,
    started_tls: bool,
    ehlo_calls: int,
) -> None:
    monkeypatch.setattr(smtplib, smtp_class, FakeSmtp)
    host = "localhost" if security is SmtpSecurity.NONE else "smtp.example.com"
    configured = settings(host=host, security=security)

    await SmtpEmailSender(configured).send(login_email())

    client = FakeSmtp.instances[-1]
    assert client.started_tls is started_tls
    assert client.ehlo_calls == ehlo_calls
    assert client.login_credentials == ("mailer@example.com", "app-password-secret")
    assert client.message is not None
    if security is SmtpSecurity.TLS:
        assert "context" in client.kwargs


async def test_sender_translates_provider_failure_without_exposing_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(smtplib, "SMTP", FakeSmtp)
    FakeSmtp.fail = True

    with pytest.raises(AuthError) as captured:
        await SmtpEmailSender(settings()).send(login_email())

    assert captured.value.code is AuthErrorCode.EMAIL_DELIVERY_FAILED
    assert "provider secret detail" not in str(captured.value)
    assert captured.value.__suppress_context__ is True


async def test_sender_supports_unauthenticated_local_smtp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(smtplib, "SMTP", FakeSmtp)
    configured = settings(
        host="localhost",
        username=None,
        password=None,
        security=SmtpSecurity.NONE,
    )

    await SmtpEmailSender(configured).send(login_email())

    assert FakeSmtp.instances[-1].login_credentials is None
    assert FakeSmtp.instances[-1].message is not None


def test_smtp_settings_fail_closed_for_credentials_and_cleartext() -> None:
    with pytest.raises(ValidationError, match="configured together"):
        settings(password=None)
    with pytest.raises(ValidationError, match="only for local"):
        settings(security=SmtpSecurity.NONE)
    with pytest.raises(ValidationError, match="URL scheme"):
        settings(host="https://smtp.example.com")
    with pytest.raises(ValidationError, match="printable"):
        settings(app_name="   ")


def test_smtp_settings_load_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EPOK_AUTH_SMTP_HOST", "smtp.gmail.com")
    monkeypatch.setenv("EPOK_AUTH_SMTP_FROM_ADDRESS", "person@gmail.com")
    monkeypatch.setenv("EPOK_AUTH_SMTP_USERNAME", "person@gmail.com")
    monkeypatch.setenv("EPOK_AUTH_SMTP_PASSWORD", "gmail-app-password")
    configured = SmtpSettings.from_env()

    assert configured.host == "smtp.gmail.com"
    assert configured.username == "person@gmail.com"
    assert configured.password is not None
    assert configured.password.get_secret_value() == "gmail-app-password"
    assert "gmail-app-password" not in repr(configured)
