import asyncio
import html
import smtplib
import ssl
from collections.abc import Callable
from email.message import EmailMessage
from email.utils import formataddr
from enum import StrEnum
from typing import Protocol, Self

from pydantic import EmailStr, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from epok_auth.email_links.models import AuthEmail, AuthEmailKind
from epok_auth.errores import AuthError, AuthErrorCode, Severidad

type EmailRenderer = Callable[[AuthEmail, "SmtpSettings"], EmailMessage]


class SmtpSecurity(StrEnum):
    STARTTLS = "starttls"
    TLS = "tls"
    NONE = "none"


class SmtpSettings(BaseSettings):
    """SMTP configuration loaded from EPOK_AUTH_SMTP_* variables."""

    model_config = SettingsConfigDict(
        env_prefix="EPOK_AUTH_SMTP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=587, ge=1, le=65535)
    username: str | None = Field(default=None, min_length=1, max_length=320)
    password: SecretStr | None = Field(default=None, repr=False)
    from_address: EmailStr
    app_name: str = Field(default="Epok", min_length=1, max_length=100)
    security: SmtpSecurity = SmtpSecurity.STARTTLS
    timeout_seconds: float = Field(default=10.0, gt=0, le=60)

    @classmethod
    def from_env(cls) -> Self:
        return cls()  # type: ignore[call-arg]

    @field_validator("host", "app_name")
    @classmethod
    def validate_printable_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(ord(character) < 32 for character in normalized):
            raise ValueError("must contain printable text")
        if "://" in normalized:
            raise ValueError("host must not contain a URL scheme")
        return normalized

    @model_validator(mode="after")
    def validate_credentials(self) -> Self:
        if (self.username is None) != (self.password is None):
            raise ValueError("SMTP username and password must be configured together")
        if self.security is SmtpSecurity.NONE and self.host not in {
            "localhost",
            "127.0.0.1",
            "::1",
        }:
            raise ValueError("unencrypted SMTP is allowed only for local development")
        return self


class EmailLinkSender(Protocol):
    async def send(self, email: AuthEmail) -> None: ...


class SmtpEmailSender:
    """Sends authentication email through SMTP without blocking the event loop."""

    def __init__(
        self,
        settings: SmtpSettings,
        renderer: EmailRenderer | None = None,
    ) -> None:
        self.settings = settings
        self.renderer = renderer or render_auth_email

    async def send(self, email: AuthEmail) -> None:
        message = self.renderer(email, self.settings)
        try:
            await asyncio.to_thread(self._send, message)
        except (OSError, smtplib.SMTPException):
            raise AuthError(
                AuthErrorCode.EMAIL_DELIVERY_FAILED,
                "The authentication email provider did not accept the message.",
                severity=Severidad.ERROR,
            ) from None

    def _send(self, message: EmailMessage) -> None:
        settings = self.settings
        context = ssl.create_default_context()
        if settings.security is SmtpSecurity.TLS:
            with smtplib.SMTP_SSL(
                settings.host,
                settings.port,
                timeout=settings.timeout_seconds,
                context=context,
            ) as client:
                self._authenticate_and_send(client, message)
            return

        with smtplib.SMTP(
            settings.host,
            settings.port,
            timeout=settings.timeout_seconds,
        ) as client:
            client.ehlo()
            if settings.security is SmtpSecurity.STARTTLS:
                client.starttls(context=context)
                client.ehlo()
            self._authenticate_and_send(client, message)

    def _authenticate_and_send(
        self,
        client: smtplib.SMTP,
        message: EmailMessage,
    ) -> None:
        if self.settings.username is not None and self.settings.password is not None:
            client.login(
                self.settings.username,
                self.settings.password.get_secret_value(),
            )
        client.send_message(message)


def render_auth_email(email: AuthEmail, settings: SmtpSettings) -> EmailMessage:
    subject, instruction = _email_copy(email.kind, settings.app_name)
    action = ""
    html_action = ""
    if email.action_url is not None:
        action = f"\n\nOpen this secure link:\n{email.action_url}"
        safe_url = html.escape(email.action_url, quote=True)
        html_action = f'<p><a href="{safe_url}">Continue securely</a></p>'
    expiry = ""
    html_expiry = ""
    if email.expires_at is not None:
        expiry = f"\n\nThis link expires at {email.expires_at.isoformat()}."
        html_expiry = f"<p>This link expires at {html.escape(email.expires_at.isoformat())}.</p>"

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = formataddr((settings.app_name, str(settings.from_address)))
    message["To"] = email.recipient
    message.set_content(f"{instruction}{action}{expiry}\n\nIf you did not request this, ignore it.")
    message.add_alternative(
        "<html><body>"
        f"<p>{html.escape(instruction)}</p>"
        f"{html_action}{html_expiry}"
        "<p>If you did not request this, ignore it.</p>"
        "</body></html>",
        subtype="html",
    )
    return message


def _email_copy(kind: AuthEmailKind, app_name: str) -> tuple[str, str]:
    if kind is AuthEmailKind.LOGIN:
        return f"Sign in to {app_name}", f"Use this link to sign in to {app_name}."
    if kind is AuthEmailKind.PASSWORD_RESET:
        return f"Reset your {app_name} password", "Use this link to reset your password."
    if kind is AuthEmailKind.INVITATION:
        return f"Activate your {app_name} account", f"Activate your {app_name} account."
    return f"Your {app_name} password changed", "Your password was changed successfully."
