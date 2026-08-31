import re
import secrets
from enum import StrEnum
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from epok_auth._validation import canonical_origin, normalize_capability, normalize_domain


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class GoogleAccountMode(StrEnum):
    LINKED_ONLY = "linked_only"
    PREAUTHORIZED = "preauthorized"
    OPEN = "open"


_UNSAFE_SECRETS = frozenset(
    {
        "change-me",
        "changeme",
        "secret",
        "secret123",
        "your-secret-key",
        "cambia-esto-por-un-secreto-aleatorio-largo",
    }
)
_HTTP_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


class AuthSettings(BaseSettings):
    """Validated configuration loaded from ``EPOK_AUTH_*`` variables."""

    model_config = SettingsConfigDict(
        env_prefix="EPOK_AUTH_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
        validate_default=True,
        enable_decoding=False,
    )

    environment: Environment = Environment.PRODUCTION
    database_url: SecretStr | None = Field(default=None, repr=False)

    issuer: str = Field(default="epok-auth", min_length=1, max_length=200)
    audience: str = Field(default="epok-auth-api", min_length=1, max_length=200)
    jwt_secret: SecretStr = Field(repr=False)
    jwt_algorithm: Literal["HS256"] = "HS256"
    jwt_leeway_seconds: int = Field(default=30, ge=0, le=300)
    max_access_token_chars: int = Field(default=8192, ge=512, le=65536)

    access_ttl_seconds: int = Field(default=15 * 60, ge=60, le=24 * 60 * 60)
    refresh_idle_ttl_seconds: int = Field(default=7 * 24 * 60 * 60, ge=5 * 60, le=90 * 86400)
    refresh_absolute_ttl_seconds: int = Field(default=30 * 24 * 60 * 60, ge=3600, le=365 * 86400)

    login_max_attempts: int = Field(default=5, ge=2, le=100)
    lockout_seconds: int = Field(default=15 * 60, ge=10, le=24 * 60 * 60)

    password_min_length: int = Field(default=15, ge=8, le=128)
    password_max_length: int = Field(default=128, ge=32, le=1024)
    temporary_password_bytes: int = Field(default=24, ge=16, le=64)
    max_roles: int = Field(default=32, ge=1, le=256)
    max_scopes: int = Field(default=256, ge=1, le=2048)

    secure_cookies: bool = True
    csrf_cookie_http_only: bool = True
    cookie_same_site: Literal["lax", "strict", "none"] = "lax"
    cookie_use_host_prefix: bool = True
    cookie_domain: str | None = None
    cookie_path: str = "/"
    refresh_cookie_name: str = "epok_refresh"
    csrf_cookie_name: str = "epok_csrf"
    csrf_header_name: str = "X-CSRF-Token"

    trusted_origins: tuple[str, ...] = ()
    require_origin: bool = True

    passkey_rp_id: str | None = Field(default=None, min_length=1, max_length=253)
    passkey_rp_name: str | None = Field(default=None, min_length=1, max_length=100)
    passkey_challenge_ttl_seconds: int = Field(default=300, ge=60, le=600)
    passkey_timeout_ms: int = Field(default=60_000, ge=15_000, le=300_000)
    passkey_registration_max_age_seconds: int = Field(default=300, ge=0, le=3600)
    passkey_max_credentials_per_user: int = Field(default=10, ge=1, le=50)

    google_client_id: str | None = Field(default=None, min_length=20, max_length=255)
    google_account_mode: GoogleAccountMode = GoogleAccountMode.LINKED_ONLY
    google_hosted_domains: tuple[str, ...] = ()
    google_challenge_ttl_seconds: int = Field(default=300, ge=60, le=600)
    google_link_max_age_seconds: int = Field(default=300, ge=60, le=3600)
    google_token_timeout_seconds: int = Field(default=5, ge=1, le=30)
    google_max_credential_chars: int = Field(default=8192, ge=1024, le=16384)

    email_link_login_url: str | None = None
    email_link_password_reset_url: str | None = None
    email_link_invitation_url: str | None = None
    email_link_activation_url: str | None = None
    email_link_login_ttl_seconds: int = Field(default=10 * 60, ge=60, le=60 * 60)
    email_link_password_reset_ttl_seconds: int = Field(default=15 * 60, ge=60, le=60 * 60)
    email_link_invitation_ttl_seconds: int = Field(default=24 * 60 * 60, ge=300, le=86400)
    email_link_activation_ttl_seconds: int = Field(default=24 * 60 * 60, ge=300, le=86400)
    email_link_request_window_seconds: int = Field(default=15 * 60, ge=60, le=86400)
    email_link_max_requests_per_window: int = Field(default=3, ge=1, le=20)
    email_link_retention_seconds: int = Field(default=7 * 86400, ge=300, le=90 * 86400)
    email_link_max_token_chars: int = Field(default=128, ge=64, le=512)
    email_link_cookie_name: str = "epok_email_link"

    admin_role: str = Field(default="admin", min_length=1, max_length=100)
    default_user_role: str = Field(default="user", min_length=1, max_length=100)

    @field_validator("issuer", "audience")
    @classmethod
    def strip_non_empty(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("must not be empty")
        if any(ord(character) < 32 for character in stripped):
            raise ValueError("must not contain control characters")
        return stripped

    @field_validator("admin_role", "default_user_role")
    @classmethod
    def validate_capability(cls, value: str) -> str:
        try:
            return normalize_capability(value)
        except ValueError as error:
            raise ValueError("roles must use lowercase capability syntax") from error

    @field_validator("cookie_path")
    @classmethod
    def validate_cookie_path(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("cookie_path must start with '/'")
        if any(ord(character) < 32 for character in value):
            raise ValueError("cookie_path must not contain control characters")
        return value

    @field_validator("trusted_origins", mode="before")
    @classmethod
    def parse_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        return value

    @field_validator("trusted_origins")
    @classmethod
    def normalize_origins(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized: list[str] = []
        for raw in value:
            origin = raw.strip().rstrip("/")
            if not origin:
                continue
            if "*" in origin:
                raise ValueError("trusted_origins cannot contain wildcards")
            parsed = urlsplit(origin)
            host = (parsed.hostname or "").casefold()
            if (
                not parsed.scheme
                or not host
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in ("", "/")
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("trusted_origins must be scheme-and-host origins without paths")
            scheme = parsed.scheme.casefold()
            local = host in {"localhost", "127.0.0.1", "::1"}
            if scheme != "https" and not (scheme == "http" and local):
                raise ValueError("trusted origins must use HTTPS, except localhost origins")
            canonical = canonical_origin(origin)
            if not canonical:
                raise ValueError("trusted_origins must contain valid ports")
            normalized.append(canonical)
        if len(normalized) != len(set(normalized)):
            raise ValueError("trusted_origins must not contain duplicates")
        return tuple(normalized)

    @field_validator("passkey_rp_id")
    @classmethod
    def normalize_passkey_rp_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            return normalize_domain(value)
        except ValueError as error:
            raise ValueError("passkey_rp_id must be a valid domain") from error

    @field_validator("passkey_rp_name")
    @classmethod
    def normalize_passkey_rp_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped or any(ord(character) < 32 for character in stripped):
            raise ValueError("passkey_rp_name must be printable text")
        return stripped

    @field_validator("google_client_id")
    @classmethod
    def normalize_google_client_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized.endswith(".apps.googleusercontent.com") or any(
            ord(character) < 33 for character in normalized
        ):
            raise ValueError("google_client_id must be a Google OAuth web client ID")
        return normalized

    @field_validator("google_hosted_domains", mode="before")
    @classmethod
    def parse_google_hosted_domains(cls, value: object) -> object:
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        return value

    @field_validator("google_hosted_domains")
    @classmethod
    def normalize_google_hosted_domains(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        try:
            normalized = tuple(normalize_domain(item) for item in value)
        except ValueError as error:
            raise ValueError("google_hosted_domains must contain valid domains") from error
        if len(normalized) != len(set(normalized)):
            raise ValueError("google_hosted_domains must not contain duplicates")
        return normalized

    @field_validator(
        "refresh_cookie_name",
        "csrf_cookie_name",
        "csrf_header_name",
        "email_link_cookie_name",
    )
    @classmethod
    def validate_http_name(cls, value: str) -> str:
        stripped = value.strip()
        if _HTTP_TOKEN.fullmatch(stripped) is None:
            raise ValueError("cookie and header names must use valid HTTP token characters")
        return stripped

    @field_validator(
        "email_link_login_url",
        "email_link_password_reset_url",
        "email_link_invitation_url",
        "email_link_activation_url",
    )
    @classmethod
    def validate_email_link_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().rstrip("/")
        try:
            parsed = urlsplit(normalized)
            host = (parsed.hostname or "").casefold()
            port = parsed.port
        except ValueError as error:
            raise ValueError("email link URLs must be valid absolute URLs") from error
        local = host in {"localhost", "127.0.0.1", "::1"}
        if (
            not host
            or parsed.scheme.casefold() not in {"http", "https"}
            or (parsed.scheme.casefold() != "https" and not local)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("email link URLs require HTTPS, except localhost, without query data")
        default_port = (parsed.scheme.casefold() == "https" and port in (None, 443)) or (
            parsed.scheme.casefold() == "http" and port in (None, 80)
        )
        authority = f"[{host}]" if ":" in host else host
        if not default_port:
            authority = f"{authority}:{port}"
        path = parsed.path.rstrip("/")
        return f"{parsed.scheme.casefold()}://{authority}{path}"

    @model_validator(mode="after")
    def validate_security_invariants(self) -> Self:
        self._validate_secret()
        self._validate_lifetimes()
        self._validate_email_links()
        self._validate_google_mode()
        self._validate_cookie_policy()
        self._validate_production()
        return self

    def _validate_secret(self) -> None:
        secret = self.jwt_secret.get_secret_value()
        stripped_secret = secret.strip()
        if secret != stripped_secret or any(ord(character) < 32 for character in secret):
            raise ValueError("jwt_secret must not contain surrounding or control whitespace")
        if len(secret.encode()) < 32:
            raise ValueError("jwt_secret must contain at least 32 bytes")
        if secret.casefold() in _UNSAFE_SECRETS or len(set(secret)) < 8:
            raise ValueError("jwt_secret is a weak or public example value")

    def _validate_lifetimes(self) -> None:
        if self.access_ttl_seconds >= self.refresh_idle_ttl_seconds:
            raise ValueError("access TTL must be shorter than refresh idle TTL")
        if self.refresh_idle_ttl_seconds > self.refresh_absolute_ttl_seconds:
            raise ValueError("refresh idle TTL cannot exceed the absolute session TTL")
        if self.password_min_length > self.password_max_length:
            raise ValueError("password_min_length cannot exceed password_max_length")

    def _validate_email_links(self) -> None:
        email_link_urls = (
            self.email_link_login_url,
            self.email_link_password_reset_url,
            self.email_link_invitation_url,
        )
        if any(email_link_urls) and not all(email_link_urls):
            raise ValueError("all email link frontend URLs must be configured together")
        for url in (*email_link_urls, self.email_link_activation_url):
            if url is None:
                continue
            parsed = urlsplit(url)
            origin = canonical_origin(f"{parsed.scheme}://{parsed.netloc}")
            if origin not in self.trusted_origins:
                raise ValueError("email link frontend origins must be trusted origins")
        minimum_retention = max(
            self.email_link_login_ttl_seconds,
            self.email_link_password_reset_ttl_seconds,
            self.email_link_invitation_ttl_seconds,
            self.email_link_activation_ttl_seconds,
            self.email_link_request_window_seconds,
        )
        if self.email_link_retention_seconds < minimum_retention:
            raise ValueError("email link retention must cover every TTL and rate-limit window")

    def _validate_google_mode(self) -> None:
        if (
            self.google_account_mode is GoogleAccountMode.OPEN
            and self.default_user_role == self.admin_role
        ):
            raise ValueError("open Google accounts cannot receive the administrative role")

    def _validate_cookie_policy(self) -> None:
        if (
            len(
                {
                    self.effective_refresh_cookie_name,
                    self.effective_csrf_cookie_name,
                    self.effective_email_link_cookie_name,
                }
            )
            != 3
        ):
            raise ValueError("authentication cookie names must be different")
        if self.cookie_same_site == "none" and not self.secure_cookies:
            raise ValueError("SameSite=None cookies require Secure")
        if self.cookie_use_host_prefix:
            if self.cookie_domain is not None:
                raise ValueError("__Host- cookies cannot set Domain")
            if self.cookie_path != "/":
                raise ValueError("__Host- cookies require Path=/")

    def _validate_production(self) -> None:
        if self.environment is not Environment.PRODUCTION:
            return
        if self.database_url is None:
            raise ValueError("production requires database_url")
        if self.issuer == "epok-auth" or self.audience == "epok-auth-api":
            raise ValueError("production requires application-specific issuer and audience")
        if not self.secure_cookies:
            raise ValueError("production requires secure cookies")
        if not self.cookie_use_host_prefix:
            raise ValueError("production requires __Host- cookie names")
        if not self.require_origin or not self.trusted_origins:
            raise ValueError("production requires explicit Origin validation")
        if self.password_min_length < 15:
            raise ValueError("production password minimum must be at least 15 characters")

    @property
    def effective_refresh_cookie_name(self) -> str:
        return self._cookie_name(self.refresh_cookie_name)

    @property
    def effective_csrf_cookie_name(self) -> str:
        return self._cookie_name(self.csrf_cookie_name)

    @property
    def effective_email_link_cookie_name(self) -> str:
        return self._cookie_name(self.email_link_cookie_name)

    @property
    def effective_passkey_rp_name(self) -> str:
        return self.passkey_rp_name or self.issuer

    def _cookie_name(self, name: str) -> str:
        clean = name.removeprefix("__Host-")
        return f"__Host-{clean}" if self.cookie_use_host_prefix else clean

    @classmethod
    def development(cls, **overrides: object) -> Self:
        values: dict[str, object] = {
            "environment": Environment.DEVELOPMENT,
            "jwt_secret": secrets.token_urlsafe(48),
            "issuer": "epok-auth-development",
            "audience": "epok-auth-development-api",
            "secure_cookies": False,
            "cookie_use_host_prefix": False,
            "trusted_origins": ("http://localhost:3000", "http://127.0.0.1:3000"),
            "passkey_rp_id": "localhost",
        }
        values.update(overrides)
        return cls(**values)  # type: ignore[arg-type]


def load_auth_settings() -> AuthSettings:
    """Load validated configuration from ``EPOK_AUTH_*`` variables."""
    return AuthSettings()  # pyright: ignore[reportCallIssue]
