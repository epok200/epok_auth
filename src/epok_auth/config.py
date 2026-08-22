import re
import secrets
from enum import StrEnum
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


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
_CAPABILITY = re.compile(r"[a-z0-9][a-z0-9:._-]{0,99}")


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
        normalized = value.strip().casefold()
        if _CAPABILITY.fullmatch(normalized) is None:
            raise ValueError("roles must use lowercase capability syntax")
        return normalized

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
            default_port = (scheme == "https" and parsed.port in (None, 443)) or (
                scheme == "http" and parsed.port in (None, 80)
            )
            canonical = f"{scheme}://{host}" if default_port else f"{scheme}://{host}:{parsed.port}"
            normalized.append(canonical)
        if len(normalized) != len(set(normalized)):
            raise ValueError("trusted_origins must not contain duplicates")
        return tuple(normalized)

    @field_validator("passkey_rp_id")
    @classmethod
    def normalize_passkey_rp_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        candidate = value.strip().rstrip(".").casefold()
        if not candidate or "://" in candidate or any(mark in candidate for mark in "/:#?@"):
            raise ValueError("passkey_rp_id must be a domain without scheme, port or path")
        try:
            normalized = candidate.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise ValueError("passkey_rp_id must be a valid domain") from error
        labels = normalized.split(".")
        if len(normalized) > 253 or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or re.fullmatch(r"[a-z0-9-]+", label) is None
            for label in labels
        ):
            raise ValueError("passkey_rp_id must be a valid domain")
        return normalized

    @field_validator("passkey_rp_name")
    @classmethod
    def normalize_passkey_rp_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped or any(ord(character) < 32 for character in stripped):
            raise ValueError("passkey_rp_name must be printable text")
        return stripped

    @field_validator("refresh_cookie_name", "csrf_cookie_name", "csrf_header_name")
    @classmethod
    def validate_http_name(cls, value: str) -> str:
        stripped = value.strip()
        if _HTTP_TOKEN.fullmatch(stripped) is None:
            raise ValueError("cookie and header names must use valid HTTP token characters")
        return stripped

    @model_validator(mode="after")
    def validate_security_invariants(self) -> Self:
        secret = self.jwt_secret.get_secret_value()
        stripped_secret = secret.strip()
        if secret != stripped_secret or any(ord(character) < 32 for character in secret):
            raise ValueError("jwt_secret must not contain surrounding or control whitespace")
        if len(secret.encode()) < 32:
            raise ValueError("jwt_secret must contain at least 32 bytes")
        if secret.casefold() in _UNSAFE_SECRETS or len(set(secret)) < 8:
            raise ValueError("jwt_secret is a weak or public example value")
        if self.access_ttl_seconds >= self.refresh_idle_ttl_seconds:
            raise ValueError("access TTL must be shorter than refresh idle TTL")
        if self.refresh_idle_ttl_seconds > self.refresh_absolute_ttl_seconds:
            raise ValueError("refresh idle TTL cannot exceed the absolute session TTL")
        if self.password_min_length > self.password_max_length:
            raise ValueError("password_min_length cannot exceed password_max_length")
        if self.effective_refresh_cookie_name == self.effective_csrf_cookie_name:
            raise ValueError("refresh and CSRF cookie names must be different")
        if self.cookie_same_site == "none" and not self.secure_cookies:
            raise ValueError("SameSite=None cookies require Secure")
        if self.cookie_use_host_prefix:
            if self.cookie_domain is not None:
                raise ValueError("__Host- cookies cannot set Domain")
            if self.cookie_path != "/":
                raise ValueError("__Host- cookies require Path=/")
        if self.environment is Environment.PRODUCTION:
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
        return self

    @property
    def effective_refresh_cookie_name(self) -> str:
        return self._cookie_name(self.refresh_cookie_name)

    @property
    def effective_csrf_cookie_name(self) -> str:
        return self._cookie_name(self.csrf_cookie_name)

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
