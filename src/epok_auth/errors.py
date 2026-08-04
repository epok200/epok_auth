from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AuthErrorCode(StrEnum):
    INVALID_CREDENTIALS = "AUTH_INVALID_CREDENTIALS"
    INVALID_TOKEN = "AUTH_TOKEN_INVALID"
    INVALID_CSRF = "AUTH_CSRF_INVALID"
    INVALID_ORIGIN = "AUTH_ORIGIN_INVALID"
    PASSWORD_INVALID = "AUTH_PASSWORD_INVALID"
    PASSWORD_CHANGE_REQUIRED = "AUTH_PASSWORD_CHANGE_REQUIRED"
    FORBIDDEN = "AUTH_FORBIDDEN"
    USER_NOT_FOUND = "AUTH_USER_NOT_FOUND"
    USER_EXISTS = "AUTH_USER_EXISTS"
    ADMIN_EXISTS = "AUTH_ADMIN_EXISTS"
    LAST_ADMIN_REQUIRED = "AUTH_LAST_ADMIN_REQUIRED"
    INPUT_INVALID = "AUTH_INPUT_INVALID"
    REFRESH_CONFLICT = "AUTH_REFRESH_CONFLICT"
    CONFIG_INVALID = "AUTH_CONFIG_INVALID"


@dataclass(eq=False, slots=True)
class AuthError(Exception):
    code: AuthErrorCode
    detail: str
    status_code: int = 400
    headers: dict[str, str] | None = None

    def __str__(self) -> str:
        return self.detail


def invalid_credentials() -> AuthError:
    return AuthError(
        AuthErrorCode.INVALID_CREDENTIALS,
        "The email or password is not valid.",
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
    )


def invalid_session() -> AuthError:
    return AuthError(
        AuthErrorCode.INVALID_TOKEN,
        "The session is not valid.",
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
    )


def invalid_csrf() -> AuthError:
    return AuthError(AuthErrorCode.INVALID_CSRF, "CSRF protection failed.", status_code=403)


def forbidden(detail: str = "You are not allowed to perform this operation.") -> AuthError:
    return AuthError(AuthErrorCode.FORBIDDEN, detail, status_code=403)
