import re
from collections.abc import Sequence
from urllib.parse import urlsplit

from email_validator import EmailNotValidError, validate_email

from epok_auth.errores import AuthError, AuthErrorCode

_CAPABILITY = re.compile(r"[a-z0-9][a-z0-9:._-]{0,99}")


def normalize_email(value: str) -> str:
    try:
        normalized = validate_email(value.strip(), check_deliverability=False).normalized
    except EmailNotValidError as error:
        raise AuthError(
            AuthErrorCode.INPUT_INVALID, "Email is not valid.", status_code=422
        ) from error
    return normalized.casefold()


def normalize_email_for_login(value: str) -> str:
    try:
        return normalize_email(value)
    except AuthError:
        return value.strip().casefold()[:320]


def normalize_display_name(value: str) -> str:
    normalized = " ".join(value.split())
    if not 1 <= len(normalized) <= 200 or any(ord(character) < 32 for character in normalized):
        raise AuthError(AuthErrorCode.INPUT_INVALID, "Display name is not valid.", status_code=422)
    return normalized


def normalize_capabilities(values: Sequence[str], *, maximum: int) -> tuple[str, ...]:
    if len(values) > maximum:
        raise AuthError(AuthErrorCode.INPUT_INVALID, "Too many capabilities.", status_code=422)
    if any(not value.strip() for value in values):
        raise AuthError(
            AuthErrorCode.INPUT_INVALID, "Capability syntax is not valid.", status_code=422
        )
    normalized = tuple(sorted({value.strip().casefold() for value in values}))
    if any(_CAPABILITY.fullmatch(value) is None for value in normalized):
        raise AuthError(
            AuthErrorCode.INPUT_INVALID, "Capability syntax is not valid.", status_code=422
        )
    return normalized


def canonical_origin(origin: str) -> str:
    try:
        parsed = urlsplit(origin.strip().rstrip("/"))
        host = (parsed.hostname or "").casefold()
        scheme = parsed.scheme.casefold()
        port = parsed.port
    except ValueError:
        return ""
    if (
        scheme not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        return ""
    default_port = (scheme == "https" and port in (None, 443)) or (
        scheme == "http" and port in (None, 80)
    )
    return f"{scheme}://{host}" if default_port else f"{scheme}://{host}:{port}"
