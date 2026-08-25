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


def normalize_domain(value: str) -> str:
    candidate = value.strip().rstrip(".").casefold()
    if not candidate or "://" in candidate or any(mark in candidate for mark in "/:#?@"):
        raise ValueError("domain must not contain scheme, port, user info, or path")
    try:
        normalized = candidate.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError("domain is not valid") from error
    labels = normalized.split(".")
    if len(normalized) > 253 or any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or re.fullmatch(r"[a-z0-9-]+", label) is None
        for label in labels
    ):
        raise ValueError("domain is not valid")
    return normalized


def normalize_capability(value: str) -> str:
    normalized = value.strip().casefold()
    if _CAPABILITY.fullmatch(normalized) is None:
        raise ValueError("capability syntax is not valid")
    return normalized


def normalize_capabilities(values: Sequence[str], *, maximum: int) -> tuple[str, ...]:
    if len(values) > maximum:
        raise AuthError(AuthErrorCode.INPUT_INVALID, "Too many capabilities.", status_code=422)
    try:
        normalized = tuple(sorted({normalize_capability(value) for value in values}))
    except ValueError as error:
        raise AuthError(
            AuthErrorCode.INPUT_INVALID, "Capability syntax is not valid.", status_code=422
        ) from error
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
    authority = f"[{host}]" if ":" in host else host
    return f"{scheme}://{authority}" if default_port else f"{scheme}://{authority}:{port}"
