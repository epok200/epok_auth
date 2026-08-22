from epok_auth._service_sessions import SessionServiceMethods
from epok_auth._service_users import UserServiceMethods
from epok_auth._validation import (
    canonical_origin,
    normalize_capabilities,
    normalize_display_name,
    normalize_email,
    normalize_email_for_login,
)


class AuthService(UserServiceMethods, SessionServiceMethods):
    """Identity administration and PostgreSQL-authoritative sessions."""


__all__ = [
    "AuthService",
    "canonical_origin",
    "normalize_capabilities",
    "normalize_display_name",
    "normalize_email",
    "normalize_email_for_login",
]
