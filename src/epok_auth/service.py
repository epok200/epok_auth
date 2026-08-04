from __future__ import annotations

from epok_auth.service_sessions import SessionServiceMixin
from epok_auth.service_users import UserServiceMixin
from epok_auth.service_utils import (
    normalize_capabilities,
    normalize_display_name,
    normalize_email,
    normalize_email_for_login,
)


class AuthService(UserServiceMixin, SessionServiceMixin):
    """Authentication, administrative identity, and revocable session service."""


__all__ = [
    "AuthService",
    "normalize_capabilities",
    "normalize_display_name",
    "normalize_email",
    "normalize_email_for_login",
]
