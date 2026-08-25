from dataclasses import replace
from datetime import datetime

from epok_auth._validation import (
    normalize_display_name,
    normalize_domain,
    normalize_email,
)
from epok_auth.config import AuthSettings
from epok_auth.errores import AuthError, invalid_google_credentials
from epok_auth.google.models import GOOGLE_ISSUER, GoogleClaims
from epok_auth.models import Principal, RefreshSession, UserAccount


class GoogleAccountPolicy:
    """Validates Google claims and account admission rules."""

    def __init__(self, settings: AuthSettings) -> None:
        self.hosted_domains = settings.google_hosted_domains

    def validate(self, claims: GoogleClaims) -> GoogleClaims:
        if claims.issuer not in {"accounts.google.com", GOOGLE_ISSUER}:
            raise invalid_google_credentials()
        if not 1 <= len(claims.subject) <= 255:
            raise invalid_google_credentials()

        email = normalize_email(claims.email) if claims.email is not None else None
        hosted_domain = self._hosted_domain(claims.hosted_domain)
        if self.hosted_domains and hosted_domain not in self.hosted_domains:
            raise invalid_google_credentials()
        return replace(
            claims,
            issuer=GOOGLE_ISSUER,
            email=email,
            hosted_domain=hosted_domain,
        )

    @staticmethod
    def is_authoritative(claims: GoogleClaims) -> bool:
        if not claims.email_verified or claims.email is None:
            return False
        return claims.email.endswith("@gmail.com") or claims.hosted_domain is not None

    @staticmethod
    def can_auto_link(
        user: UserAccount | None,
        claims: GoogleClaims,
        now: datetime,
    ) -> bool:
        return (
            user is not None
            and user.can_authenticate(now)
            and user.google_auto_link_allowed
            and user.must_change_password
            and user.email == claims.email
        )

    @staticmethod
    def can_link(
        user: UserAccount | None,
        session: RefreshSession | None,
        principal: Principal,
        now: datetime,
    ) -> bool:
        return (
            user is not None
            and session is not None
            and user.can_authenticate(now)
            and not user.must_change_password
            and session.is_valid_for(principal, now)
        )

    @staticmethod
    def display_name(claims: GoogleClaims) -> str:
        if claims.display_name is not None:
            try:
                return normalize_display_name(claims.display_name)
            except AuthError:
                pass
        if claims.email is None:  # pragma: no cover
            raise ValueError("Google account creation requires an email")
        return normalize_display_name(claims.email.split("@", maxsplit=1)[0])

    @staticmethod
    def _hosted_domain(value: str | None) -> str | None:
        if not value:
            return None
        try:
            return normalize_domain(value)
        except ValueError as error:
            raise invalid_google_credentials() from error
