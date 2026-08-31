import secrets
from datetime import datetime

from epok_auth.config import AuthSettings
from epok_auth.email_links.models import EmailLink, EmailLinkPurpose, EmailLinkState
from epok_auth.errores import AuthError, AuthErrorCode
from epok_auth.models import UserAccount, UserStatus
from epok_auth.tokens import token_hash


def require_standard_urls(settings: AuthSettings) -> None:
    if not all(
        (
            settings.email_link_login_url,
            settings.email_link_password_reset_url,
            settings.email_link_invitation_url,
        )
    ):
        raise ValueError("email link frontend URLs are required when email links are enabled")


def require_email_link_url(settings: AuthSettings) -> None:
    if not any(
        (
            settings.email_link_activation_url,
            settings.email_link_login_url,
            settings.email_link_password_reset_url,
            settings.email_link_invitation_url,
        )
    ):
        raise ValueError("an email link frontend URL is required")


def require_activation_url(settings: AuthSettings) -> None:
    if settings.email_link_activation_url is None:
        raise ValueError("email_link_activation_url is required for account activation")


def email_link_url(settings: AuthSettings, purpose: EmailLinkPurpose) -> str:
    if purpose is EmailLinkPurpose.ACTIVATION:
        url = settings.email_link_activation_url
    elif purpose is EmailLinkPurpose.LOGIN:
        url = settings.email_link_login_url
    elif purpose is EmailLinkPurpose.PASSWORD_RESET:
        url = settings.email_link_password_reset_url
    else:
        url = settings.email_link_invitation_url
    if url is None:
        raise ValueError(f"{purpose.value} email link URL is not configured")
    return url


def email_link_ttl(settings: AuthSettings, purpose: EmailLinkPurpose) -> int:
    if purpose is EmailLinkPurpose.ACTIVATION:
        return settings.email_link_activation_ttl_seconds
    if purpose is EmailLinkPurpose.LOGIN:
        return settings.email_link_login_ttl_seconds
    if purpose is EmailLinkPurpose.PASSWORD_RESET:
        return settings.email_link_password_reset_ttl_seconds
    return settings.email_link_invitation_ttl_seconds


def can_request(
    settings: AuthSettings,
    user: UserAccount,
    purpose: EmailLinkPurpose,
    now: datetime,
) -> bool:
    if purpose is EmailLinkPurpose.ACTIVATION:
        return user.status is UserStatus.PENDING_ACTIVATION
    if settings.admin_role in user.roles:
        return False
    if purpose is EmailLinkPurpose.LOGIN:
        return (
            user.can_authenticate(now)
            and user.email_link_login_enabled
            and not user.must_change_password
        )
    if purpose is EmailLinkPurpose.PASSWORD_RESET:
        return user.status is UserStatus.ACTIVE and user.password_login_enabled
    return user.status is UserStatus.ACTIVE and user.must_change_password


def deliverable_link(
    settings: AuthSettings,
    link: EmailLink | None,
    latest: EmailLink | None,
    user: UserAccount | None,
    now: datetime,
) -> EmailLink | None:
    if link is None or latest is None or user is None:
        return None
    can_deliver = (
        link.state is EmailLinkState.PENDING
        and link.id == latest.id
        and link.expires_at > now
        and link.security_version == user.security_version
        and secrets.compare_digest(link.recipient_hash, token_hash(user.email))
        and can_request(settings, user, link.purpose, now)
    )
    return link if can_deliver else None


def matches_user(
    settings: AuthSettings,
    link: EmailLink,
    user: UserAccount,
    now: datetime,
) -> bool:
    return (
        link.state is EmailLinkState.ACTIVE
        and link.expires_at > now
        and link.security_version == user.security_version
        and secrets.compare_digest(link.recipient_hash, token_hash(user.email))
        and can_request(settings, user, link.purpose, now)
    )


def valid_browser(link: EmailLink, browser_nonce: str | None) -> bool:
    if link.browser_hash is None or browser_nonce is None:
        return False
    return secrets.compare_digest(link.browser_hash, token_hash(browser_nonce))


def login_nonce(existing: str | None) -> str:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    if existing and len(existing) == 43 and all(character in allowed for character in existing):
        return existing
    return secrets.token_urlsafe(32)


def invalid_email_link() -> AuthError:
    return AuthError(
        AuthErrorCode.EMAIL_LINK_INVALID,
        "The email link is invalid or expired.",
    )
