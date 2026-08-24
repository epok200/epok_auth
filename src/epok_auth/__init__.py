from importlib.metadata import PackageNotFoundError, version

from epok_auth.config import AuthSettings, Environment
from epok_auth.email_links import (
    AuthEmail,
    AuthEmailKind,
    EmailLinkDispatcher,
    EmailLinkMailer,
    EmailLinkSender,
    EmailLinkService,
    PendingEmailLink,
    SmtpEmailSender,
    SmtpSecurity,
    SmtpSettings,
)
from epok_auth.errors import AuthError, AuthErrorCode
from epok_auth.fastapi import EpokAuth
from epok_auth.google import GoogleAccountMode, GoogleLoginService
from epok_auth.models import Principal, UserAccount, UserStatus
from epok_auth.passkeys import PasskeyCredential, PasskeyOptions, PasskeyService

try:
    __version__ = version("epok-auth")
except PackageNotFoundError:  # pragma: no cover - direct source checkout without installation
    __version__ = "0.0.0+unknown"

__all__ = [
    "AuthEmail",
    "AuthEmailKind",
    "AuthError",
    "AuthErrorCode",
    "AuthSettings",
    "EmailLinkDispatcher",
    "EmailLinkMailer",
    "EmailLinkSender",
    "EmailLinkService",
    "Environment",
    "EpokAuth",
    "GoogleAccountMode",
    "GoogleLoginService",
    "PasskeyCredential",
    "PasskeyOptions",
    "PasskeyService",
    "PendingEmailLink",
    "Principal",
    "SmtpEmailSender",
    "SmtpSecurity",
    "SmtpSettings",
    "UserAccount",
    "UserStatus",
    "__version__",
]
