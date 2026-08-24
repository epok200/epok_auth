from typing import Protocol

from epok_auth.google.models import GoogleClaims


class GoogleVerificationError(Exception):
    """A Google ID token failed protocol or claim verification."""


class GoogleServiceUnavailableError(Exception):
    """Google verification infrastructure could not be reached."""


class GoogleTokenVerifier(Protocol):
    def verify(self, credential: str, *, audience: str, nonce: str) -> GoogleClaims: ...
