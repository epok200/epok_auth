import secrets
from collections.abc import Mapping
from threading import Lock

from cachecontrol import CacheControl
from google.auth.exceptions import GoogleAuthError, TransportError
from google.auth.transport import Response
from google.auth.transport.requests import Request
from google.oauth2 import id_token
from requests import Session

from epok_auth.google.adapter import GoogleServiceUnavailableError, GoogleVerificationError
from epok_auth.google.models import GOOGLE_ISSUER, GoogleClaims


class GoogleAuthVerifier:
    """Verifies Google ID tokens through Google's maintained Python client."""

    def __init__(self, *, timeout_seconds: int = 5, max_credential_chars: int = 8192) -> None:
        self.max_credential_chars = max_credential_chars
        self._transport = _CachedGoogleRequest(timeout_seconds)

    def verify(self, credential: str, *, audience: str, nonce: str) -> GoogleClaims:
        if not credential or len(credential) > self.max_credential_chars:
            raise GoogleVerificationError("Google credential size is invalid")
        try:
            claims = id_token.verify_oauth2_token(  # pyright: ignore[reportUnknownMemberType]
                credential,
                self._transport,
                audience=audience,
            )
        except TransportError as error:
            raise GoogleServiceUnavailableError("Google verification is unavailable") from error
        except (GoogleAuthError, ValueError) as error:
            raise GoogleVerificationError("Google credential verification failed") from error
        return _verified_claims(claims, nonce)

    def close(self) -> None:
        self._transport.close()


class _CachedGoogleRequest:
    def __init__(self, timeout_seconds: int) -> None:
        self.timeout_seconds = timeout_seconds
        session = CacheControl(Session())  # pyright: ignore[reportUnknownVariableType]
        self._session = session  # pyright: ignore[reportUnknownMemberType]
        self._request = Request(session=session)  # pyright: ignore[reportUnknownArgumentType]
        self._lock = Lock()

    def __call__(
        self,
        url: str,
        method: str = "GET",
        body: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: int | None = None,
    ) -> Response:
        del timeout
        with self._lock:
            return self._request(
                url=url,
                method=method,
                body=body,
                headers=headers,
                timeout=self.timeout_seconds,
            )

    def close(self) -> None:
        self._session.close()  # pyright: ignore[reportUnknownMemberType]


def _verified_claims(payload: Mapping[str, object], nonce: str) -> GoogleClaims:
    issuer = payload.get("iss")
    subject = payload.get("sub")
    received_nonce = payload.get("nonce")
    if issuer not in {"accounts.google.com", GOOGLE_ISSUER}:
        raise GoogleVerificationError("Google issuer is invalid")
    if not isinstance(subject, str) or not 1 <= len(subject) <= 255:
        raise GoogleVerificationError("Google subject is invalid")
    if not isinstance(received_nonce, str) or not secrets.compare_digest(received_nonce, nonce):
        raise GoogleVerificationError("Google nonce is invalid")
    return GoogleClaims(
        issuer=GOOGLE_ISSUER,
        subject=subject,
        email=_optional_text(payload, "email", 320),
        email_verified=payload.get("email_verified") is True,
        hosted_domain=_optional_text(payload, "hd", 253),
        display_name=_optional_text(payload, "name", 200),
    )


def _optional_text(payload: Mapping[str, object], name: str, maximum: int) -> str | None:
    value = payload.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise GoogleVerificationError(f"Google {name} claim is invalid")
    return value
