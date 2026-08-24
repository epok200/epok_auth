from dataclasses import dataclass

from epok_auth.config import AuthSettings, GoogleAccountMode
from epok_auth.google.adapter import GoogleTokenVerifier
from epok_auth.google.models import GoogleClaims
from epok_auth.google.service import GoogleLoginService
from epok_auth.service import AuthService
from epok_auth.testing import MemoryAuthStore
from tests.conftest import MutableClock

CLIENT_ID = "123456789-test.apps.googleusercontent.com"
ORIGIN = "http://localhost:3000"


class FakeGoogleVerifier(GoogleTokenVerifier):
    def __init__(self) -> None:
        self.results: dict[str, GoogleClaims | Exception] = {}
        self.calls: list[tuple[str, str]] = []

    def add(self, credential: str, result: GoogleClaims | Exception) -> None:
        self.results[credential] = result

    def verify(self, credential: str, *, audience: str, nonce: str) -> GoogleClaims:
        self.calls.append((audience, nonce))
        result = self.results[credential]
        if isinstance(result, Exception):
            raise result
        return result


@dataclass(slots=True)
class GoogleHarness:
    settings: AuthSettings
    store: MemoryAuthStore
    auth: AuthService
    google: GoogleLoginService
    verifier: FakeGoogleVerifier


def create_harness(
    settings: AuthSettings,
    store: MemoryAuthStore,
    clock: MutableClock,
    *,
    mode: GoogleAccountMode = GoogleAccountMode.LINKED_ONLY,
    hosted_domains: tuple[str, ...] = (),
    max_credential_chars: int = 8192,
) -> GoogleHarness:
    configured = settings.model_copy(
        update={
            "google_client_id": CLIENT_ID,
            "google_account_mode": mode,
            "google_hosted_domains": hosted_domains,
            "google_max_credential_chars": max_credential_chars,
        }
    )
    auth = AuthService(store=store, settings=configured, clock=clock)
    verifier = FakeGoogleVerifier()
    google = GoogleLoginService(
        store=store,
        settings=configured,
        signer=auth.signer,
        verifier=verifier,
        passwords=auth.passwords,
        clock=clock,
    )
    return GoogleHarness(configured, store, auth, google, verifier)


def claims(
    *,
    subject: str = "google-subject-1",
    email: str | None = "person@gmail.com",
    verified: bool = True,
    hosted_domain: str | None = None,
    display_name: str | None = "Google Person",
    issuer: str = "https://accounts.google.com",
) -> GoogleClaims:
    return GoogleClaims(
        issuer=issuer,
        subject=subject,
        email=email,
        email_verified=verified,
        hosted_domain=hosted_domain,
        display_name=display_name,
    )
