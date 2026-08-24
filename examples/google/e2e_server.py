from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from epok_auth import AuthSettings, EpokAuth, GoogleAccountMode
from epok_auth.google.adapter import GoogleVerificationError
from epok_auth.google.models import GoogleClaims
from epok_auth.google.service import GoogleLoginService
from epok_auth.service import AuthService
from epok_auth.testing import MemoryAuthStore

SANDBOX_ORIGIN = "http://localhost:8766"
CLIENT_ID = "123456789-browser.apps.googleusercontent.com"
EXAMPLE_DIR = Path(__file__).parent


class BrowserProofVerifier:
    def verify(self, credential: str, *, audience: str, nonce: str) -> GoogleClaims:
        if credential != "browser-proof" or audience != CLIENT_ID or not nonce:
            raise GoogleVerificationError("browser proof credential is invalid")
        return GoogleClaims(
            issuer="https://accounts.google.com",
            subject="browser-google-subject",
            email="browser@gmail.com",
            email_verified=True,
            display_name="Browser proof",
        )


settings = AuthSettings.development(
    trusted_origins=(SANDBOX_ORIGIN,),
    google_client_id=CLIENT_ID,
    google_account_mode=GoogleAccountMode.OPEN,
)
store = MemoryAuthStore()
service = AuthService(store=store, settings=settings)
google = GoogleLoginService(
    store=store,
    settings=settings,
    signer=service.signer,
    verifier=BrowserProofVerifier(),
    passwords=service.passwords,
)
auth = EpokAuth(settings=settings, store=store, service=service, google=google)
api_app = FastAPI(title="epok-auth Google browser proof")
auth.install(api_app, prefix="/api/v1/auth", include_google=True)


@api_app.get("/", response_class=FileResponse)
async def sandbox() -> Path:
    return EXAMPLE_DIR / "sandbox.html"


@api_app.get("/sandbox.js", response_class=FileResponse)
async def sandbox_client() -> Path:
    return EXAMPLE_DIR / "sandbox.js"


@api_app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
