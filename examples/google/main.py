import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from epok_auth import AuthSettings, EpokAuth, GoogleAccountMode
from epok_auth.testing import MemoryAuthStore

SANDBOX_ORIGIN = "http://localhost:8766"
EXAMPLE_DIR = Path(__file__).parent

client_id = os.environ.get("EPOK_AUTH_GOOGLE_CLIENT_ID")
if client_id is None:
    raise RuntimeError("Set EPOK_AUTH_GOOGLE_CLIENT_ID before starting the Google sandbox")

settings = AuthSettings.development(
    trusted_origins=(SANDBOX_ORIGIN,),
    google_client_id=client_id,
    google_account_mode=GoogleAccountMode.OPEN,
)
store = MemoryAuthStore()
auth = EpokAuth(settings=settings, store=store, google_store=store)
app = FastAPI(title="epok-auth Google Sign-In sandbox", lifespan=auth.lifespan)
auth.install(app, prefix="/api/v1/auth", include_google=True)


@app.get("/", response_class=FileResponse)
async def sandbox() -> Path:
    return EXAMPLE_DIR / "sandbox.html"


@app.get("/sandbox.js", response_class=FileResponse)
async def sandbox_client() -> Path:
    return EXAMPLE_DIR / "sandbox.js"


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
