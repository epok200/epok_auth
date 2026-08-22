from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse

from epok_auth import AuthSettings, EpokAuth
from epok_auth.testing import MemoryAuthStore

FRONTEND_ORIGIN = "http://localhost:8766"
ADMIN_EMAIL = "browser@example.com"
ADMIN_PASSWORD = "browser passkey proof password"
EXAMPLE_DIR = Path(__file__).parent

settings = AuthSettings.development(
    trusted_origins=(FRONTEND_ORIGIN,),
    passkey_rp_id="localhost",
    passkey_rp_name="EPOK browser proof",
)
auth = EpokAuth(settings=settings, store=MemoryAuthStore())


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    await auth.service.create_admin(
        email=ADMIN_EMAIL,
        display_name="Browser proof",
        password=ADMIN_PASSWORD,
    )
    yield


api_app = FastAPI(title="epok-auth browser passkey proof", lifespan=lifespan)
api_app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type", settings.csrf_header_name],
)
auth.install(api_app, prefix="/api/v1/auth", include_passkeys=True)
frontend_app = FastAPI(title="epok-auth browser passkey frontend")


@frontend_app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return '<!doctype html><html><body><main id="result">ready</main></body></html>'


@frontend_app.get("/browser.js", response_class=FileResponse)
async def browser_helper() -> Path:
    return EXAMPLE_DIR / "browser.js"


@api_app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
