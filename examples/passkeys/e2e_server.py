from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from epok_auth import AuthSettings, EpokAuth
from epok_auth.testing import MemoryAuthStore

SANDBOX_ORIGIN = "http://localhost:8765"
ADMIN_EMAIL = "browser@example.com"
ADMIN_PASSWORD = "browser passkey proof password"
EXAMPLE_DIR = Path(__file__).parent

settings = AuthSettings.development(
    trusted_origins=(SANDBOX_ORIGIN,),
    passkey_rp_id="localhost",
    passkey_rp_name="EPOK passkey sandbox",
)
auth = EpokAuth(settings=settings, store=MemoryAuthStore())


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None]:
    await auth.service.create_admin(
        email=ADMIN_EMAIL,
        display_name="Browser proof",
        password=ADMIN_PASSWORD,
    )
    yield


api_app = FastAPI(title="epok-auth passkey sandbox", lifespan=lifespan)
auth.install(api_app, prefix="/api/v1/auth", include_passkeys=True)


@api_app.get("/", response_class=FileResponse)
async def sandbox() -> Path:
    return EXAMPLE_DIR / "sandbox.html"


@api_app.get("/browser.js", response_class=FileResponse)
async def browser_helper() -> Path:
    return EXAMPLE_DIR / "browser.js"


@api_app.get("/sandbox.js", response_class=FileResponse)
async def sandbox_client() -> Path:
    return EXAMPLE_DIR / "sandbox.js"


@api_app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
