from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import replace
from pathlib import Path

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import FileResponse

from epok_auth import AuthEmail, AuthSettings, EpokAuth
from epok_auth.testing import MemoryAuthStore

SANDBOX_ORIGIN = "http://localhost:8767"
USER_EMAIL = "browser@example.com"
EXAMPLE_DIR = Path(__file__).parent


class SandboxSender:
    def __init__(self) -> None:
        self.emails: list[AuthEmail] = []

    async def send(self, email: AuthEmail) -> None:
        self.emails.append(email)


settings = AuthSettings.development(
    trusted_origins=(SANDBOX_ORIGIN,),
    email_link_login_url=f"{SANDBOX_ORIGIN}/magic",
    email_link_password_reset_url=f"{SANDBOX_ORIGIN}/reset-password",
    email_link_invitation_url=f"{SANDBOX_ORIGIN}/invitation",
)
store = MemoryAuthStore()
sender = SandboxSender()
auth = EpokAuth(settings=settings, store=store, email_link_sender=sender)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None]:
    provisioned = await auth.service.create_user(email=USER_EMAIL, display_name="Browser proof")
    async with store.transaction() as transaction:
        await transaction.update_user(
            replace(
                provisioned.user,
                must_change_password=False,
                email_link_login_enabled=True,
            )
        )
    yield


api_app = FastAPI(title="epok-auth Magic Link sandbox", lifespan=lifespan)
auth.install(api_app, prefix="/api/v1/auth", include_email_links=True)


@api_app.get("/", response_class=FileResponse)
@api_app.get("/magic", response_class=FileResponse)
async def sandbox() -> Path:
    return EXAMPLE_DIR / "sandbox.html"


@api_app.get("/sandbox.js", response_class=FileResponse)
async def sandbox_client() -> Path:
    return EXAMPLE_DIR / "sandbox.js"


@api_app.get("/test/latest-link")
async def latest_link(response: Response) -> dict[str, str]:
    response.headers["Cache-Control"] = "no-store"
    if not sender.emails or sender.emails[-1].action_url is None:
        raise HTTPException(status_code=404, detail="No email has been accepted yet")
    return {"url": sender.emails[-1].action_url}


@api_app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
