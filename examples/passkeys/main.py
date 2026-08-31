from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from epok_auth import EpokAuth, load_auth_settings

settings = load_auth_settings()
auth = EpokAuth.postgres(settings=settings)

app = FastAPI(title="epok-auth passkeys example")
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.trusted_origins),
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type", settings.csrf_header_name],
)
auth.install(
    app,
    prefix="/api/v1/auth",
    include_admin=True,
    include_passkeys=True,
)
