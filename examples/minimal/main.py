from fastapi import Depends, FastAPI

from epok_auth import EpokAuth, Principal, load_auth_settings

settings = load_auth_settings()
auth = EpokAuth.postgres(settings=settings)

app = FastAPI(title="epok-auth minimal example", lifespan=auth.lifespan)
auth.install(app, prefix="/api/v1/auth", include_admin=True)

private = auth.protected_router(prefix="/api/v1/private", tags=["private"])


@private.get("")
async def private_endpoint(
    principal: Principal = Depends(auth.authenticated),
) -> dict[str, str]:
    return {"authenticated_user": principal.email}


app.include_router(private)
