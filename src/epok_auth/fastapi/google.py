# pyright: reportUnusedFunction=false
from collections.abc import Awaitable, Callable
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request, Response

from epok_auth.fastapi.schemas import ProvisionedUserResponse, SessionResponse
from epok_auth.google.schemas import (
    FinishGoogleAuthenticationRequest,
    GoogleIdentityResponse,
    GoogleOptionsResponse,
)
from epok_auth.google.service import GoogleLoginService
from epok_auth.models import Principal, RequestContext, SessionBundle

type PrincipalDependency = Callable[..., Awaitable[Principal]]
type SessionCookieSetter = Callable[[Response, SessionBundle], None]
type RequestContextFactory = Callable[[Request], RequestContext]
type CacheDisabler = Callable[[Response], None]


def create_google_router(
    *,
    service: GoogleLoginService,
    principal_dependency: PrincipalDependency,
    set_session_cookies: SessionCookieSetter,
    request_context: RequestContextFactory,
    disable_cache: CacheDisabler,
    prefix: str,
) -> APIRouter:
    router = APIRouter(prefix=prefix, tags=["Google Sign-In"])

    @router.post("/options")
    async def begin_login(
        response: Response,
        origin: Annotated[str | None, Header(alias="Origin")] = None,
    ) -> GoogleOptionsResponse:
        options = await service.begin_login(origin)
        disable_cache(response)
        return GoogleOptionsResponse.from_options(options)

    @router.post("/verify")
    async def finish_login(
        payload: FinishGoogleAuthenticationRequest,
        request: Request,
        response: Response,
        origin: Annotated[str | None, Header(alias="Origin")] = None,
    ) -> SessionResponse:
        bundle = await service.finish_login(
            payload.challenge_id,
            payload.credential,
            origin,
            context=request_context(request),
        )
        set_session_cookies(response, bundle)
        disable_cache(response)
        return SessionResponse.from_bundle(bundle)

    @router.post("/link/options")
    async def begin_link(
        response: Response,
        principal: Annotated[Principal, Depends(principal_dependency)],
        origin: Annotated[str | None, Header(alias="Origin")] = None,
    ) -> GoogleOptionsResponse:
        options = await service.begin_link(principal, origin)
        disable_cache(response)
        return GoogleOptionsResponse.from_options(options)

    @router.post("/link/verify")
    async def finish_link(
        payload: FinishGoogleAuthenticationRequest,
        request: Request,
        response: Response,
        principal: Annotated[Principal, Depends(principal_dependency)],
        origin: Annotated[str | None, Header(alias="Origin")] = None,
    ) -> GoogleIdentityResponse:
        identity = await service.finish_link(
            principal,
            payload.challenge_id,
            payload.credential,
            origin,
            context=request_context(request),
        )
        disable_cache(response)
        return GoogleIdentityResponse.from_identity(identity)

    return router


def create_google_admin_router(
    *,
    service: GoogleLoginService,
    admin_dependency: PrincipalDependency,
    request_context: RequestContextFactory,
    disable_cache: CacheDisabler,
    prefix: str,
) -> APIRouter:
    router = APIRouter(
        prefix=prefix,
        tags=["authentication administration"],
        dependencies=[Depends(admin_dependency)],
    )

    @router.post("/{user_id}/google/recover")
    async def recover_google_account(
        user_id: UUID,
        request: Request,
        response: Response,
    ) -> ProvisionedUserResponse:
        result = await service.recover_password_access(
            user_id,
            context=request_context(request),
        )
        disable_cache(response)
        return ProvisionedUserResponse.from_result(result)

    return router
