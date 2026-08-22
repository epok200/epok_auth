# pyright: reportUnusedFunction=false
from collections.abc import Awaitable, Callable
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request, Response, status

from epok_auth.fastapi.schemas import SessionResponse
from epok_auth.models import Principal, RequestContext, SessionBundle
from epok_auth.passkeys.schemas import (
    FinishPasskeyAuthenticationRequest,
    FinishPasskeyRegistrationRequest,
    PasskeyListResponse,
    PasskeyOptionsResponse,
    PasskeyResponse,
)
from epok_auth.passkeys.service import PasskeyService

type PrincipalDependency = Callable[..., Awaitable[Principal]]
type SessionCookieSetter = Callable[[Response, SessionBundle], None]
type RequestContextFactory = Callable[[Request], RequestContext]
type CacheDisabler = Callable[[Response], None]


def create_passkey_router(
    *,
    service: PasskeyService,
    principal_dependency: PrincipalDependency,
    set_session_cookies: SessionCookieSetter,
    request_context: RequestContextFactory,
    disable_cache: CacheDisabler,
    prefix: str,
) -> APIRouter:
    router = APIRouter(prefix=prefix, tags=["passkeys"])

    @router.post("/registration/options")
    async def begin_registration(
        response: Response,
        principal: Annotated[Principal, Depends(principal_dependency)],
        origin: Annotated[str | None, Header(alias="Origin")] = None,
    ) -> PasskeyOptionsResponse:
        options = await service.begin_registration(principal, origin)
        disable_cache(response)
        return PasskeyOptionsResponse.from_options(options)

    @router.post(
        "/registration/verify",
        status_code=status.HTTP_201_CREATED,
    )
    async def finish_registration(
        payload: FinishPasskeyRegistrationRequest,
        request: Request,
        response: Response,
        principal: Annotated[Principal, Depends(principal_dependency)],
        origin: Annotated[str | None, Header(alias="Origin")] = None,
    ) -> PasskeyResponse:
        credential = await service.finish_registration(
            principal,
            payload.ceremony_id,
            payload.name,
            payload.credential.as_webauthn(),
            origin,
            context=request_context(request),
        )
        disable_cache(response)
        return PasskeyResponse.from_credential(credential)

    @router.post("/authentication/options")
    async def begin_authentication(
        response: Response,
        origin: Annotated[str | None, Header(alias="Origin")] = None,
    ) -> PasskeyOptionsResponse:
        options = await service.begin_authentication(origin)
        disable_cache(response)
        return PasskeyOptionsResponse.from_options(options)

    @router.post("/authentication/verify")
    async def finish_authentication(
        payload: FinishPasskeyAuthenticationRequest,
        request: Request,
        response: Response,
        origin: Annotated[str | None, Header(alias="Origin")] = None,
    ) -> SessionResponse:
        bundle = await service.finish_authentication(
            payload.ceremony_id,
            payload.credential.as_webauthn(),
            origin,
            context=request_context(request),
        )
        set_session_cookies(response, bundle)
        disable_cache(response)
        return SessionResponse.from_bundle(bundle)

    @router.get("")
    async def list_passkeys(
        response: Response,
        principal: Annotated[Principal, Depends(principal_dependency)],
    ) -> PasskeyListResponse:
        credentials = await service.list_passkeys(principal)
        disable_cache(response)
        return PasskeyListResponse(
            items=[PasskeyResponse.from_credential(item) for item in credentials]
        )

    @router.delete("/{passkey_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def revoke_passkey(
        passkey_id: UUID,
        request: Request,
        principal: Annotated[Principal, Depends(principal_dependency)],
        origin: Annotated[str | None, Header(alias="Origin")] = None,
    ) -> Response:
        await service.revoke_passkey(
            principal,
            passkey_id,
            origin,
            context=request_context(request),
        )
        response = Response(status_code=status.HTTP_204_NO_CONTENT)
        disable_cache(response)
        return response

    return router
