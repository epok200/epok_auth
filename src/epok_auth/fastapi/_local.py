# pyright: reportUnusedFunction=false
from collections.abc import Awaitable, Callable
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Cookie, Depends, Header, Query, Request, Response, status

from epok_auth.fastapi.schemas import (
    ChangePasswordRequest,
    CreateUserRequest,
    ErrorResponse,
    LoginRequest,
    PrincipalResponse,
    ProvisionedUserResponse,
    RevocationResponse,
    SessionResponse,
    UpdateUserRequest,
    UserListResponse,
    UserResponse,
)
from epok_auth.fastapi.transport import AuthHttpTransport
from epok_auth.models import Principal, UserUpdate
from epok_auth.service import AuthService

PrincipalProvider = Callable[..., Awaitable[Principal]]


def create_auth_router(
    service: AuthService,
    transport: AuthHttpTransport,
    current_user: PrincipalProvider,
    *,
    prefix: str,
) -> APIRouter:
    settings = transport.settings
    router = APIRouter(prefix=prefix, tags=["authentication"])

    @router.post(
        "/login",
        response_model=SessionResponse,
        responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    )
    async def login(
        payload: LoginRequest,
        request: Request,
        response: Response,
        origin: Annotated[str | None, Header(alias="Origin")] = None,
    ) -> SessionResponse:
        service.validate_origin(origin)
        bundle = await service.login(
            payload.email,
            payload.password,
            context=transport.request_context(request),
        )
        transport.set_session_cookies(response, bundle)
        transport.disable_cache(response)
        return SessionResponse.from_bundle(bundle)

    @router.post(
        "/refresh",
        response_model=SessionResponse,
        responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
    )
    async def refresh(
        request: Request,
        response: Response,
        refresh_token: Annotated[
            str | None,
            Cookie(alias=settings.effective_refresh_cookie_name),
        ] = None,
        csrf_cookie: Annotated[
            str | None,
            Cookie(alias=settings.effective_csrf_cookie_name),
        ] = None,
        csrf_header: Annotated[
            str | None,
            Header(alias=settings.csrf_header_name),
        ] = None,
        origin: Annotated[str | None, Header(alias="Origin")] = None,
    ) -> SessionResponse:
        bundle = await service.refresh(
            refresh_token or "",
            csrf_cookie or "",
            csrf_header or "",
            origin=origin,
            context=transport.request_context(request),
        )
        transport.set_session_cookies(response, bundle)
        transport.disable_cache(response)
        return SessionResponse.from_bundle(bundle)

    @router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
    async def logout(
        request: Request,
        refresh_token: Annotated[
            str | None,
            Cookie(alias=settings.effective_refresh_cookie_name),
        ] = None,
        csrf_cookie: Annotated[
            str | None,
            Cookie(alias=settings.effective_csrf_cookie_name),
        ] = None,
        csrf_header: Annotated[
            str | None,
            Header(alias=settings.csrf_header_name),
        ] = None,
        origin: Annotated[str | None, Header(alias="Origin")] = None,
    ) -> Response:
        await service.logout(
            refresh_token,
            csrf_cookie,
            csrf_header,
            origin=origin,
            context=transport.request_context(request),
        )
        response = Response(status_code=status.HTTP_204_NO_CONTENT)
        transport.delete_session_cookies(response)
        transport.disable_cache(response)
        return response

    @router.get("/me", response_model=PrincipalResponse)
    async def me(
        principal: Annotated[Principal, Depends(current_user)],
    ) -> PrincipalResponse:
        return PrincipalResponse.from_principal(principal)

    @router.post("/change-password", response_model=SessionResponse)
    async def change_password(
        payload: ChangePasswordRequest,
        request: Request,
        response: Response,
        principal: Annotated[Principal, Depends(current_user)],
        origin: Annotated[str | None, Header(alias="Origin")] = None,
    ) -> SessionResponse:
        service.validate_origin(origin)
        bundle = await service.change_password(
            principal,
            payload.current_password,
            payload.new_password,
            context=transport.request_context(request),
        )
        transport.set_session_cookies(response, bundle)
        transport.disable_cache(response)
        return SessionResponse.from_bundle(bundle)

    return router


def create_admin_router(
    service: AuthService,
    transport: AuthHttpTransport,
    admin_dependency: PrincipalProvider,
    *,
    prefix: str,
) -> APIRouter:
    router = APIRouter(
        prefix=prefix,
        tags=["authentication administration"],
        dependencies=[Depends(admin_dependency)],
    )

    @router.get("", response_model=UserListResponse)
    async def list_users(
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> UserListResponse:
        users = await service.list_users(limit=limit, offset=offset)
        return UserListResponse(
            items=[UserResponse.from_user(user) for user in users],
            limit=limit,
            offset=offset,
        )

    @router.post("", response_model=ProvisionedUserResponse, status_code=201)
    async def create_user(
        payload: CreateUserRequest,
        request: Request,
    ) -> ProvisionedUserResponse:
        result = await service.create_user(
            email=payload.email,
            display_name=payload.display_name,
            roles=payload.roles,
            scopes=payload.scopes,
            google_auto_link_allowed=payload.google_auto_link_allowed,
            context=transport.request_context(request),
        )
        return ProvisionedUserResponse.from_result(result)

    @router.get("/{user_id}", response_model=UserResponse)
    async def get_user(user_id: UUID) -> UserResponse:
        return UserResponse.from_user(await service.get_user(user_id))

    @router.patch("/{user_id}", response_model=UserResponse)
    async def update_user(
        user_id: UUID,
        payload: UpdateUserRequest,
        request: Request,
    ) -> UserResponse:
        user = await service.update_user(
            user_id,
            UserUpdate(
                display_name=payload.display_name,
                status=payload.status,
                roles=tuple(payload.roles) if payload.roles is not None else None,
                scopes=tuple(payload.scopes) if payload.scopes is not None else None,
                google_auto_link_allowed=payload.google_auto_link_allowed,
                email_link_login_enabled=payload.email_link_login_enabled,
            ),
            context=transport.request_context(request),
        )
        return UserResponse.from_user(user)

    @router.post("/{user_id}/reset-password", response_model=ProvisionedUserResponse)
    async def reset_password(user_id: UUID, request: Request) -> ProvisionedUserResponse:
        result = await service.reset_password(
            user_id,
            context=transport.request_context(request),
        )
        return ProvisionedUserResponse.from_result(result)

    @router.post("/{user_id}/revoke-sessions", response_model=RevocationResponse)
    async def revoke_sessions(user_id: UUID, request: Request) -> RevocationResponse:
        count = await service.revoke_user_sessions(
            user_id,
            context=transport.request_context(request),
        )
        return RevocationResponse(revoked_sessions=count)

    return router
