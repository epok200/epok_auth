from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Annotated, Any, Self
from uuid import UUID

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    FastAPI,
    Header,
    Query,
    Request,
    Response,
    status,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from epok_auth.config import AuthSettings
from epok_auth.errors import AuthError, AuthErrorCode
from epok_auth.models import Principal, RequestContext, UserUpdate
from epok_auth.service import AuthService
from epok_auth.store import AuthStore
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

PrincipalDependency = Principal
SafeAuthRoute = APIRoute
_bearer = HTTPBearer(auto_error=False)


class EpokAuth:
    """FastAPI-first facade over the authentication service."""

    def __init__(
        self,
        *,
        settings: AuthSettings,
        store: AuthStore,
        service: AuthService | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.service = service or AuthService(store=store, settings=settings)
        self._prefixes: set[str] = set()

    @classmethod
    def postgres(
        cls,
        *,
        settings: AuthSettings,
        pool_size: int = 5,
        max_overflow: int = 10,
        pool_timeout: float = 5.0,
    ) -> Self:
        if settings.database_url is None:
            raise ValueError("database_url is required for the PostgreSQL adapter")
        from epok_auth.postgres import PostgresAuthStore

        store = PostgresAuthStore.from_url(
            settings.database_url.get_secret_value(),
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_timeout=pool_timeout,
        )
        return cls(settings=settings, store=store)

    def install(
        self,
        app: FastAPI,
        *,
        prefix: str = "/auth",
        include_admin: bool = False,
        admin_prefix: str = "/users",
    ) -> None:
        normalized_prefix = "/" + prefix.strip("/")
        self._prefixes.add(normalized_prefix)
        app.include_router(self.router(prefix=normalized_prefix))
        if include_admin:
            app.include_router(
                self.admin_router(prefix=normalized_prefix + "/" + admin_prefix.strip("/"))
            )
        if not getattr(app.state, "_epok_auth_handlers_installed", False):
            app.add_exception_handler(AuthError, self._auth_error_handler)  # type: ignore[arg-type]
            app.add_exception_handler(RequestValidationError, self._validation_error_handler)  # type: ignore[arg-type]
            app.state._epok_auth_handlers_installed = True

    def router(self, *, prefix: str = "/auth") -> APIRouter:
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
            self.service.validate_origin(origin)
            bundle = await self.service.login(
                payload.email,
                payload.password,
                context=self._request_context(request),
            )
            self._set_session_cookies(response, bundle)
            self._disable_cache(response)
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
                Cookie(alias=self.settings.effective_refresh_cookie_name),
            ] = None,
            csrf_cookie: Annotated[
                str | None,
                Cookie(alias=self.settings.effective_csrf_cookie_name),
            ] = None,
            csrf_header: Annotated[
                str | None,
                Header(alias=self.settings.csrf_header_name),
            ] = None,
            origin: Annotated[str | None, Header(alias="Origin")] = None,
        ) -> SessionResponse:
            bundle = await self.service.refresh(
                refresh_token or "",
                csrf_cookie or "",
                csrf_header or "",
                origin=origin,
                context=self._request_context(request),
            )
            self._set_session_cookies(response, bundle)
            self._disable_cache(response)
            return SessionResponse.from_bundle(bundle)

        @router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
        async def logout(
            request: Request,
            refresh_token: Annotated[
                str | None,
                Cookie(alias=self.settings.effective_refresh_cookie_name),
            ] = None,
            csrf_cookie: Annotated[
                str | None,
                Cookie(alias=self.settings.effective_csrf_cookie_name),
            ] = None,
            csrf_header: Annotated[
                str | None,
                Header(alias=self.settings.csrf_header_name),
            ] = None,
            origin: Annotated[str | None, Header(alias="Origin")] = None,
        ) -> Response:
            await self.service.logout(
                refresh_token,
                csrf_cookie,
                csrf_header,
                origin=origin,
                context=self._request_context(request),
            )
            response = Response(status_code=status.HTTP_204_NO_CONTENT)
            self._delete_session_cookies(response)
            self._disable_cache(response)
            return response

        @router.get("/me", response_model=PrincipalResponse)
        async def me(
            principal: Annotated[Principal, Depends(self.current_user)],
        ) -> PrincipalResponse:
            return PrincipalResponse.from_principal(principal)

        @router.post("/change-password", response_model=SessionResponse)
        async def change_password(
            payload: ChangePasswordRequest,
            request: Request,
            response: Response,
            principal: Annotated[Principal, Depends(self.current_user)],
            origin: Annotated[str | None, Header(alias="Origin")] = None,
        ) -> SessionResponse:
            self.service.validate_origin(origin)
            bundle = await self.service.change_password(
                principal,
                payload.current_password,
                payload.new_password,
                context=self._request_context(request),
            )
            self._set_session_cookies(response, bundle)
            self._disable_cache(response)
            return SessionResponse.from_bundle(bundle)

        return router

    def admin_router(self, *, prefix: str = "/auth/users") -> APIRouter:
        admin_dependency = self.require_roles(self.settings.admin_role)
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
            users = await self.service.list_users(limit=limit, offset=offset)
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
            result = await self.service.create_user(
                email=payload.email,
                display_name=payload.display_name,
                roles=payload.roles,
                scopes=payload.scopes,
                context=self._request_context(request),
            )
            return ProvisionedUserResponse.from_result(result)

        @router.get("/{user_id}", response_model=UserResponse)
        async def get_user(user_id: UUID) -> UserResponse:
            return UserResponse.from_user(await self.service.get_user(user_id))

        @router.patch("/{user_id}", response_model=UserResponse)
        async def update_user(
            user_id: UUID,
            payload: UpdateUserRequest,
            request: Request,
        ) -> UserResponse:
            user = await self.service.update_user(
                user_id,
                UserUpdate(
                    display_name=payload.display_name,
                    status=payload.status,
                    roles=tuple(payload.roles) if payload.roles is not None else None,
                    scopes=tuple(payload.scopes) if payload.scopes is not None else None,
                ),
                context=self._request_context(request),
            )
            return UserResponse.from_user(user)

        @router.post("/{user_id}/reset-password", response_model=ProvisionedUserResponse)
        async def reset_password(user_id: UUID, request: Request) -> ProvisionedUserResponse:
            return ProvisionedUserResponse.from_result(
                await self.service.reset_password(
                    user_id,
                    context=self._request_context(request),
                )
            )

        @router.post("/{user_id}/revoke-sessions", response_model=RevocationResponse)
        async def revoke_sessions(user_id: UUID, request: Request) -> RevocationResponse:
            count = await self.service.revoke_user_sessions(
                user_id,
                context=self._request_context(request),
            )
            return RevocationResponse(revoked_sessions=count)

        return router

    async def current_user(
        self,
        credentials: Annotated[
            HTTPAuthorizationCredentials | None,
            Depends(_bearer),
        ],
    ) -> Principal:
        return await self._principal_from_credentials(credentials)

    async def authenticated(
        self,
        credentials: Annotated[
            HTTPAuthorizationCredentials | None,
            Depends(_bearer),
        ],
    ) -> Principal:
        principal = await self._principal_from_credentials(credentials)
        if principal.must_change_password:
            raise AuthError(
                AuthErrorCode.PASSWORD_CHANGE_REQUIRED,
                "Password change is required before using the application.",
                status_code=403,
            )
        return principal

    async def _principal_from_credentials(
        self,
        credentials: HTTPAuthorizationCredentials | None,
    ) -> Principal:
        if credentials is None or credentials.scheme.casefold() != "bearer":
            from epok_auth.errors import invalid_session

            raise invalid_session()
        return await self.service.authenticate(credentials.credentials)

    def require_roles(self, *roles: str) -> Callable[..., Awaitable[Principal]]:
        async def dependency(
            principal: Annotated[Principal, Depends(self.authenticated)],
        ) -> Principal:
            self.service.require_roles(principal, *roles)
            return principal

        return dependency

    def require_scopes(self, *scopes: str) -> Callable[..., Awaitable[Principal]]:
        async def dependency(
            principal: Annotated[Principal, Depends(self.authenticated)],
        ) -> Principal:
            self.service.require_scopes(principal, *scopes)
            return principal

        return dependency

    def require_recent_authentication(
        self,
        *,
        max_age_seconds: int = 300,
    ) -> Callable[..., Awaitable[Principal]]:
        async def dependency(
            principal: Annotated[Principal, Depends(self.authenticated)],
        ) -> Principal:
            self.service.require_recent_authentication(
                principal,
                max_age_seconds=max_age_seconds,
            )
            return principal

        return dependency

    def protected_router(self, **kwargs: Any) -> APIRouter:
        dependencies = list(kwargs.pop("dependencies", []))
        dependencies.append(Depends(self.authenticated))
        return APIRouter(dependencies=dependencies, **kwargs)

    async def _auth_error_handler(self, request: Request, error: AuthError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None)
        response = JSONResponse(
            status_code=error.status_code,
            content={
                "code": error.code.value,
                "detail": error.detail,
                "request_id": request_id,
            },
            headers=error.headers,
        )
        self._disable_cache(response)
        return response

    async def _validation_error_handler(
        self,
        request: Request,
        error: RequestValidationError,
    ) -> JSONResponse:
        if any(request.url.path.startswith(prefix) for prefix in self._prefixes):
            response = JSONResponse(
                status_code=422,
                content={
                    "code": AuthErrorCode.INPUT_INVALID.value,
                    "detail": "The request does not match the expected authentication contract.",
                    "request_id": getattr(request.state, "request_id", None),
                },
            )
            self._disable_cache(response)
            return response
        from fastapi.exception_handlers import request_validation_exception_handler

        return await request_validation_exception_handler(request, error)

    def _set_session_cookies(self, response: Response, bundle: Any) -> None:
        now = datetime.now(UTC)
        max_age = max(
            0,
            int(
                min(bundle.refresh_idle_expires_at, bundle.refresh_absolute_expires_at).timestamp()
                - now.timestamp()
            ),
        )
        common: dict[str, Any] = {
            "max_age": max_age,
            "expires": bundle.refresh_absolute_expires_at,
            "path": self.settings.cookie_path,
            "domain": self.settings.cookie_domain,
            "secure": self.settings.secure_cookies,
            "samesite": self.settings.cookie_same_site,
        }
        response.set_cookie(
            self.settings.effective_refresh_cookie_name,
            bundle.refresh_token,
            httponly=True,
            **common,
        )
        response.set_cookie(
            self.settings.effective_csrf_cookie_name,
            bundle.csrf_token,
            httponly=self.settings.csrf_cookie_http_only,
            **common,
        )

    def _delete_session_cookies(self, response: Response) -> None:
        common = {
            "path": self.settings.cookie_path,
            "domain": self.settings.cookie_domain,
            "secure": self.settings.secure_cookies,
            "samesite": self.settings.cookie_same_site,
        }
        response.delete_cookie(self.settings.effective_refresh_cookie_name, **common)
        response.delete_cookie(self.settings.effective_csrf_cookie_name, **common)

    @staticmethod
    def _disable_cache(response: Response) -> None:
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"

    @staticmethod
    def _request_context(request: Request) -> RequestContext:
        forwarded = request.headers.get("x-forwarded-for")
        ip_address = forwarded.split(",", 1)[0].strip() if forwarded else None
        if ip_address is None and request.client is not None:
            ip_address = request.client.host
        return RequestContext(
            request_id=getattr(request.state, "request_id", None)
            or request.headers.get("x-request-id"),
            ip_address=ip_address,
            user_agent=request.headers.get("user-agent"),
        )
