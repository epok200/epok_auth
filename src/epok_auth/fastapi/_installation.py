from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from inspect import isawaitable
from typing import Protocol, cast

from fastapi import FastAPI, Request, Response
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from epok_auth.errores import AuthError, AuthErrorCode
from epok_auth.errores.handler import registrar
from epok_auth.errores.http import error_response
from epok_auth.fastapi.transport import AuthHttpTransport

type ValidationErrorHandler = Callable[[Request, Exception], Response | Awaitable[Response]]


class AsyncClosable(Protocol):
    async def aclose(self) -> None: ...


@dataclass(slots=True)
class AuthInstallState:
    prefixes: set[str] = field(default_factory=set[str])
    facades: list[AsyncClosable] = field(default_factory=list[AsyncClosable])
    handlers_installed: bool = False
    validation_fallback: ValidationErrorHandler | None = None

    def register(self, prefix: str, facade: AsyncClosable) -> None:
        if prefix in self.prefixes:
            raise ValueError(f"epok-auth is already installed at {prefix}")
        self.prefixes.add(prefix)
        if facade not in self.facades:
            self.facades.append(facade)


def install_state(app: FastAPI) -> AuthInstallState:
    state = getattr(app.state, "_epok_auth_install_state", None)
    if state is None:
        state = AuthInstallState()
        app.state._epok_auth_install_state = state
    return cast(AuthInstallState, state)


def install_exception_handlers(app: FastAPI) -> None:
    state = install_state(app)
    if state.handlers_installed:
        return
    state.validation_fallback = cast(
        ValidationErrorHandler | None,
        app.exception_handlers.get(RequestValidationError),
    )
    app.add_exception_handler(AuthError, auth_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, validation_error_handler)  # type: ignore[arg-type]
    state.handlers_installed = True


async def auth_error_handler(request: Request, error: AuthError) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None)
    registrar(error, contexto=request.url.path)
    response = error_response(error, request_id)
    AuthHttpTransport.disable_cache(response)
    return response


async def validation_error_handler(
    request: Request,
    error: RequestValidationError,
) -> Response:
    state = install_state(request.app)
    path = request.url.path
    belongs_to_auth = any(
        path == prefix or path.startswith(f"{prefix}/") for prefix in state.prefixes
    )
    if belongs_to_auth:
        response = JSONResponse(
            status_code=422,
            content={
                "code": AuthErrorCode.INPUT_INVALID.value,
                "detail": "The request does not match the expected authentication contract.",
                "request_id": getattr(request.state, "request_id", None),
            },
        )
        AuthHttpTransport.disable_cache(response)
        return response
    if state.validation_fallback is None:
        return await request_validation_exception_handler(request, error)
    response = state.validation_fallback(request, error)
    if isawaitable(response):
        return await response
    return response
