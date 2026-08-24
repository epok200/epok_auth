# pyright: reportUnusedFunction=false
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Cookie, Depends, Header, Request, Response, status

from epok_auth.email_links.dispatcher import EmailLinkDispatcher
from epok_auth.email_links.mailer import EmailLinkMailer
from epok_auth.email_links.models import AuthEmail, PendingEmailLink
from epok_auth.email_links.schemas import (
    ConsumeEmailLink,
    ConsumePasswordReset,
    EmailLinkAccepted,
    RequestEmailLink,
)
from epok_auth.email_links.service import EmailLinkService
from epok_auth.errores import AuthError, AuthErrorCode, registrar
from epok_auth.fastapi.schemas import SessionResponse
from epok_auth.fastapi.transport import AuthHttpTransport
from epok_auth.models import Principal

type OriginValidator = Callable[[str | None], None]
type PrincipalDependency = Callable[..., Awaitable[Principal]]


@dataclass(frozen=True, slots=True)
class EmailLinkCookies:
    browser_nonce: str | None
    refresh_token: str | None
    authorization: str | None


def create_email_link_router(
    *,
    service: EmailLinkService,
    mailer: EmailLinkMailer | None,
    transport: AuthHttpTransport,
    validate_origin: OriginValidator,
    prefix: str,
    dispatcher: EmailLinkDispatcher | None = None,
) -> APIRouter:
    router = APIRouter(prefix=prefix, tags=["email links"])
    settings = transport.settings

    async def read_email_link_cookies(
        browser_nonce: Annotated[
            str | None,
            Cookie(alias=settings.effective_email_link_cookie_name),
        ] = None,
        refresh_token: Annotated[
            str | None,
            Cookie(alias=settings.effective_refresh_cookie_name),
        ] = None,
        authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    ) -> EmailLinkCookies:
        return EmailLinkCookies(browser_nonce, refresh_token, authorization)

    @router.post(
        "/login",
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def request_login(
        payload: RequestEmailLink,
        request: Request,
        response: Response,
        background_tasks: BackgroundTasks,
        origin: Annotated[str | None, Header(alias="Origin")] = None,
    ) -> EmailLinkAccepted:
        validate_origin(origin)
        issue = await service.request_login(
            payload.email,
            browser_nonce=request.cookies.get(settings.effective_email_link_cookie_name),
            context=transport.request_context(request),
        )
        await _dispatch(issue.pending, background_tasks, service, mailer, dispatcher)
        if issue.browser_nonce is None:  # pragma: no cover
            raise RuntimeError("login email-link request did not create a browser nonce")
        transport.set_email_link_cookie(response, issue.browser_nonce)
        transport.disable_cache(response)
        return EmailLinkAccepted()

    @router.post("/login/consume")
    async def consume_login(
        payload: ConsumeEmailLink,
        request: Request,
        response: Response,
        cookies: Annotated[EmailLinkCookies, Depends(read_email_link_cookies)],
        origin: Annotated[str | None, Header(alias="Origin")] = None,
    ) -> SessionResponse:
        validate_origin(origin)
        _require_signed_out(cookies)
        bundle = await service.login(
            payload.token,
            cookies.browser_nonce or "",
            context=transport.request_context(request),
        )
        transport.set_session_cookies(response, bundle)
        transport.delete_email_link_cookie(response)
        transport.disable_cache(response)
        return SessionResponse.from_bundle(bundle)

    @router.post(
        "/password-reset",
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def request_password_reset(
        payload: RequestEmailLink,
        request: Request,
        response: Response,
        background_tasks: BackgroundTasks,
        origin: Annotated[str | None, Header(alias="Origin")] = None,
    ) -> EmailLinkAccepted:
        validate_origin(origin)
        issue = await service.request_password_reset(
            payload.email,
            context=transport.request_context(request),
        )
        await _dispatch(issue.pending, background_tasks, service, mailer, dispatcher)
        transport.disable_cache(response)
        return EmailLinkAccepted()

    @router.post("/password-reset/consume", status_code=status.HTTP_204_NO_CONTENT)
    async def consume_password_reset(
        payload: ConsumePasswordReset,
        request: Request,
        background_tasks: BackgroundTasks,
        cookies: Annotated[EmailLinkCookies, Depends(read_email_link_cookies)],
        origin: Annotated[str | None, Header(alias="Origin")] = None,
    ) -> Response:
        validate_origin(origin)
        _require_signed_out(cookies)
        notice = await service.reset_password(
            payload.token,
            payload.new_password,
            context=transport.request_context(request),
        )
        await _dispatch_notice(notice, background_tasks, service, mailer, dispatcher)
        response = Response(status_code=status.HTTP_204_NO_CONTENT)
        transport.disable_cache(response)
        return response

    @router.post("/invitation/consume", status_code=status.HTTP_204_NO_CONTENT)
    async def activate_invitation(
        payload: ConsumeEmailLink,
        request: Request,
        cookies: Annotated[EmailLinkCookies, Depends(read_email_link_cookies)],
        origin: Annotated[str | None, Header(alias="Origin")] = None,
    ) -> Response:
        validate_origin(origin)
        _require_signed_out(cookies)
        await service.activate_invitation(
            payload.token,
            context=transport.request_context(request),
        )
        response = Response(status_code=status.HTTP_204_NO_CONTENT)
        transport.disable_cache(response)
        return response

    return router


def create_email_link_admin_router(
    *,
    service: EmailLinkService,
    mailer: EmailLinkMailer | None,
    transport: AuthHttpTransport,
    validate_origin: OriginValidator,
    admin_dependency: PrincipalDependency,
    prefix: str,
    dispatcher: EmailLinkDispatcher | None = None,
) -> APIRouter:
    router = APIRouter(
        prefix=prefix,
        tags=["authentication administration"],
        dependencies=[Depends(admin_dependency)],
    )

    @router.post(
        "/{user_id}/invitation",
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def invite_user(
        user_id: UUID,
        request: Request,
        response: Response,
        background_tasks: BackgroundTasks,
        origin: Annotated[str | None, Header(alias="Origin")] = None,
    ) -> EmailLinkAccepted:
        validate_origin(origin)
        issue = await service.invite(
            user_id,
            context=transport.request_context(request),
        )
        await _dispatch(issue.pending, background_tasks, service, mailer, dispatcher)
        transport.disable_cache(response)
        return EmailLinkAccepted()

    return router


async def _dispatch(
    pending: PendingEmailLink | None,
    background_tasks: BackgroundTasks,
    service: EmailLinkService,
    mailer: EmailLinkMailer | None,
    dispatcher: EmailLinkDispatcher | None,
) -> None:
    if pending is None:
        return
    if dispatcher is not None:
        try:
            await dispatcher.dispatch(pending)
        except Exception as error:
            registrar(error, contexto="email_link.dispatch")
            await service.mark_delivery_failed(pending.link_id)
        return
    if mailer is None:  # pragma: no cover
        raise RuntimeError("email link mailer is not configured")
    background_tasks.add_task(mailer.deliver, pending)


async def _dispatch_notice(
    notice: AuthEmail,
    background_tasks: BackgroundTasks,
    service: EmailLinkService,
    mailer: EmailLinkMailer | None,
    dispatcher: EmailLinkDispatcher | None,
) -> None:
    if dispatcher is not None:
        try:
            await dispatcher.dispatch(notice)
        except Exception as error:
            registrar(error, contexto="email_notice.dispatch")
            if notice.user_id is not None:  # pragma: no branch
                await service.mark_notice_delivery_failed(notice.user_id)
        return
    if mailer is None:  # pragma: no cover
        raise RuntimeError("email link mailer is not configured")
    background_tasks.add_task(mailer.send_notice, notice)


def _require_signed_out(cookies: EmailLinkCookies) -> None:
    if cookies.refresh_token or cookies.authorization:
        raise AuthError(
            AuthErrorCode.EMAIL_LINK_SESSION_EXISTS,
            "Sign out before consuming an email authentication link.",
        )
