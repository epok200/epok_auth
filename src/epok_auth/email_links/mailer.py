from epok_auth.email_links.models import AuthEmail, PendingEmailLink
from epok_auth.email_links.service import EmailLinkService
from epok_auth.email_links.smtp import EmailLinkSender
from epok_auth.errores import AuthError, AuthErrorCode


class EmailLinkMailer:
    """Activates links only after the provider accepts their email."""

    def __init__(self, service: EmailLinkService, sender: EmailLinkSender) -> None:
        self.service = service
        self.sender = sender

    async def deliver(self, pending: PendingEmailLink) -> bool:
        try:
            await self.sender.send(pending.email)
        except Exception:
            await self.service.mark_delivery_failed(pending.link_id)
            raise AuthError(
                AuthErrorCode.EMAIL_DELIVERY_FAILED,
                "The authentication email could not be accepted for delivery.",
            ) from None
        return await self.service.mark_delivered(pending.link_id)

    async def send_notice(self, email: AuthEmail) -> None:
        try:
            await self.sender.send(email)
        except Exception:
            if email.user_id is not None:
                await self.service.mark_notice_delivery_failed(email.user_id)
            raise AuthError(
                AuthErrorCode.EMAIL_DELIVERY_FAILED,
                "The security notice could not be accepted for delivery.",
            ) from None
