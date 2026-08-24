from typing import Protocol

from epok_auth.email_links.models import AuthEmail, PendingEmailLink

type EmailDispatch = AuthEmail | PendingEmailLink


class EmailLinkDispatcher(Protocol):
    """Queues pending email links for durable delivery."""

    async def dispatch(self, message: EmailDispatch) -> None: ...
