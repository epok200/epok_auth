import secrets
from datetime import datetime, timedelta
from urllib.parse import quote
from uuid import uuid4

from epok_auth._events import record_security_event
from epok_auth.config import AuthSettings
from epok_auth.email_links._policy import (
    email_link_ttl,
    email_link_url,
    matches_user,
    valid_browser,
)
from epok_auth.email_links.models import (
    AuthEmail,
    AuthEmailKind,
    EmailLink,
    EmailLinkIssue,
    EmailLinkPurpose,
    EmailLinkState,
    PendingEmailLink,
)
from epok_auth.email_links.store import EmailLinkStore, EmailLinkTransaction
from epok_auth.models import RequestContext, SecurityEventType, UserAccount
from epok_auth.tokens import token_hash


async def issue_link(
    transaction: EmailLinkTransaction,
    settings: AuthSettings,
    user: UserAccount,
    purpose: EmailLinkPurpose,
    *,
    now: datetime,
    context: RequestContext,
    browser_nonce: str | None = None,
) -> EmailLinkIssue:
    retention = timedelta(seconds=settings.email_link_retention_seconds)
    await transaction.delete_old_email_links(now - retention)
    window = timedelta(seconds=settings.email_link_request_window_seconds)
    request_count = await transaction.count_email_link_requests(
        user.id,
        purpose,
        now - window,
    )
    if request_count >= settings.email_link_max_requests_per_window:
        return EmailLinkIssue()

    latest = await transaction.get_latest_email_link(user.id, purpose)
    generation = latest.generation + 1 if latest is not None else 1
    token = secrets.token_urlsafe(32)
    link = EmailLink(
        id=uuid4(),
        user_id=user.id,
        purpose=purpose,
        generation=generation,
        token_hash=token_hash(token),
        recipient_hash=token_hash(user.email),
        browser_hash=token_hash(browser_nonce) if browser_nonce is not None else None,
        security_version=user.security_version,
        created_at=now,
        expires_at=now + timedelta(seconds=email_link_ttl(settings, purpose)),
    )
    await transaction.insert_email_link(link)
    await record_security_event(
        transaction,
        SecurityEventType.EMAIL_LINK_ISSUED,
        now,
        user_id=user.id,
        context=context,
        metadata={"purpose": purpose.value},
    )
    email = AuthEmail(
        recipient=user.email,
        kind=AuthEmailKind(purpose.value),
        action_url=f"{email_link_url(settings, purpose)}#token={quote(token, safe='')}",
        expires_at=link.expires_at,
    )
    return EmailLinkIssue(pending=PendingEmailLink(link_id=link.id, email=email))


async def consumable_link(
    transaction: EmailLinkTransaction,
    settings: AuthSettings,
    token: str,
    purpose: EmailLinkPurpose,
    now: datetime,
    *,
    browser_nonce: str | None = None,
) -> tuple[EmailLink | None, UserAccount | None]:
    if not token or len(token) > settings.email_link_max_token_chars:
        return None, None
    candidate = await transaction.get_email_link_by_token_hash(token_hash(token), purpose)
    if candidate is None:
        return None, None
    user = await transaction.get_user_by_id(candidate.user_id, for_update=True)
    link = await transaction.get_email_link(candidate.id, for_update=True)
    if link is None or link.state is not EmailLinkState.ACTIVE:
        return None, user
    if user is None or not matches_user(settings, link, user, now):
        await transaction.revoke_email_link(link.id, now)
        return None, user
    if purpose is EmailLinkPurpose.LOGIN and not valid_browser(link, browser_nonce):
        return None, user
    return link, user


async def active_link_exists(
    store: EmailLinkStore,
    settings: AuthSettings,
    token: str,
    purpose: EmailLinkPurpose,
    now: datetime,
) -> bool:
    if not token or len(token) > settings.email_link_max_token_chars:
        return False
    async with store.transaction() as transaction:
        link = await transaction.get_email_link_by_token_hash(token_hash(token), purpose)
    return link is not None and link.state is EmailLinkState.ACTIVE and link.expires_at > now
