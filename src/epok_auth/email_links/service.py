import asyncio
import secrets
from dataclasses import replace
from datetime import datetime
from uuid import UUID

from epok_auth._events import EMPTY_CONTEXT, record_security_event
from epok_auth._validation import normalize_email_for_login
from epok_auth.config import AuthSettings
from epok_auth.email_links._operations import active_link_exists, consumable_link, issue_link
from epok_auth.email_links._policy import (
    can_request,
    deliverable_link,
    invalid_email_link,
    login_nonce,
    require_email_link_url,
)
from epok_auth.email_links.models import (
    AuthEmail,
    AuthEmailKind,
    EmailLink,
    EmailLinkIssue,
    EmailLinkPurpose,
)
from epok_auth.email_links.store import EmailLinkStore, EmailLinkTransaction
from epok_auth.errores import AuthError, AuthErrorCode
from epok_auth.models import (
    RequestContext,
    SecurityEventType,
    SessionBundle,
    UserAccount,
)
from epok_auth.passwords import PasswordManager
from epok_auth.sessions import SessionIssuer
from epok_auth.tokens import AccessTokenSigner, Clock, clock_now, utc_now


class EmailLinkService:
    """Owns issuance, delivery activation and one-time email-link consumption."""

    def __init__(
        self,
        *,
        store: EmailLinkStore,
        settings: AuthSettings,
        signer: AccessTokenSigner,
        passwords: PasswordManager,
        clock: Clock = utc_now,
    ) -> None:
        require_email_link_url(settings)
        self.store = store
        self.settings = settings
        self.passwords = passwords
        self.clock = clock
        self.session_issuer = SessionIssuer(settings=settings, signer=signer)

    async def request_login(
        self,
        email: str,
        *,
        browser_nonce: str | None = None,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> EmailLinkIssue:
        browser_nonce = login_nonce(browser_nonce)
        issue = await self._request_for_email(
            email,
            EmailLinkPurpose.LOGIN,
            browser_nonce=browser_nonce,
            context=context,
        )
        return replace(issue, browser_nonce=browser_nonce)

    async def request_password_reset(
        self,
        email: str,
        *,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> EmailLinkIssue:
        return await self._request_for_email(
            email,
            EmailLinkPurpose.PASSWORD_RESET,
            browser_nonce=None,
            context=context,
        )

    async def invite(
        self,
        user_id: UUID,
        *,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> EmailLinkIssue:
        now = clock_now(self.clock)
        async with self.store.transaction() as transaction:
            user = await transaction.get_user_by_id(user_id, for_update=True)
            if user is None:
                raise AuthError(AuthErrorCode.USER_NOT_FOUND, "User not found.")
            if not can_request(self.settings, user, EmailLinkPurpose.INVITATION, now):
                raise AuthError(
                    AuthErrorCode.FORBIDDEN,
                    "This account is not eligible for email invitation.",
                )
            return await self._issue(
                transaction,
                user,
                EmailLinkPurpose.INVITATION,
                browser_nonce=None,
                now=now,
                context=context,
            )

    async def mark_delivered(self, link_id: UUID) -> bool:
        now = clock_now(self.clock)
        async with self.store.transaction() as transaction:
            candidate = await transaction.get_email_link(link_id)
            if candidate is None:
                return False
            user = await transaction.get_user_by_id(candidate.user_id, for_update=True)
            link = await transaction.get_email_link(link_id, for_update=True)
            latest = await transaction.get_latest_email_link(
                candidate.user_id,
                candidate.purpose,
            )
            deliverable = deliverable_link(self.settings, link, latest, user, now)
            if deliverable is None:
                if link is not None:
                    await transaction.revoke_email_link(link.id, now)
                return False
            activated = await transaction.activate_email_link(deliverable.id, now)
            if activated is None:
                return False
            await transaction.revoke_other_active_email_links(
                deliverable.user_id,
                deliverable.purpose,
                deliverable.id,
                now,
            )
            await record_security_event(
                transaction,
                SecurityEventType.EMAIL_LINK_DELIVERED,
                now,
                user_id=deliverable.user_id,
                metadata={"purpose": deliverable.purpose.value},
            )
            return True

    async def mark_delivery_failed(self, link_id: UUID) -> None:
        now = clock_now(self.clock)
        async with self.store.transaction() as transaction:
            failed = await transaction.fail_email_link(link_id, now)
            if failed is None:
                return
            await record_security_event(
                transaction,
                SecurityEventType.EMAIL_LINK_DELIVERY_FAILED,
                now,
                user_id=failed.user_id,
                metadata={"purpose": failed.purpose.value},
            )

    async def mark_notice_delivery_failed(self, user_id: UUID) -> None:
        now = clock_now(self.clock)
        async with self.store.transaction() as transaction:
            await record_security_event(
                transaction,
                SecurityEventType.EMAIL_NOTICE_DELIVERY_FAILED,
                now,
                user_id=user_id,
            )

    async def login(
        self,
        token: str,
        browser_nonce: str,
        *,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> SessionBundle:
        now = clock_now(self.clock)
        result: SessionBundle | None = None
        async with self.store.transaction() as transaction:
            link, user = await self._consumable(
                transaction,
                token,
                EmailLinkPurpose.LOGIN,
                now,
                browser_nonce=browser_nonce,
            )
            if (
                link is None
                or user is None
                or not can_request(self.settings, user, EmailLinkPurpose.LOGIN, now)
            ):
                await self._login_failure(transaction, user, now, context)
            else:
                consumed = await transaction.consume_email_link(link.id, link.purpose, now)
                if consumed is None:
                    await self._login_failure(transaction, user, now, context)
                else:
                    result = await self.session_issuer.issue(
                        transaction,
                        user,
                        now=now,
                        context=context,
                    )
                    await record_security_event(
                        transaction,
                        SecurityEventType.EMAIL_LINK_LOGIN_SUCCEEDED,
                        now,
                        user_id=user.id,
                        session_id=result.principal.session_id,
                        context=context,
                    )
        if result is None:
            raise invalid_email_link()
        return result

    async def reset_password(
        self,
        token: str,
        new_password: str,
        *,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> AuthEmail:
        self.passwords.validate(new_password)
        now = clock_now(self.clock)
        if not await self._active_link_exists(token, EmailLinkPurpose.PASSWORD_RESET, now):
            raise invalid_email_link()
        password_hash = await asyncio.to_thread(self.passwords.hash, new_password)
        notice: AuthEmail | None = None
        async with self.store.transaction() as transaction:
            link, user = await self._consumable(
                transaction,
                token,
                EmailLinkPurpose.PASSWORD_RESET,
                now,
            )
            if (
                link is not None
                and user is not None
                and can_request(self.settings, user, EmailLinkPurpose.PASSWORD_RESET, now)
            ):
                consumed = await transaction.consume_email_link(link.id, link.purpose, now)
                if consumed is not None:
                    updated = user.activate_password(password_hash, now)
                    await transaction.update_user(updated)
                    await transaction.revoke_user_sessions(user.id, revoked_at=now)
                    await record_security_event(
                        transaction,
                        SecurityEventType.PASSWORD_RECOVERY_COMPLETED,
                        now,
                        user_id=user.id,
                        context=context,
                    )
                    notice = AuthEmail(
                        recipient=user.email,
                        kind=AuthEmailKind.PASSWORD_CHANGED,
                        user_id=user.id,
                    )
        if notice is None:
            raise invalid_email_link()
        return notice

    async def activate_invitation(
        self,
        token: str,
        *,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> UserAccount:
        now = clock_now(self.clock)
        if not await self._active_link_exists(token, EmailLinkPurpose.INVITATION, now):
            raise invalid_email_link()
        unusable_password = secrets.token_urlsafe(self.settings.temporary_password_bytes)
        password_hash = await asyncio.to_thread(self.passwords.hash, unusable_password)
        result: UserAccount | None = None
        async with self.store.transaction() as transaction:
            link, user = await self._consumable(
                transaction,
                token,
                EmailLinkPurpose.INVITATION,
                now,
            )
            if (
                link is not None
                and user is not None
                and can_request(self.settings, user, EmailLinkPurpose.INVITATION, now)
            ):
                consumed = await transaction.consume_email_link(link.id, link.purpose, now)
                if consumed is not None:
                    result = user.activate_email_link_login(password_hash, now)
                    await transaction.update_user(result)
                    await transaction.revoke_user_sessions(user.id, revoked_at=now)
                    await record_security_event(
                        transaction,
                        SecurityEventType.INVITATION_ACTIVATED,
                        now,
                        user_id=user.id,
                        context=context,
                    )
        if result is None:
            raise invalid_email_link()
        return result

    async def _request_for_email(
        self,
        email: str,
        purpose: EmailLinkPurpose,
        *,
        browser_nonce: str | None,
        context: RequestContext,
    ) -> EmailLinkIssue:
        now = clock_now(self.clock)
        normalized_email = normalize_email_for_login(email)
        async with self.store.transaction() as transaction:
            user = await transaction.get_user_by_email(normalized_email, for_update=True)
            if user is None or not can_request(self.settings, user, purpose, now):
                return EmailLinkIssue()
            return await self._issue(
                transaction,
                user,
                purpose,
                browser_nonce=browser_nonce,
                now=now,
                context=context,
            )

    async def _issue(
        self,
        transaction: EmailLinkTransaction,
        user: UserAccount,
        purpose: EmailLinkPurpose,
        *,
        browser_nonce: str | None,
        now: datetime,
        context: RequestContext,
    ) -> EmailLinkIssue:
        return await issue_link(
            transaction,
            self.settings,
            user,
            purpose,
            now=now,
            context=context,
            browser_nonce=browser_nonce,
        )

    async def _consumable(
        self,
        transaction: EmailLinkTransaction,
        token: str,
        purpose: EmailLinkPurpose,
        now: datetime,
        *,
        browser_nonce: str | None = None,
    ) -> tuple[EmailLink | None, UserAccount | None]:
        return await consumable_link(
            transaction,
            self.settings,
            token,
            purpose,
            now,
            browser_nonce=browser_nonce,
        )

    async def _active_link_exists(
        self,
        token: str,
        purpose: EmailLinkPurpose,
        now: datetime,
    ) -> bool:
        return await active_link_exists(self.store, self.settings, token, purpose, now)

    async def _login_failure(
        self,
        transaction: EmailLinkTransaction,
        user: UserAccount | None,
        now: datetime,
        context: RequestContext,
    ) -> None:
        await record_security_event(
            transaction,
            SecurityEventType.EMAIL_LINK_LOGIN_FAILED,
            now,
            user_id=user.id if user is not None else None,
            context=context,
        )
