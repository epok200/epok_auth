import asyncio
import secrets
from dataclasses import replace
from datetime import datetime, timedelta
from urllib.parse import quote
from uuid import UUID, uuid4

from epok_auth._events import EMPTY_CONTEXT, record_security_event
from epok_auth._validation import normalize_email_for_login
from epok_auth.config import AuthSettings
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
from epok_auth.errores import AuthError, AuthErrorCode
from epok_auth.models import (
    RequestContext,
    SecurityEventType,
    SessionBundle,
    UserAccount,
    UserStatus,
)
from epok_auth.passwords import PasswordManager
from epok_auth.sessions import SessionIssuer
from epok_auth.tokens import AccessTokenSigner, Clock, clock_now, token_hash, utc_now


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
        _require_frontend_urls(settings)
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
        browser_nonce = _login_nonce(browser_nonce)
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
            if not self._can_request(user, EmailLinkPurpose.INVITATION, now):
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
            if link is None or not self._can_activate(link, latest, user, now):
                if link is not None:
                    await transaction.revoke_email_link(link.id, now)
                return False
            activated = await transaction.activate_email_link(link.id, now)
            if activated is None:
                return False
            await transaction.revoke_other_active_email_links(
                link.user_id,
                link.purpose,
                link.id,
                now,
            )
            await record_security_event(
                transaction,
                SecurityEventType.EMAIL_LINK_DELIVERED,
                now,
                user_id=link.user_id,
                metadata={"purpose": link.purpose.value},
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
            if link is None or user is None or not self._can_login(user, now):
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
            raise _invalid_email_link()
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
            raise _invalid_email_link()
        password_hash = await asyncio.to_thread(self.passwords.hash, new_password)
        notice: AuthEmail | None = None
        async with self.store.transaction() as transaction:
            link, user = await self._consumable(
                transaction,
                token,
                EmailLinkPurpose.PASSWORD_RESET,
                now,
            )
            if link is not None and user is not None and self._can_reset_password(user):
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
            raise _invalid_email_link()
        return notice

    async def activate_invitation(
        self,
        token: str,
        *,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> UserAccount:
        now = clock_now(self.clock)
        if not await self._active_link_exists(token, EmailLinkPurpose.INVITATION, now):
            raise _invalid_email_link()
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
            if link is not None and user is not None and self._can_invite(user):
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
            raise _invalid_email_link()
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
            if user is None or not self._can_request(user, purpose, now):
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
        retention = timedelta(seconds=self.settings.email_link_retention_seconds)
        await transaction.delete_old_email_links(now - retention)
        window = timedelta(seconds=self.settings.email_link_request_window_seconds)
        request_count = await transaction.count_email_link_requests(
            user.id,
            purpose,
            now - window,
        )
        if request_count >= self.settings.email_link_max_requests_per_window:
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
            expires_at=now + timedelta(seconds=self._ttl(purpose)),
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
            action_url=f"{self._frontend_url(purpose)}#token={quote(token, safe='')}",
            expires_at=link.expires_at,
        )
        return EmailLinkIssue(pending=PendingEmailLink(link_id=link.id, email=email))

    async def _consumable(
        self,
        transaction: EmailLinkTransaction,
        token: str,
        purpose: EmailLinkPurpose,
        now: datetime,
        *,
        browser_nonce: str | None = None,
    ) -> tuple[EmailLink | None, UserAccount | None]:
        if not token or len(token) > self.settings.email_link_max_token_chars:
            return None, None
        candidate = await transaction.get_email_link_by_token_hash(token_hash(token), purpose)
        if candidate is None:
            return None, None
        user = await transaction.get_user_by_id(candidate.user_id, for_update=True)
        link = await transaction.get_email_link(candidate.id, for_update=True)
        if link is None or link.state is not EmailLinkState.ACTIVE:
            return None, user
        if user is None or not self._matches_user(link, user, now):
            await transaction.revoke_email_link(link.id, now)
            return None, user
        if purpose is EmailLinkPurpose.LOGIN and not self._matches_browser(
            link,
            browser_nonce,
        ):
            return None, user
        return link, user

    async def _active_link_exists(
        self,
        token: str,
        purpose: EmailLinkPurpose,
        now: datetime,
    ) -> bool:
        if not token or len(token) > self.settings.email_link_max_token_chars:
            return False
        async with self.store.transaction() as transaction:
            link = await transaction.get_email_link_by_token_hash(token_hash(token), purpose)
        return link is not None and link.state is EmailLinkState.ACTIVE and link.expires_at > now

    def _matches_user(self, link: EmailLink, user: UserAccount, now: datetime) -> bool:
        return (
            link.state is EmailLinkState.ACTIVE
            and link.expires_at > now
            and link.security_version == user.security_version
            and secrets.compare_digest(link.recipient_hash, token_hash(user.email))
            and self.settings.admin_role not in user.roles
        )

    @staticmethod
    def _matches_browser(link: EmailLink, browser_nonce: str | None) -> bool:
        if link.browser_hash is None or browser_nonce is None:
            return False
        return secrets.compare_digest(link.browser_hash, token_hash(browser_nonce))

    def _can_activate(
        self,
        link: EmailLink | None,
        latest: EmailLink | None,
        user: UserAccount | None,
        now: datetime,
    ) -> bool:
        if link is None or latest is None or user is None:
            return False
        return (
            link.state is EmailLinkState.PENDING
            and link.id == latest.id
            and link.expires_at > now
            and link.security_version == user.security_version
            and secrets.compare_digest(link.recipient_hash, token_hash(user.email))
            and self._can_request(user, link.purpose, now)
        )

    def _can_request(
        self,
        user: UserAccount,
        purpose: EmailLinkPurpose,
        now: datetime,
    ) -> bool:
        if self.settings.admin_role in user.roles:
            return False
        if purpose is EmailLinkPurpose.LOGIN:
            return self._can_login(user, now)
        if purpose is EmailLinkPurpose.PASSWORD_RESET:
            return self._can_reset_password(user)
        return self._can_invite(user)

    @staticmethod
    def _can_login(user: UserAccount, now: datetime) -> bool:
        return (
            user.can_authenticate(now)
            and user.email_link_login_enabled
            and not user.must_change_password
        )

    @staticmethod
    def _can_reset_password(user: UserAccount) -> bool:
        return user.status is UserStatus.ACTIVE and user.password_login_enabled

    @staticmethod
    def _can_invite(user: UserAccount) -> bool:
        return user.status is UserStatus.ACTIVE and user.must_change_password

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

    def _frontend_url(self, purpose: EmailLinkPurpose) -> str:
        if purpose is EmailLinkPurpose.LOGIN:
            url = self.settings.email_link_login_url
        elif purpose is EmailLinkPurpose.PASSWORD_RESET:
            url = self.settings.email_link_password_reset_url
        else:
            url = self.settings.email_link_invitation_url
        if url is None:  # pragma: no cover
            raise RuntimeError("email link frontend URLs are not configured")
        return url

    def _ttl(self, purpose: EmailLinkPurpose) -> int:
        if purpose is EmailLinkPurpose.LOGIN:
            return self.settings.email_link_login_ttl_seconds
        if purpose is EmailLinkPurpose.PASSWORD_RESET:
            return self.settings.email_link_password_reset_ttl_seconds
        return self.settings.email_link_invitation_ttl_seconds


def _require_frontend_urls(settings: AuthSettings) -> None:
    if not all(
        (
            settings.email_link_login_url,
            settings.email_link_password_reset_url,
            settings.email_link_invitation_url,
        )
    ):
        raise ValueError("email link frontend URLs are required when email links are enabled")


def _login_nonce(existing: str | None) -> str:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    if existing and len(existing) == 43 and all(character in allowed for character in existing):
        return existing
    return secrets.token_urlsafe(32)


def _invalid_email_link() -> AuthError:
    return AuthError(
        AuthErrorCode.EMAIL_LINK_INVALID,
        "The email link is invalid or expired.",
    )
