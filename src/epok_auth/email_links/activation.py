import asyncio
import secrets
from datetime import datetime
from uuid import UUID, uuid4

from epok_auth._events import EMPTY_CONTEXT, record_security_event
from epok_auth._validation import (
    normalize_capabilities,
    normalize_display_name,
    normalize_email,
)
from epok_auth.config import AuthSettings
from epok_auth.email_links._operations import active_link_exists, consumable_link, issue_link
from epok_auth.email_links._policy import can_request, invalid_email_link, require_activation_url
from epok_auth.email_links.models import (
    AccountActivation,
    EmailLinkIssue,
    EmailLinkPurpose,
    InitialAdminActivation,
)
from epok_auth.email_links.store import EmailLinkStore, EmailLinkTransaction
from epok_auth.errores import AuthError, AuthErrorCode
from epok_auth.models import RequestContext, SecurityEventType, UserAccount, UserStatus
from epok_auth.passwords import PasswordManager
from epok_auth.store import StoreConflictError
from epok_auth.tokens import Clock, clock_now, utc_now


class AccountActivationService:
    """Creates pending accounts and owns their first-password transition."""

    def __init__(
        self,
        *,
        store: EmailLinkStore,
        settings: AuthSettings,
        passwords: PasswordManager,
        clock: Clock = utc_now,
    ) -> None:
        self.store = store
        self.settings = settings
        self.passwords = passwords
        self.clock = clock

    async def provision(
        self,
        *,
        email: str,
        display_name: str,
        roles: tuple[str, ...] | None = None,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> AccountActivation:
        require_activation_url(self.settings)
        now = clock_now(self.clock)
        normalized_roles = normalize_capabilities(
            roles if roles is not None else (self.settings.default_user_role,),
            maximum=self.settings.max_roles,
        )
        if self.settings.admin_role in normalized_roles:
            raise AuthError(
                AuthErrorCode.FORBIDDEN,
                "Administrative activation requires the initial-admin operation.",
            )
        user = await self._pending_user(email, display_name, normalized_roles, now)
        try:
            async with self.store.transaction() as transaction:
                return await self._create(transaction, user, now, context)
        except StoreConflictError as error:
            raise _user_exists() from error

    async def ensure_initial_admin(
        self,
        *,
        email: str,
        display_name: str,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> InitialAdminActivation:
        require_activation_url(self.settings)
        now = clock_now(self.clock)
        normalized_email = normalize_email(email)
        user = await self._pending_user(
            normalized_email,
            display_name,
            (self.settings.admin_role,),
            now,
            scopes=("auth:admin",),
        )
        try:
            async with self.store.transaction() as transaction:
                await transaction.acquire_admin_invariant_lock()
                existing = await transaction.get_user_by_email(normalized_email, for_update=True)
                if existing is not None:
                    if self.settings.admin_role in existing.roles:
                        return InitialAdminActivation(existing)
                    raise _user_exists()
                if await transaction.count_users_with_role(
                    self.settings.admin_role,
                    active_only=False,
                ):
                    raise AuthError(
                        AuthErrorCode.ADMIN_EXISTS,
                        "The initial administrator already exists.",
                        status_code=409,
                    )
                activation = await self._create(transaction, user, now, context)
                await record_security_event(
                    transaction,
                    SecurityEventType.ADMIN_CREATED,
                    now,
                    user_id=user.id,
                    context=context,
                )
                return InitialAdminActivation(activation.user, activation.pending)
        except StoreConflictError as error:
            raise _user_exists() from error

    async def replace(
        self,
        user_id: UUID,
        *,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> EmailLinkIssue:
        require_activation_url(self.settings)
        now = clock_now(self.clock)
        async with self.store.transaction() as transaction:
            user = await transaction.get_user_by_id(user_id, for_update=True)
            if user is None:
                raise AuthError(AuthErrorCode.USER_NOT_FOUND, "User not found.", status_code=404)
            if not can_request(self.settings, user, EmailLinkPurpose.ACTIVATION, now):
                raise AuthError(
                    AuthErrorCode.FORBIDDEN,
                    "This account is not eligible for activation.",
                )
            return await issue_link(
                transaction,
                self.settings,
                user,
                EmailLinkPurpose.ACTIVATION,
                now=now,
                context=context,
            )

    async def activate(
        self,
        token: str,
        first_password: str,
        *,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> UserAccount:
        self.passwords.validate(first_password)
        now = clock_now(self.clock)
        if not await active_link_exists(
            self.store,
            self.settings,
            token,
            EmailLinkPurpose.ACTIVATION,
            now,
        ):
            raise invalid_email_link()
        password_hash = await asyncio.to_thread(self.passwords.hash, first_password)
        result: UserAccount | None = None
        async with self.store.transaction() as transaction:
            link, user = await consumable_link(
                transaction,
                self.settings,
                token,
                EmailLinkPurpose.ACTIVATION,
                now,
            )
            if (
                link is not None
                and user is not None
                and can_request(self.settings, user, EmailLinkPurpose.ACTIVATION, now)
            ):
                consumed = await transaction.consume_email_link(link.id, link.purpose, now)
                if consumed is not None:
                    result = user.activate_account(password_hash, now)
                    await transaction.update_user(result)
                    await transaction.revoke_user_sessions(user.id, revoked_at=now)
                    await record_security_event(
                        transaction,
                        SecurityEventType.ACCOUNT_ACTIVATED,
                        now,
                        user_id=user.id,
                        context=context,
                    )
        if result is None:
            raise invalid_email_link()
        return result

    async def _pending_user(
        self,
        email: str,
        display_name: str,
        roles: tuple[str, ...],
        now: datetime,
        *,
        scopes: tuple[str, ...] = (),
    ) -> UserAccount:
        normalized_scopes = normalize_capabilities(scopes, maximum=self.settings.max_scopes)
        unusable_password = secrets.token_urlsafe(self.settings.temporary_password_bytes)
        password_hash = await asyncio.to_thread(self.passwords.hash, unusable_password)
        return UserAccount(
            id=uuid4(),
            email=normalize_email(email),
            display_name=normalize_display_name(display_name),
            password_hash=password_hash,
            status=UserStatus.PENDING_ACTIVATION,
            roles=roles,
            scopes=normalized_scopes,
            password_login_enabled=False,
            created_at=now,
            updated_at=now,
        )

    async def _create(
        self,
        transaction: EmailLinkTransaction,
        user: UserAccount,
        now: datetime,
        context: RequestContext,
    ) -> AccountActivation:
        await transaction.insert_user(user)
        await record_security_event(
            transaction,
            SecurityEventType.USER_CREATED,
            now,
            user_id=user.id,
            context=context,
        )
        issue = await issue_link(
            transaction,
            self.settings,
            user,
            EmailLinkPurpose.ACTIVATION,
            now=now,
            context=context,
        )
        if issue.pending is None:
            raise RuntimeError("new account activation did not produce a pending link")
        return AccountActivation(user, issue.pending)


def _user_exists() -> AuthError:
    return AuthError(
        AuthErrorCode.USER_EXISTS,
        "A user with that email already exists.",
        status_code=409,
    )
