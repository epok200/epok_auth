import asyncio
import secrets
from collections.abc import Sequence
from dataclasses import replace
from uuid import UUID, uuid4

from epok_auth._events import EMPTY_CONTEXT, record_security_event
from epok_auth._service_base import AuthServiceBase
from epok_auth._validation import normalize_capabilities, normalize_display_name, normalize_email
from epok_auth.errores import AuthError, AuthErrorCode
from epok_auth.models import (
    ProvisionedUser,
    RequestContext,
    SecurityEventType,
    UserAccount,
    UserStatus,
    UserUpdate,
)
from epok_auth.store import StoreConflictError
from epok_auth.tokens import clock_now


class UserServiceMethods(AuthServiceBase):
    async def create_admin(
        self,
        *,
        email: str,
        display_name: str,
        password: str,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> UserAccount:
        now = clock_now(self.clock)
        normalized_email = normalize_email(email)
        normalized_name = normalize_display_name(display_name)
        password_hash = await asyncio.to_thread(self.passwords.hash, password)
        user = UserAccount(
            id=uuid4(),
            email=normalized_email,
            display_name=normalized_name,
            password_hash=password_hash,
            roles=(self.settings.admin_role,),
            scopes=("auth:admin",),
            must_change_password=False,
            password_changed_at=now,
            created_at=now,
            updated_at=now,
        )
        try:
            async with self.store.transaction() as transaction:
                await transaction.acquire_admin_invariant_lock()
                if await transaction.count_users_with_role(
                    self.settings.admin_role,
                    active_only=False,
                ):
                    raise AuthError(
                        AuthErrorCode.ADMIN_EXISTS,
                        "The initial administrator already exists.",
                        status_code=409,
                    )
                await transaction.insert_user(user)
                await record_security_event(
                    transaction,
                    SecurityEventType.ADMIN_CREATED,
                    now=now,
                    user_id=user.id,
                    context=context,
                )
        except StoreConflictError as error:
            raise AuthError(
                AuthErrorCode.USER_EXISTS,
                "A user with that email already exists.",
                status_code=409,
            ) from error
        return user

    async def create_user(
        self,
        *,
        email: str,
        display_name: str,
        roles: Sequence[str] | None = None,
        scopes: Sequence[str] = (),
        google_auto_link_allowed: bool = False,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> ProvisionedUser:
        now = clock_now(self.clock)
        normalized_roles = normalize_capabilities(
            roles if roles is not None else (self.settings.default_user_role,),
            maximum=self.settings.max_roles,
        )
        normalized_scopes = normalize_capabilities(scopes, maximum=self.settings.max_scopes)
        temporary_password = secrets.token_urlsafe(self.settings.temporary_password_bytes)
        password_hash = await asyncio.to_thread(self.passwords.hash, temporary_password)
        user = UserAccount(
            id=uuid4(),
            email=normalize_email(email),
            display_name=normalize_display_name(display_name),
            password_hash=password_hash,
            roles=normalized_roles,
            scopes=normalized_scopes,
            must_change_password=True,
            google_auto_link_allowed=google_auto_link_allowed,
            password_changed_at=now,
            created_at=now,
            updated_at=now,
        )
        try:
            async with self.store.transaction() as transaction:
                await transaction.insert_user(user)
                await record_security_event(
                    transaction,
                    SecurityEventType.USER_CREATED,
                    now=now,
                    user_id=user.id,
                    context=context,
                )
        except StoreConflictError as error:
            raise AuthError(
                AuthErrorCode.USER_EXISTS,
                "A user with that email already exists.",
                status_code=409,
            ) from error
        return ProvisionedUser(user=user, temporary_password=temporary_password)

    async def list_users(self, *, limit: int = 100, offset: int = 0) -> Sequence[UserAccount]:
        if not 1 <= limit <= 500 or offset < 0:
            raise AuthError(AuthErrorCode.INPUT_INVALID, "Invalid pagination.", status_code=422)
        async with self.store.transaction() as transaction:
            return await transaction.list_users(limit=limit, offset=offset)

    async def get_user(self, user_id: UUID) -> UserAccount:
        async with self.store.transaction() as transaction:
            user = await transaction.get_user_by_id(user_id)
        if user is None:
            raise AuthError(AuthErrorCode.USER_NOT_FOUND, "User not found.", status_code=404)
        return user

    async def update_user(
        self,
        user_id: UUID,
        update: UserUpdate,
        *,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> UserAccount:
        now = clock_now(self.clock)
        async with self.store.transaction() as transaction:
            await transaction.acquire_admin_invariant_lock()
            current = await transaction.get_user_by_id(user_id, for_update=True)
            if current is None:
                raise AuthError(AuthErrorCode.USER_NOT_FOUND, "User not found.", status_code=404)
            roles = (
                normalize_capabilities(update.roles, maximum=self.settings.max_roles)
                if update.roles is not None
                else current.roles
            )
            scopes = (
                normalize_capabilities(update.scopes, maximum=self.settings.max_scopes)
                if update.scopes is not None
                else current.scopes
            )
            status = update.status or current.status
            display_name = (
                normalize_display_name(update.display_name)
                if update.display_name is not None
                else current.display_name
            )
            google_auto_link_allowed = (
                update.google_auto_link_allowed
                if update.google_auto_link_allowed is not None
                else current.google_auto_link_allowed
            )
            email_link_login_enabled = (
                update.email_link_login_enabled
                if update.email_link_login_enabled is not None
                else current.email_link_login_enabled
            )
            loses_active_admin = (
                current.status is UserStatus.ACTIVE
                and self.settings.admin_role in current.roles
                and (status is not UserStatus.ACTIVE or self.settings.admin_role not in roles)
            )
            if (
                loses_active_admin
                and await transaction.count_users_with_role(
                    self.settings.admin_role,
                    active_only=True,
                )
                <= 1
            ):
                raise AuthError(
                    AuthErrorCode.LAST_ADMIN_REQUIRED,
                    "At least one active administrator is required.",
                    status_code=409,
                )
            security_changed = (
                status is not current.status
                or roles != current.roles
                or scopes != current.scopes
                or google_auto_link_allowed != current.google_auto_link_allowed
                or email_link_login_enabled != current.email_link_login_enabled
            )
            updated = replace(
                current,
                display_name=display_name,
                status=status,
                roles=roles,
                scopes=scopes,
                google_auto_link_allowed=google_auto_link_allowed,
                email_link_login_enabled=email_link_login_enabled,
                updated_at=now,
            )
            if security_changed:
                updated = updated.advance_security_version(now)
            await transaction.update_user(updated)
            event_type = SecurityEventType.USER_UPDATED
            if current.status is not status:
                event_type = (
                    SecurityEventType.USER_DISABLED
                    if status is UserStatus.DISABLED
                    else SecurityEventType.USER_ENABLED
                )
            if status is UserStatus.DISABLED:
                await transaction.revoke_user_sessions(user_id, revoked_at=now)
            await record_security_event(
                transaction,
                event_type,
                now=now,
                user_id=user_id,
                context=context,
            )
            return updated

    async def reset_password(
        self,
        user_id: UUID,
        *,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> ProvisionedUser:
        now = clock_now(self.clock)
        temporary_password = secrets.token_urlsafe(self.settings.temporary_password_bytes)
        password_hash = await asyncio.to_thread(self.passwords.hash, temporary_password)
        async with self.store.transaction() as transaction:
            current = await transaction.get_user_by_id(user_id, for_update=True)
            if current is None:
                raise AuthError(AuthErrorCode.USER_NOT_FOUND, "User not found.", status_code=404)
            updated = current.require_password_change(password_hash, now)
            await transaction.update_user(updated)
            await transaction.revoke_user_sessions(user_id, revoked_at=now)
            await record_security_event(
                transaction,
                SecurityEventType.PASSWORD_RESET,
                now=now,
                user_id=user_id,
                context=context,
            )
        return ProvisionedUser(user=updated, temporary_password=temporary_password)

    async def revoke_user_sessions(
        self,
        user_id: UUID,
        *,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> int:
        now = clock_now(self.clock)
        async with self.store.transaction() as transaction:
            if await transaction.get_user_by_id(user_id) is None:
                raise AuthError(AuthErrorCode.USER_NOT_FOUND, "User not found.", status_code=404)
            count = await transaction.revoke_user_sessions(user_id, revoked_at=now)
            await record_security_event(
                transaction,
                SecurityEventType.SESSIONS_REVOKED,
                now=now,
                user_id=user_id,
                context=context,
                metadata={"count": count},
            )
            return count
