from __future__ import annotations

import asyncio
import re
import secrets
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from email_validator import EmailNotValidError, validate_email

from epok_auth.config import AuthSettings
from epok_auth.errors import (
    AuthError,
    AuthErrorCode,
    forbidden,
    invalid_credentials,
    invalid_csrf,
    invalid_session,
)
from epok_auth.models import (
    Principal,
    ProvisionedUser,
    RefreshSession,
    RequestContext,
    SecurityEvent,
    SecurityEventType,
    SessionBundle,
    UserAccount,
    UserStatus,
    UserUpdate,
)
from epok_auth.passwords import PasswordManager
from epok_auth.store import AuthStore, AuthTransaction, StoreConflictError
from epok_auth.tokens import (
    AccessTokenSigner,
    Clock,
    HMACJWTSigner,
    create_csrf_token,
    create_refresh_token,
    secure_token_equals,
    token_hash,
    utc_now,
)

_CAPABILITY = re.compile(r"[a-z0-9][a-z0-9:._-]{0,99}")
_EMPTY_CONTEXT = RequestContext()


class AuthService:
    """Identity administration and PostgreSQL-authoritative session service."""

    def __init__(
        self,
        *,
        store: AuthStore,
        settings: AuthSettings,
        passwords: PasswordManager | None = None,
        signer: AccessTokenSigner | None = None,
        clock: Clock = utc_now,
    ) -> None:
        self.store = store
        self.settings = settings
        self.passwords = passwords or PasswordManager.recommended(
            minimum=settings.password_min_length,
            maximum=settings.password_max_length,
        )
        self.clock = clock
        self.signer = signer or HMACJWTSigner(
            secret=settings.jwt_secret.get_secret_value(),
            issuer=settings.issuer,
            audience=settings.audience,
            access_ttl_seconds=settings.access_ttl_seconds,
            algorithm=settings.jwt_algorithm,
            leeway_seconds=settings.jwt_leeway_seconds,
            max_token_chars=settings.max_access_token_chars,
            clock=clock,
        )

    async def create_admin(
        self,
        *,
        email: str,
        display_name: str,
        password: str,
        context: RequestContext = _EMPTY_CONTEXT,
    ) -> UserAccount:
        now = self._now()
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
                await self._event(
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
        context: RequestContext = _EMPTY_CONTEXT,
    ) -> ProvisionedUser:
        now = self._now()
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
            password_changed_at=now,
            created_at=now,
            updated_at=now,
        )
        try:
            async with self.store.transaction() as transaction:
                await transaction.insert_user(user)
                await self._event(
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
        context: RequestContext = _EMPTY_CONTEXT,
    ) -> UserAccount:
        now = self._now()
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
            updated = replace(
                current,
                display_name=display_name,
                status=status,
                roles=roles,
                scopes=scopes,
                updated_at=now,
            )
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
            await self._event(
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
        context: RequestContext = _EMPTY_CONTEXT,
    ) -> ProvisionedUser:
        now = self._now()
        temporary_password = secrets.token_urlsafe(self.settings.temporary_password_bytes)
        password_hash = await asyncio.to_thread(self.passwords.hash, temporary_password)
        async with self.store.transaction() as transaction:
            current = await transaction.get_user_by_id(user_id, for_update=True)
            if current is None:
                raise AuthError(AuthErrorCode.USER_NOT_FOUND, "User not found.", status_code=404)
            updated = replace(
                current,
                password_hash=password_hash,
                must_change_password=True,
                failed_login_attempts=0,
                locked_until=None,
                password_changed_at=now,
                updated_at=now,
            )
            await transaction.update_user(updated)
            await transaction.revoke_user_sessions(user_id, revoked_at=now)
            await self._event(
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
        context: RequestContext = _EMPTY_CONTEXT,
    ) -> int:
        now = self._now()
        async with self.store.transaction() as transaction:
            if await transaction.get_user_by_id(user_id) is None:
                raise AuthError(AuthErrorCode.USER_NOT_FOUND, "User not found.", status_code=404)
            count = await transaction.revoke_user_sessions(user_id, revoked_at=now)
            await self._event(
                transaction,
                SecurityEventType.SESSIONS_REVOKED,
                now=now,
                user_id=user_id,
                context=context,
                metadata={"count": count},
            )
            return count

    async def login(
        self,
        email: str,
        password: str,
        *,
        context: RequestContext = _EMPTY_CONTEXT,
    ) -> SessionBundle:
        now = self._now()
        normalized_email = normalize_email_for_login(email)
        failure: AuthError | None = None
        result: SessionBundle | None = None
        async with self.store.transaction() as transaction:
            user = await transaction.get_user_by_email(normalized_email, for_update=True)
            verification = await asyncio.to_thread(
                self.passwords.verify_for_login,
                password,
                user.password_hash if user else None,
            )
            unavailable = (
                user is None
                or user.status is not UserStatus.ACTIVE
                or bool(user.locked_until and user.locked_until > now)
            )
            if unavailable or not verification.valid:
                if (
                    user is not None
                    and user.status is UserStatus.ACTIVE
                    and not (user.locked_until and user.locked_until > now)
                ):
                    previous_attempts = (
                        0
                        if user.locked_until and user.locked_until <= now
                        else user.failed_login_attempts
                    )
                    attempts = previous_attempts + 1
                    locked_until = (
                        now + timedelta(seconds=self.settings.lockout_seconds)
                        if attempts >= self.settings.login_max_attempts
                        else None
                    )
                    user = replace(
                        user,
                        failed_login_attempts=attempts,
                        locked_until=locked_until,
                        updated_at=now,
                    )
                    await transaction.update_user(user)
                    if locked_until is not None:
                        await transaction.revoke_user_sessions(user.id, revoked_at=now)
                        await self._event(
                            transaction,
                            SecurityEventType.ACCOUNT_LOCKED,
                            now=now,
                            user_id=user.id,
                            context=context,
                        )
                await self._event(
                    transaction,
                    SecurityEventType.LOGIN_FAILED,
                    now=now,
                    user_id=user.id if user else None,
                    context=context,
                )
                failure = invalid_credentials()
            else:
                assert user is not None
                updated_hash = verification.updated_hash or user.password_hash
                user = replace(
                    user,
                    password_hash=updated_hash,
                    failed_login_attempts=0,
                    locked_until=None,
                    updated_at=now,
                )
                await transaction.update_user(user)
                result = await self._start_session(transaction, user, now=now, context=context)
                await self._event(
                    transaction,
                    SecurityEventType.LOGIN_SUCCEEDED,
                    now=now,
                    user_id=user.id,
                    session_id=result.principal.session_id,
                    context=context,
                )
        if failure is not None:
            raise failure
        if result is None:  # pragma: no cover - defensive invariant
            raise RuntimeError("login completed without a result")
        return result

    async def authenticate(self, access_token: str) -> Principal:
        claims = self.signer.verify(access_token)
        now = self._now()
        async with self.store.transaction() as transaction:
            user = await transaction.get_user_by_id(claims.user_id)
            session = await transaction.get_session_by_id(claims.session_id)
        if (
            user is None
            or session is None
            or user.status is not UserStatus.ACTIVE
            or bool(user.locked_until and user.locked_until > now)
            or session.user_id != user.id
            or session.family_id != claims.family_id
            or session.revoked_at is not None
            or session.idle_expires_at <= now
            or session.absolute_expires_at <= now
            or abs((session.authenticated_at - claims.authenticated_at).total_seconds()) > 1
        ):
            raise invalid_session()
        return self._principal(user, session)

    async def refresh(
        self,
        refresh_token: str,
        csrf_cookie: str,
        csrf_header: str,
        *,
        origin: str | None = None,
        context: RequestContext = _EMPTY_CONTEXT,
    ) -> SessionBundle:
        self.validate_origin(origin)
        self.validate_csrf_pair(csrf_cookie, csrf_header)
        now = self._now()
        failure: AuthError | None = None
        result: SessionBundle | None = None
        async with self.store.transaction() as transaction:
            session = await transaction.get_session_by_token_hash(
                token_hash(refresh_token),
                for_update=True,
            )
            if session is None or session.revoked_at is not None:
                failure = invalid_session()
            elif session.used_at is not None:
                await transaction.revoke_family(session.family_id, revoked_at=now)
                await self._event(
                    transaction,
                    SecurityEventType.REFRESH_REUSE_DETECTED,
                    now=now,
                    user_id=session.user_id,
                    session_id=session.id,
                    context=context,
                )
                failure = invalid_session()
            elif session.idle_expires_at <= now or session.absolute_expires_at <= now:
                await transaction.revoke_family(session.family_id, revoked_at=now)
                failure = invalid_session()
            elif not secure_token_equals(session.csrf_hash, token_hash(csrf_cookie)):
                failure = invalid_csrf()
            else:
                user = await transaction.get_user_by_id(session.user_id, for_update=True)
                if (
                    user is None
                    or user.status is not UserStatus.ACTIVE
                    or bool(user.locked_until and user.locked_until > now)
                ):
                    await transaction.revoke_family(session.family_id, revoked_at=now)
                    failure = invalid_session()
                else:
                    result = await self._start_session(
                        transaction,
                        user,
                        now=now,
                        family_id=session.family_id,
                        absolute_expires_at=session.absolute_expires_at,
                        authenticated_at=session.authenticated_at,
                        context=context,
                    )
                    await transaction.update_session(
                        replace(
                            session,
                            used_at=now,
                            replaced_by_id=result.principal.session_id,
                        )
                    )
                    await self._event(
                        transaction,
                        SecurityEventType.REFRESH_ROTATED,
                        now=now,
                        user_id=user.id,
                        session_id=result.principal.session_id,
                        context=context,
                    )
        if failure is not None:
            raise failure
        if result is None:  # pragma: no cover
            raise RuntimeError("refresh completed without a result")
        return result

    async def logout(
        self,
        refresh_token: str | None,
        csrf_cookie: str | None,
        csrf_header: str | None,
        *,
        origin: str | None = None,
        context: RequestContext = _EMPTY_CONTEXT,
    ) -> int:
        self.validate_origin(origin)
        if not refresh_token:
            return 0
        self.validate_csrf_pair(csrf_cookie or "", csrf_header or "")
        now = self._now()
        async with self.store.transaction() as transaction:
            session = await transaction.get_session_by_token_hash(
                token_hash(refresh_token),
                for_update=True,
            )
            if session is None or session.revoked_at is not None:
                return 0
            if not secure_token_equals(session.csrf_hash, token_hash(csrf_cookie or "")):
                raise invalid_csrf()
            count = await transaction.revoke_family(session.family_id, revoked_at=now)
            await self._event(
                transaction,
                SecurityEventType.LOGOUT,
                now=now,
                user_id=session.user_id,
                session_id=session.id,
                context=context,
            )
            return count

    async def change_password(
        self,
        principal: Principal,
        current_password: str,
        new_password: str,
        *,
        context: RequestContext = _EMPTY_CONTEXT,
    ) -> SessionBundle:
        self.passwords.validate(new_password)
        now = self._now()
        async with self.store.transaction() as transaction:
            user = await transaction.get_user_by_id(principal.user_id, for_update=True)
            session = await transaction.get_session_by_id(principal.session_id, for_update=True)
            if (
                user is None
                or session is None
                or user.status is not UserStatus.ACTIVE
                or session.user_id != user.id
                or session.family_id != principal.family_id
                or abs((session.authenticated_at - principal.authenticated_at).total_seconds()) > 1
                or session.revoked_at is not None
                or session.idle_expires_at <= now
                or session.absolute_expires_at <= now
            ):
                raise invalid_session()
            verification = await asyncio.to_thread(
                self.passwords.verify,
                current_password,
                user.password_hash,
            )
            if not verification.valid:
                raise invalid_credentials()
            same_password = await asyncio.to_thread(
                self.passwords.verify,
                new_password,
                user.password_hash,
            )
            if same_password.valid:
                raise AuthError(
                    AuthErrorCode.PASSWORD_INVALID,
                    "The new password must be different.",
                    status_code=422,
                )
            password_hash = await asyncio.to_thread(self.passwords.hash, new_password)
            user = replace(
                user,
                password_hash=password_hash,
                must_change_password=False,
                failed_login_attempts=0,
                locked_until=None,
                password_changed_at=now,
                updated_at=now,
            )
            await transaction.update_user(user)
            await transaction.revoke_user_sessions(user.id, revoked_at=now)
            result = await self._start_session(transaction, user, now=now, context=context)
            await self._event(
                transaction,
                SecurityEventType.PASSWORD_CHANGED,
                now=now,
                user_id=user.id,
                session_id=result.principal.session_id,
                context=context,
            )
            return result

    def validate_csrf_pair(self, cookie: str, header: str) -> None:
        if not cookie or not header or not secure_token_equals(cookie, header):
            raise invalid_csrf()

    def validate_origin(self, origin: str | None) -> None:
        if not self.settings.require_origin and origin is None:
            return
        if origin is None:
            raise AuthError(AuthErrorCode.INVALID_ORIGIN, "Origin is required.", status_code=403)
        normalized = canonical_origin(origin)
        if normalized not in self.settings.trusted_origins:
            raise AuthError(AuthErrorCode.INVALID_ORIGIN, "Origin is not trusted.", status_code=403)

    def require_roles(self, principal: Principal, *roles: str) -> None:
        expected = normalize_capabilities(roles, maximum=self.settings.max_roles)
        if not all(principal.has_role(role) for role in expected):
            raise forbidden()

    def require_scopes(self, principal: Principal, *scopes: str) -> None:
        expected = normalize_capabilities(scopes, maximum=self.settings.max_scopes)
        if not all(principal.has_scope(scope) for scope in expected):
            raise forbidden()

    def require_recent_authentication(self, principal: Principal, *, max_age_seconds: int) -> None:
        if max_age_seconds < 0:
            raise ValueError("max_age_seconds must be non-negative")
        if self._now() - principal.authenticated_at > timedelta(seconds=max_age_seconds):
            raise AuthError(
                AuthErrorCode.FORBIDDEN,
                "Recent authentication is required.",
                status_code=403,
            )

    async def _start_session(
        self,
        transaction: AuthTransaction,
        user: UserAccount,
        *,
        now: datetime,
        family_id: UUID | None = None,
        absolute_expires_at: datetime | None = None,
        authenticated_at: datetime | None = None,
        context: RequestContext = _EMPTY_CONTEXT,
    ) -> SessionBundle:
        session_id = uuid4()
        family_id = family_id or uuid4()
        authenticated_at = authenticated_at or now
        absolute_expires_at = absolute_expires_at or (
            now + timedelta(seconds=self.settings.refresh_absolute_ttl_seconds)
        )
        idle_expires_at = min(
            now + timedelta(seconds=self.settings.refresh_idle_ttl_seconds),
            absolute_expires_at,
        )
        refresh_token = create_refresh_token()
        csrf_token = create_csrf_token()
        session = RefreshSession(
            id=session_id,
            user_id=user.id,
            family_id=family_id,
            token_hash=token_hash(refresh_token),
            csrf_hash=token_hash(csrf_token),
            created_at=now,
            idle_expires_at=idle_expires_at,
            absolute_expires_at=absolute_expires_at,
            authenticated_at=authenticated_at,
        )
        await transaction.insert_session(session)
        principal = self._principal(user, session)
        access_token, _ = self.signer.issue(principal, now=now)
        await self._event(
            transaction,
            SecurityEventType.SESSION_CREATED,
            now=now,
            user_id=user.id,
            session_id=session_id,
            context=context,
        )
        return SessionBundle(
            access_token=access_token,
            access_expires_in=self.settings.access_ttl_seconds,
            refresh_token=refresh_token,
            csrf_token=csrf_token,
            refresh_idle_expires_at=idle_expires_at,
            refresh_absolute_expires_at=absolute_expires_at,
            principal=principal,
        )

    @staticmethod
    def _principal(user: UserAccount, session: RefreshSession) -> Principal:
        return Principal(
            user_id=user.id,
            session_id=session.id,
            family_id=session.family_id,
            email=user.email,
            display_name=user.display_name,
            roles=user.roles,
            scopes=user.scopes,
            must_change_password=user.must_change_password,
            authenticated_at=session.authenticated_at,
        )

    async def _event(
        self,
        transaction: AuthTransaction,
        event_type: SecurityEventType,
        *,
        now: datetime,
        user_id: UUID | None = None,
        session_id: UUID | None = None,
        context: RequestContext = _EMPTY_CONTEXT,
        metadata: dict[str, str | int | bool | None] | None = None,
    ) -> None:
        await transaction.add_security_event(
            SecurityEvent(
                event_type=event_type,
                occurred_at=now,
                user_id=user_id,
                session_id=session_id,
                request_id=_bounded(context.request_id, 200),
                ip_address=_bounded(context.ip_address, 64),
                user_agent=_bounded(context.user_agent, 500),
                metadata=metadata or {},
            )
        )

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None:
            raise ValueError("clock must return a timezone-aware datetime")
        return value.astimezone(UTC)


def normalize_email(value: str) -> str:
    try:
        normalized = validate_email(value.strip(), check_deliverability=False).normalized
    except EmailNotValidError as error:
        raise AuthError(
            AuthErrorCode.INPUT_INVALID, "Email is not valid.", status_code=422
        ) from error
    return normalized.casefold()


def normalize_email_for_login(value: str) -> str:
    try:
        return normalize_email(value)
    except AuthError:
        # Deliberately map malformed login identifiers into the same credential response.
        return value.strip().casefold()[:320]


def normalize_display_name(value: str) -> str:
    normalized = " ".join(value.split())
    if not 1 <= len(normalized) <= 200 or any(ord(character) < 32 for character in normalized):
        raise AuthError(AuthErrorCode.INPUT_INVALID, "Display name is not valid.", status_code=422)
    return normalized


def normalize_capabilities(values: Sequence[str], *, maximum: int) -> tuple[str, ...]:
    if len(values) > maximum:
        raise AuthError(AuthErrorCode.INPUT_INVALID, "Too many capabilities.", status_code=422)
    if any(not value.strip() for value in values):
        raise AuthError(
            AuthErrorCode.INPUT_INVALID, "Capability syntax is not valid.", status_code=422
        )
    normalized = tuple(sorted({value.strip().casefold() for value in values}))
    if any(_CAPABILITY.fullmatch(value) is None for value in normalized):
        raise AuthError(
            AuthErrorCode.INPUT_INVALID, "Capability syntax is not valid.", status_code=422
        )
    return normalized


def canonical_origin(origin: str) -> str:
    try:
        parsed = urlsplit(origin.strip().rstrip("/"))
        host = (parsed.hostname or "").casefold()
        scheme = parsed.scheme.casefold()
        port = parsed.port
    except ValueError:
        return ""
    if (
        scheme not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        return ""
    default_port = (scheme == "https" and port in (None, 443)) or (
        scheme == "http" and port in (None, 80)
    )
    return f"{scheme}://{host}" if default_port else f"{scheme}://{host}:{port}"


def _bounded(value: str | None, maximum: int) -> str | None:
    if value is None:
        return None
    return value[:maximum]
