import asyncio
from dataclasses import replace
from datetime import datetime, timedelta
from uuid import UUID

from epok_auth._events import EMPTY_CONTEXT, record_security_event
from epok_auth._service_base import AuthServiceBase
from epok_auth._validation import (
    canonical_origin,
    normalize_capabilities,
    normalize_email_for_login,
)
from epok_auth.errores import (
    AuthError,
    AuthErrorCode,
    forbidden,
    invalid_credentials,
    invalid_csrf,
    invalid_session,
)
from epok_auth.models import (
    Principal,
    Reauthentication,
    ReauthenticationMethod,
    RequestContext,
    SecurityEventType,
    SecurityMetadata,
    SessionBundle,
    UserAccount,
)
from epok_auth.passwords import PasswordVerification
from epok_auth.sessions import principal_from_session, require_principal_user
from epok_auth.store import AuthTransaction
from epok_auth.tokens import clock_now, secure_token_equals, token_hash


class SessionServiceMethods(AuthServiceBase):
    async def login(
        self,
        email: str,
        password: str,
        *,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> SessionBundle:
        now = clock_now(self.clock)
        normalized_email = normalize_email_for_login(email)
        failure: AuthError | None = None
        result: SessionBundle | None = None
        async with self.store.transaction() as transaction:
            user = await transaction.get_user_by_email(normalized_email, for_update=True)
            verification = await asyncio.to_thread(
                self.passwords.verify_for_login,
                password,
                user.password_hash if user and user.password_login_enabled else None,
            )
            unavailable = (
                user is None or not user.password_login_enabled or not user.can_authenticate(now)
            )
            if unavailable or not verification.valid:
                await self._record_password_failure(
                    transaction,
                    SecurityEventType.LOGIN_FAILED,
                    user,
                    now,
                    context,
                )
                failure = invalid_credentials()
            else:
                if user is None:
                    raise invalid_credentials()
                user = await self._apply_password_verification(
                    transaction,
                    user,
                    verification,
                    now,
                )
                result = await self.session_issuer.issue(
                    transaction,
                    user,
                    now=now,
                    context=context,
                )
                await record_security_event(
                    transaction,
                    SecurityEventType.LOGIN_SUCCEEDED,
                    now=now,
                    user_id=user.id,
                    session_id=result.principal.session_id,
                    context=context,
                )
        if failure is not None:
            raise failure
        if result is None:  # pragma: no cover
            raise RuntimeError("login completed without a result")
        return result

    async def reauthenticate_password(
        self,
        principal: Principal,
        password: str,
        *,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> Reauthentication:
        now = clock_now(self.clock)
        failure: AuthError | None = None
        result: Reauthentication | None = None
        async with self.store.transaction() as transaction:
            user = await require_principal_user(transaction, principal, now, for_update=True)
            verification = await asyncio.to_thread(
                self.passwords.verify_for_login,
                password,
                user.password_hash if user.password_login_enabled else None,
            )
            if not user.password_login_enabled or not verification.valid:
                await self._record_password_failure(
                    transaction,
                    SecurityEventType.REAUTHENTICATION_FAILED,
                    user,
                    now,
                    context,
                    session_id=principal.session_id,
                    method=ReauthenticationMethod.PASSWORD,
                )
                failure = invalid_credentials()
            else:
                await self._apply_password_verification(transaction, user, verification, now)
                result = Reauthentication(
                    user_id=principal.user_id,
                    session_id=principal.session_id,
                    family_id=principal.family_id,
                    method=ReauthenticationMethod.PASSWORD,
                    verified_at=now,
                )
                await record_security_event(
                    transaction,
                    SecurityEventType.REAUTHENTICATION_SUCCEEDED,
                    now,
                    context,
                    user_id=principal.user_id,
                    session_id=principal.session_id,
                    metadata={"method": ReauthenticationMethod.PASSWORD.value},
                )
        if failure is not None:
            raise failure
        if result is None:  # pragma: no cover
            raise RuntimeError("password reauthentication completed without a result")
        return result

    async def authenticate(self, access_token: str) -> Principal:
        claims = self.signer.verify(access_token)
        now = clock_now(self.clock)
        async with self.store.transaction() as transaction:
            user = await transaction.get_user_by_id(claims.user_id)
            session = await transaction.get_session_by_id(claims.session_id)
        if (
            user is None
            or session is None
            or not user.can_authenticate(now)
            or not session.is_valid_for(claims, now)
        ):
            raise invalid_session()
        return principal_from_session(user, session)

    async def refresh(
        self,
        refresh_token: str,
        csrf_cookie: str,
        csrf_header: str,
        *,
        origin: str | None = None,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> SessionBundle:
        self.validate_origin(origin)
        self.validate_csrf_pair(csrf_cookie, csrf_header)
        now = clock_now(self.clock)
        failure: AuthError | None = None
        result: SessionBundle | None = None
        refresh_hash = token_hash(refresh_token)
        async with self.store.transaction() as transaction:
            candidate = await transaction.get_session_by_token_hash(refresh_hash)
            if candidate is None:
                failure = invalid_session()
            else:
                user = await transaction.get_user_by_id(candidate.user_id, for_update=True)
                session = await transaction.get_session_by_id(candidate.id, for_update=True)
                if (
                    session is None
                    or not secure_token_equals(session.token_hash, refresh_hash)
                    or session.revoked_at is not None
                ):
                    failure = invalid_session()
                elif session.used_at is not None:
                    await transaction.revoke_family(session.family_id, revoked_at=now)
                    await record_security_event(
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
                elif user is None or not user.can_authenticate(now):
                    await transaction.revoke_family(session.family_id, revoked_at=now)
                    failure = invalid_session()
                else:
                    result = await self.session_issuer.issue(
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
                    await record_security_event(
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
        context: RequestContext = EMPTY_CONTEXT,
    ) -> int:
        self.validate_origin(origin)
        if not refresh_token:
            return 0
        self.validate_csrf_pair(csrf_cookie or "", csrf_header or "")
        now = clock_now(self.clock)
        refresh_hash = token_hash(refresh_token)
        async with self.store.transaction() as transaction:
            candidate = await transaction.get_session_by_token_hash(refresh_hash)
            if candidate is None or candidate.revoked_at is not None:
                return 0
            user = await transaction.get_user_by_id(candidate.user_id, for_update=True)
            session = await transaction.get_session_by_id(candidate.id, for_update=True)
            if user is None or session is None or session.revoked_at is not None:
                return 0
            if not secure_token_equals(session.token_hash, refresh_hash):
                return 0
            if not secure_token_equals(session.csrf_hash, token_hash(csrf_cookie or "")):
                raise invalid_csrf()
            count = await transaction.revoke_family(session.family_id, revoked_at=now)
            await record_security_event(
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
        context: RequestContext = EMPTY_CONTEXT,
    ) -> SessionBundle:
        self.passwords.validate(new_password)
        now = clock_now(self.clock)
        async with self.store.transaction() as transaction:
            user = await require_principal_user(transaction, principal, now, for_update=True)
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
            user = user.activate_password(password_hash, now)
            await transaction.update_user(user)
            await transaction.revoke_user_sessions(user.id, revoked_at=now)
            result = await self.session_issuer.issue(
                transaction,
                user,
                now=now,
                context=context,
            )
            await record_security_event(
                transaction,
                SecurityEventType.PASSWORD_CHANGED,
                now=now,
                user_id=user.id,
                session_id=result.principal.session_id,
                context=context,
            )
            return result

    async def _record_password_failure(
        self,
        transaction: AuthTransaction,
        event_type: SecurityEventType,
        user: UserAccount | None,
        now: datetime,
        context: RequestContext,
        *,
        session_id: UUID | None = None,
        method: ReauthenticationMethod | None = None,
    ) -> None:
        if user is not None and user.password_login_enabled and user.can_authenticate(now):
            previous_attempts = (
                0 if user.locked_until and user.locked_until <= now else user.failed_login_attempts
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
            if locked_until is not None:
                user = user.advance_security_version(now)
            await transaction.update_user(user)
            if locked_until is not None:
                await transaction.revoke_user_sessions(user.id, revoked_at=now)
                await record_security_event(
                    transaction,
                    SecurityEventType.ACCOUNT_LOCKED,
                    now,
                    context,
                    user_id=user.id,
                )
        metadata: SecurityMetadata | None = None
        if method is not None:
            metadata = {"method": method.value}
        await record_security_event(
            transaction,
            event_type,
            now,
            context,
            user_id=user.id if user is not None else None,
            session_id=session_id,
            metadata=metadata,
        )

    @staticmethod
    async def _apply_password_verification(
        transaction: AuthTransaction,
        user: UserAccount,
        verification: PasswordVerification,
        now: datetime,
    ) -> UserAccount:
        updated = replace(
            user,
            password_hash=verification.updated_hash or user.password_hash,
            failed_login_attempts=0,
            locked_until=None,
            updated_at=now,
        )
        await transaction.update_user(updated)
        return updated

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
        if clock_now(self.clock) - principal.authenticated_at > timedelta(seconds=max_age_seconds):
            raise AuthError(
                AuthErrorCode.FORBIDDEN,
                "Recent authentication is required.",
                status_code=403,
            )
