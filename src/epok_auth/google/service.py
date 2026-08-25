import asyncio
import secrets
from dataclasses import replace
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from epok_auth._events import EMPTY_CONTEXT, record_security_event
from epok_auth.config import AuthSettings, GoogleAccountMode
from epok_auth.errores import (
    AuthError,
    AuthErrorCode,
    forbidden,
    google_identity_conflict,
    invalid_google_credentials,
    invalid_session,
)
from epok_auth.google.adapter import (
    GoogleServiceUnavailableError,
    GoogleTokenVerifier,
    GoogleVerificationError,
)
from epok_auth.google.challenges import GoogleChallengeService
from epok_auth.google.models import (
    GOOGLE_ISSUER,
    ExternalIdentity,
    GoogleChallenge,
    GoogleChallengePurpose,
    GoogleClaims,
    GoogleOptions,
)
from epok_auth.google.policy import GoogleAccountPolicy
from epok_auth.google.store import GoogleStore, GoogleTransaction
from epok_auth.models import (
    Principal,
    ProvisionedUser,
    RequestContext,
    SecurityEventType,
    SecurityMetadata,
    SessionBundle,
    UserAccount,
)
from epok_auth.passwords import PasswordManager
from epok_auth.sessions import SessionIssuer
from epok_auth.store import StoreConflictError
from epok_auth.tokens import AccessTokenSigner, Clock, clock_now, utc_now


class GoogleLoginService:
    """Google identity linking and login with product-selectable account policy."""

    def __init__(
        self,
        *,
        store: GoogleStore,
        settings: AuthSettings,
        signer: AccessTokenSigner,
        verifier: GoogleTokenVerifier,
        passwords: PasswordManager,
        clock: Clock = utc_now,
    ) -> None:
        if settings.google_client_id is None:
            raise ValueError("google_client_id is required when Google Sign-In is enabled")
        self.store = store
        self.settings = settings
        self.signer = signer
        self.verifier = verifier
        self.passwords = passwords
        self.clock = clock
        self.policy = GoogleAccountPolicy(settings)
        self.session_issuer = SessionIssuer(settings=settings, signer=signer)
        self.challenges = GoogleChallengeService(store=store, settings=settings, clock=clock)

    async def begin_login(self, origin: str | None) -> GoogleOptions:
        return await self.challenges.begin(GoogleChallengePurpose.LOGIN, origin)

    async def finish_login(
        self,
        challenge_id: UUID,
        credential: str,
        origin: str | None,
        *,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> SessionBundle:
        now = clock_now(self.clock)
        challenge = await self.challenges.consume(
            challenge_id,
            GoogleChallengePurpose.LOGIN,
            origin,
        )
        claims = await self._verify(credential, challenge, context)
        try:
            return await self._login(claims, now, context)
        except StoreConflictError:
            return await self._login_linked_after_conflict(claims, now, context)

    async def begin_link(self, principal: Principal, origin: str | None) -> GoogleOptions:
        self._require_recent_authentication(principal)
        return await self.challenges.begin(
            GoogleChallengePurpose.LINK,
            origin,
            user_id=principal.user_id,
        )

    async def finish_link(
        self,
        principal: Principal,
        challenge_id: UUID,
        credential: str,
        origin: str | None,
        *,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> ExternalIdentity:
        self._require_recent_authentication(principal)
        now = clock_now(self.clock)
        challenge = await self.challenges.consume(
            challenge_id,
            GoogleChallengePurpose.LINK,
            origin,
            user_id=principal.user_id,
        )
        claims = await self._verify(credential, challenge, context, linking=True)
        try:
            return await self._link(principal, claims, now, context)
        except StoreConflictError:
            return await self._linked_after_conflict(principal, claims, now, context)

    async def recover_password_access(
        self,
        user_id: UUID,
        *,
        context: RequestContext = EMPTY_CONTEXT,
    ) -> ProvisionedUser:
        now = clock_now(self.clock)
        temporary_password = secrets.token_urlsafe(self.settings.temporary_password_bytes)
        password_hash = await asyncio.to_thread(self.passwords.hash, temporary_password)
        async with self.store.transaction() as transaction:
            identity = await transaction.get_external_identity_for_user(
                user_id,
                GOOGLE_ISSUER,
                for_update=True,
            )
            user = await transaction.get_user_by_id(user_id, for_update=True)
            if user is None:
                raise AuthError(AuthErrorCode.USER_NOT_FOUND, "User not found.")
            if identity is None:
                raise AuthError(
                    AuthErrorCode.GOOGLE_IDENTITY_NOT_FOUND,
                    "Google identity not found.",
                )
            recovered = user.require_password_change(password_hash, now)
            await transaction.update_user(recovered)
            await transaction.delete_external_identity(identity.id)
            await transaction.revoke_user_sessions(user_id, revoked_at=now)
            await record_security_event(
                transaction,
                SecurityEventType.GOOGLE_RECOVERY_COMPLETED,
                now,
                context,
                user_id=user_id,
            )
        return ProvisionedUser(user=recovered, temporary_password=temporary_password)

    async def _verify(
        self,
        credential: str,
        challenge: GoogleChallenge,
        context: RequestContext,
        *,
        linking: bool = False,
    ) -> GoogleClaims:
        if len(credential) > self.settings.google_max_credential_chars:
            await self._verification_failure(linking, context)
            raise invalid_google_credentials()
        try:
            claims = await asyncio.to_thread(
                self.verifier.verify,
                credential,
                audience=challenge.client_id,
                nonce=challenge.nonce,
            )
            return self.policy.validate(claims)
        except GoogleServiceUnavailableError as error:
            await self._verification_failure(linking, context, provider_unavailable=True)
            raise AuthError(
                AuthErrorCode.GOOGLE_SERVICE_UNAVAILABLE,
                "Google authentication is temporarily unavailable.",
            ) from error
        except (AuthError, GoogleVerificationError) as error:
            await self._verification_failure(linking, context)
            raise invalid_google_credentials() from error

    async def _login(
        self,
        claims: GoogleClaims,
        now: datetime,
        context: RequestContext,
    ) -> SessionBundle:
        failure = False
        result = None
        async with self.store.transaction() as transaction:
            identity = await transaction.get_external_identity(
                GOOGLE_ISSUER,
                claims.subject,
                for_update=True,
            )
            if identity is not None:
                result = await self._login_linked(transaction, identity, claims, now, context)
            else:
                result = await self._login_unlinked(transaction, claims, now, context)
            if result is None:
                failure = True
                await record_security_event(
                    transaction,
                    SecurityEventType.GOOGLE_LOGIN_FAILED,
                    now,
                    context,
                )
        if failure or result is None:
            raise invalid_google_credentials()
        return result

    async def _login_linked_after_conflict(
        self,
        claims: GoogleClaims,
        now: datetime,
        context: RequestContext,
    ) -> SessionBundle:
        async with self.store.transaction() as transaction:
            identity = await transaction.get_external_identity(
                GOOGLE_ISSUER,
                claims.subject,
                for_update=True,
            )
            if identity is None:
                raise invalid_google_credentials()
            result = await self._login_linked(transaction, identity, claims, now, context)
        if result is None:
            raise invalid_google_credentials()
        return result

    async def _login_linked(
        self,
        transaction: GoogleTransaction,
        identity: ExternalIdentity,
        claims: GoogleClaims,
        now: datetime,
        context: RequestContext,
    ) -> SessionBundle | None:
        user = await transaction.get_user_by_id(identity.user_id, for_update=True)
        if user is None or not user.can_authenticate(now):
            return None
        latest_login = max(now, identity.last_login_at or identity.created_at)
        await transaction.update_external_identity(
            replace(identity, email=claims.email, last_login_at=latest_login)
        )
        result = await self.session_issuer.issue(
            transaction,
            user,
            now=now,
            context=context,
        )
        await record_security_event(
            transaction,
            SecurityEventType.GOOGLE_LOGIN_SUCCEEDED,
            now,
            context,
            user_id=user.id,
            session_id=result.principal.session_id,
        )
        return result

    async def _login_unlinked(
        self,
        transaction: GoogleTransaction,
        claims: GoogleClaims,
        now: datetime,
        context: RequestContext,
    ) -> SessionBundle | None:
        mode = self.settings.google_account_mode
        if mode is GoogleAccountMode.LINKED_ONLY:
            return None
        if mode is GoogleAccountMode.PREAUTHORIZED:
            return await self._login_preauthorized(transaction, claims, now, context)
        if mode is GoogleAccountMode.OPEN:
            return await self._login_open(transaction, claims, now, context)
        raise ValueError(f"Unsupported Google account mode: {mode}")

    async def _login_preauthorized(
        self,
        transaction: GoogleTransaction,
        claims: GoogleClaims,
        now: datetime,
        context: RequestContext,
    ) -> SessionBundle | None:
        if not self.policy.is_authoritative(claims) or claims.email is None:
            return None
        user = await transaction.get_user_by_email(claims.email, for_update=True)
        if user is None or not self.policy.can_auto_link(user, claims, now):
            return None
        return await self._link_and_login(transaction, user, claims, now, context)

    async def _login_open(
        self,
        transaction: GoogleTransaction,
        claims: GoogleClaims,
        now: datetime,
        context: RequestContext,
    ) -> SessionBundle | None:
        if not self.policy.is_authoritative(claims) or claims.email is None:
            return None
        user = await transaction.get_user_by_email(claims.email, for_update=True)
        if user is not None:
            if not self.policy.can_auto_link(user, claims, now):
                return None
            return await self._link_and_login(transaction, user, claims, now, context)
        user = await self._create_open_user(transaction, claims, now, context)
        return await self._insert_identity_and_login(transaction, user, claims, now, context)

    async def _link_and_login(
        self,
        transaction: GoogleTransaction,
        user: UserAccount,
        claims: GoogleClaims,
        now: datetime,
        context: RequestContext,
    ) -> SessionBundle:
        unusable_password = secrets.token_urlsafe(self.settings.temporary_password_bytes)
        password_hash = await asyncio.to_thread(self.passwords.hash, unusable_password)
        linked_user = user.disable_password(password_hash, now)
        await transaction.update_user(linked_user)
        return await self._insert_identity_and_login(
            transaction,
            linked_user,
            claims,
            now,
            context,
        )

    async def _create_open_user(
        self,
        transaction: GoogleTransaction,
        claims: GoogleClaims,
        now: datetime,
        context: RequestContext,
    ) -> UserAccount:
        email = claims.email
        if email is None:
            raise invalid_google_credentials()
        unusable_password = secrets.token_urlsafe(self.settings.temporary_password_bytes)
        password_hash = await asyncio.to_thread(self.passwords.hash, unusable_password)
        user = UserAccount(
            id=uuid4(),
            email=email,
            display_name=self.policy.display_name(claims),
            password_hash=password_hash,
            roles=(self.settings.default_user_role,),
            scopes=(),
            must_change_password=False,
            password_login_enabled=False,
            google_auto_link_allowed=False,
            password_changed_at=now,
            created_at=now,
            updated_at=now,
        )
        await transaction.insert_user(user)
        await record_security_event(
            transaction,
            SecurityEventType.GOOGLE_ACCOUNT_CREATED,
            now,
            context,
            user_id=user.id,
        )
        return user

    async def _insert_identity_and_login(
        self,
        transaction: GoogleTransaction,
        user: UserAccount,
        claims: GoogleClaims,
        now: datetime,
        context: RequestContext,
    ) -> SessionBundle:
        identity = self._identity(user.id, claims, now)
        await transaction.insert_external_identity(identity)
        await record_security_event(
            transaction,
            SecurityEventType.GOOGLE_IDENTITY_LINKED,
            now,
            context,
            user_id=user.id,
        )
        result = await self._login_linked(transaction, identity, claims, now, context)
        if result is None:  # pragma: no cover
            raise RuntimeError("linked user became unavailable inside the transaction")
        return result

    async def _link(
        self,
        principal: Principal,
        claims: GoogleClaims,
        now: datetime,
        context: RequestContext,
    ) -> ExternalIdentity:
        failure = None
        identity = None
        identity_inserted = False
        async with self.store.transaction() as transaction:
            user = await transaction.get_user_by_id(principal.user_id, for_update=True)
            session = await transaction.get_session_by_id(principal.session_id, for_update=True)
            if not self.policy.can_link(user, session, principal, now):
                failure = invalid_session()
            else:
                subject_owner = await transaction.get_external_identity(
                    GOOGLE_ISSUER,
                    claims.subject,
                )
                user_identity = await transaction.get_external_identity_for_user(
                    principal.user_id,
                    GOOGLE_ISSUER,
                )
                if subject_owner is not None and subject_owner.user_id == principal.user_id:
                    identity = subject_owner
                elif subject_owner is not None or user_identity is not None:
                    failure = google_identity_conflict()
                else:
                    identity = self._identity(principal.user_id, claims, now)
                    await transaction.insert_external_identity(identity)
                    identity_inserted = True
                    await record_security_event(
                        transaction,
                        SecurityEventType.GOOGLE_IDENTITY_LINKED,
                        now,
                        context,
                        user_id=principal.user_id,
                    )
            security_changed = identity_inserted or bool(
                identity is not None and user is not None and user.google_auto_link_allowed
            )
            if security_changed and user is not None:
                await transaction.update_user(
                    replace(
                        user,
                        google_auto_link_allowed=False,
                    ).advance_security_version(now)
                )
            if failure is not None:
                await record_security_event(
                    transaction,
                    SecurityEventType.GOOGLE_LINK_FAILED,
                    now,
                    context,
                    user_id=principal.user_id,
                )
        if failure is not None:
            raise failure
        if identity is None:  # pragma: no cover
            raise RuntimeError("Google linking completed without an identity")
        return identity

    async def _linked_after_conflict(
        self,
        principal: Principal,
        claims: GoogleClaims,
        now: datetime,
        context: RequestContext,
    ) -> ExternalIdentity:
        failure = invalid_session()
        async with self.store.transaction() as transaction:
            user = await transaction.get_user_by_id(principal.user_id, for_update=True)
            session = await transaction.get_session_by_id(principal.session_id, for_update=True)
            if self.policy.can_link(user, session, principal, now):
                failure = google_identity_conflict()
                identity = await transaction.get_external_identity(
                    GOOGLE_ISSUER,
                    claims.subject,
                )
                if identity is not None and identity.user_id == principal.user_id:
                    return identity
            await record_security_event(
                transaction,
                SecurityEventType.GOOGLE_LINK_FAILED,
                now,
                context,
                user_id=principal.user_id,
            )
        raise failure

    @staticmethod
    def _identity(user_id: UUID, claims: GoogleClaims, now: datetime) -> ExternalIdentity:
        return ExternalIdentity(
            id=uuid4(),
            user_id=user_id,
            issuer=GOOGLE_ISSUER,
            subject=claims.subject,
            email=claims.email,
            created_at=now,
            last_login_at=now,
        )

    async def _verification_failure(
        self,
        linking: bool,
        context: RequestContext,
        *,
        provider_unavailable: bool = False,
    ) -> None:
        now = clock_now(self.clock)
        event_type = (
            SecurityEventType.GOOGLE_LINK_FAILED
            if linking
            else SecurityEventType.GOOGLE_LOGIN_FAILED
        )
        metadata: SecurityMetadata | None = None
        if provider_unavailable:
            metadata = {"provider_unavailable": True}
        async with self.store.transaction() as transaction:
            await record_security_event(transaction, event_type, now, context, metadata=metadata)

    def _require_recent_authentication(self, principal: Principal) -> None:
        if principal.must_change_password:
            raise forbidden("Password change is required before linking Google.")
        maximum = timedelta(seconds=self.settings.google_link_max_age_seconds)
        if clock_now(self.clock) - principal.authenticated_at > maximum:
            raise forbidden("Recent authentication is required to link Google.")
