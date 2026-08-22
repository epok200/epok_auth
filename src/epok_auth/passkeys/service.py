import asyncio
import secrets
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from epok_auth._validation import canonical_origin
from epok_auth.config import AuthSettings
from epok_auth.errores import AuthError, AuthErrorCode, forbidden, invalid_session
from epok_auth.models import (
    Principal,
    RequestContext,
    SecurityEvent,
    SecurityEventType,
    SecurityMetadata,
    SessionBundle,
    UserAccount,
)
from epok_auth.passkeys.adapter import CredentialPayload, PasskeyAdapter, PasskeyVerificationError
from epok_auth.passkeys.models import (
    PasskeyCeremonyPurpose,
    PasskeyChallenge,
    PasskeyCredential,
    PasskeyOptions,
)
from epok_auth.passkeys.store import PasskeyStore, PasskeyTransaction
from epok_auth.sessions import SessionIssuer
from epok_auth.store import StoreConflictError
from epok_auth.tokens import (
    AccessTokenSigner,
    Clock,
    utc_now,
)

_EMPTY_CONTEXT = RequestContext()


class PasskeyService:
    """Passkey ceremonies with single-use challenges and authoritative sessions."""

    def __init__(
        self,
        *,
        store: PasskeyStore,
        settings: AuthSettings,
        signer: AccessTokenSigner,
        adapter: PasskeyAdapter,
        clock: Clock = utc_now,
    ) -> None:
        if settings.passkey_rp_id is None:
            raise ValueError("passkey_rp_id is required when passkeys are enabled")
        self.store = store
        self.settings = settings
        self.signer = signer
        self.adapter = adapter
        self.clock = clock
        self.session_issuer = SessionIssuer(settings=settings, signer=signer)

    async def begin_registration(
        self,
        principal: Principal,
        origin: str | None,
    ) -> PasskeyOptions:
        now = self._now()
        self._require_recent_authentication(principal, now)
        expected_origin = self._validate_origin(origin)
        async with self.store.transaction() as transaction:
            user = await transaction.get_user_by_id(principal.user_id)
            if not _can_authenticate(user, now):
                raise invalid_session()
            assert user is not None
            existing = await transaction.list_passkeys(principal.user_id)
            if len(existing) >= self.settings.passkey_max_credentials_per_user:
                raise AuthError(
                    AuthErrorCode.PASSKEY_LIMIT_REACHED,
                    "The account has reached its passkey limit.",
                )
            challenge = self._challenge(
                PasskeyCeremonyPurpose.REGISTRATION,
                expected_origin,
                now,
                user_id=principal.user_id,
            )
            options = self.adapter.registration_options(user, challenge.challenge, existing)
            await transaction.delete_expired_passkey_challenges(now)
            await transaction.insert_passkey_challenge(challenge)
        return PasskeyOptions(ceremony_id=challenge.id, public_key=options)

    async def finish_registration(
        self,
        principal: Principal,
        ceremony_id: UUID,
        name: str,
        credential: CredentialPayload,
        origin: str | None,
        *,
        context: RequestContext = _EMPTY_CONTEXT,
    ) -> PasskeyCredential:
        now = self._now()
        self._require_recent_authentication(principal, now)
        expected_origin = self._validate_origin(origin)
        normalized_name = _normalize_name(name)
        challenge = await self._consume_challenge(
            ceremony_id,
            PasskeyCeremonyPurpose.REGISTRATION,
            now,
            principal.user_id,
        )
        if challenge.origin != expected_origin:
            await self._registration_failure(principal.user_id, now, context)
            raise _invalid_challenge()
        try:
            verified = await asyncio.to_thread(
                self.adapter.verify_registration,
                credential,
                challenge.challenge,
                expected_origin,
            )
        except PasskeyVerificationError as error:
            await self._registration_failure(principal.user_id, now, context)
            raise AuthError(
                AuthErrorCode.PASSKEY_REGISTRATION_INVALID,
                "The passkey registration response is not valid.",
            ) from error
        if not 1 <= len(verified.credential_id) <= 1023 or not verified.public_key:
            await self._registration_failure(principal.user_id, now, context)
            raise AuthError(
                AuthErrorCode.PASSKEY_REGISTRATION_INVALID,
                "The passkey registration response is not valid.",
            )
        passkey = PasskeyCredential(
            id=uuid4(),
            user_id=principal.user_id,
            credential_id=verified.credential_id,
            public_key=verified.public_key,
            name=normalized_name,
            sign_count=verified.sign_count,
            aaguid=verified.aaguid,
            transports=verified.transports,
            device_type=verified.device_type,
            backed_up=verified.backed_up,
            created_at=now,
        )
        try:
            async with self.store.transaction() as transaction:
                user = await transaction.get_user_by_id(principal.user_id, for_update=True)
                if not _can_authenticate(user, now):
                    raise invalid_session()
                if (
                    await transaction.count_passkeys(principal.user_id)
                    >= self.settings.passkey_max_credentials_per_user
                ):
                    raise AuthError(
                        AuthErrorCode.PASSKEY_LIMIT_REACHED,
                        "The account has reached its passkey limit.",
                    )
                await transaction.insert_passkey(passkey)
                await self._event(
                    transaction,
                    SecurityEventType.PASSKEY_REGISTERED,
                    now,
                    context,
                    user_id=principal.user_id,
                    metadata={"passkey_id": str(passkey.id)},
                )
        except StoreConflictError as error:
            raise AuthError(
                AuthErrorCode.PASSKEY_EXISTS,
                "This passkey is already registered.",
            ) from error
        return passkey

    async def begin_authentication(self, origin: str | None) -> PasskeyOptions:
        now = self._now()
        expected_origin = self._validate_origin(origin)
        challenge = self._challenge(
            PasskeyCeremonyPurpose.AUTHENTICATION,
            expected_origin,
            now,
        )
        options = self.adapter.authentication_options(challenge.challenge)
        async with self.store.transaction() as transaction:
            await transaction.delete_expired_passkey_challenges(now)
            await transaction.insert_passkey_challenge(challenge)
        return PasskeyOptions(ceremony_id=challenge.id, public_key=options)

    async def finish_authentication(
        self,
        ceremony_id: UUID,
        credential: CredentialPayload,
        origin: str | None,
        *,
        context: RequestContext = _EMPTY_CONTEXT,
    ) -> SessionBundle:
        now = self._now()
        expected_origin = self._validate_origin(origin)
        challenge = await self._consume_challenge(
            ceremony_id,
            PasskeyCeremonyPurpose.AUTHENTICATION,
            now,
            None,
        )
        if challenge.origin != expected_origin:
            await self._authentication_failure(None, now, context)
            raise _invalid_challenge()
        try:
            credential_id = self.adapter.credential_id(credential)
        except PasskeyVerificationError as error:
            await self._authentication_failure(None, now, context)
            raise _invalid_authentication() from error

        failure: AuthError | None = None
        result: SessionBundle | None = None
        async with self.store.transaction() as transaction:
            stored = await transaction.get_passkey_by_credential_id(
                credential_id,
                for_update=True,
            )
            user = None
            if stored is not None and stored.revoked_at is None:
                user = await transaction.get_user_by_id(stored.user_id, for_update=True)
            if stored is None or stored.revoked_at is not None or not _can_authenticate(user, now):
                failure = _invalid_authentication()
            else:
                assert user is not None
                try:
                    verified = await asyncio.to_thread(
                        self.adapter.verify_authentication,
                        credential,
                        challenge.challenge,
                        expected_origin,
                        stored,
                    )
                except PasskeyVerificationError:
                    failure = _invalid_authentication()
                else:
                    if (
                        verified.credential_id != stored.credential_id
                        or verified.device_type != stored.device_type
                    ):
                        failure = _invalid_authentication()
                    else:
                        await transaction.update_passkey(
                            replace(
                                stored,
                                sign_count=verified.sign_count,
                                backed_up=verified.backed_up,
                                last_used_at=now,
                            )
                        )
                        result = await self.session_issuer.issue(
                            transaction,
                            user,
                            now=now,
                            context=context,
                        )
                        await self._event(
                            transaction,
                            SecurityEventType.PASSKEY_LOGIN_SUCCEEDED,
                            now,
                            context,
                            user_id=user.id,
                            session_id=result.principal.session_id,
                            metadata={"passkey_id": str(stored.id)},
                        )
            if failure is not None:
                await self._event(
                    transaction,
                    SecurityEventType.PASSKEY_LOGIN_FAILED,
                    now,
                    context,
                    user_id=user.id if user is not None else None,
                )
        if failure is not None:
            raise failure
        if result is None:  # pragma: no cover
            raise RuntimeError("passkey authentication completed without a result")
        return result

    async def list_passkeys(self, principal: Principal) -> Sequence[PasskeyCredential]:
        async with self.store.transaction() as transaction:
            return await transaction.list_passkeys(principal.user_id)

    async def revoke_passkey(
        self,
        principal: Principal,
        passkey_id: UUID,
        origin: str | None,
        *,
        context: RequestContext = _EMPTY_CONTEXT,
    ) -> None:
        now = self._now()
        self._require_recent_authentication(principal, now)
        self._validate_origin(origin)
        async with self.store.transaction() as transaction:
            credential = await transaction.get_passkey_by_id(
                passkey_id,
                principal.user_id,
                for_update=True,
            )
            if credential is None or credential.revoked_at is not None:
                raise AuthError(AuthErrorCode.PASSKEY_NOT_FOUND, "Passkey not found.")
            await transaction.update_passkey(replace(credential, revoked_at=now))
            await self._event(
                transaction,
                SecurityEventType.PASSKEY_REVOKED,
                now,
                context,
                user_id=principal.user_id,
                metadata={"passkey_id": str(passkey_id)},
            )

    async def _consume_challenge(
        self,
        ceremony_id: UUID,
        purpose: PasskeyCeremonyPurpose,
        now: datetime,
        user_id: UUID | None,
    ) -> PasskeyChallenge:
        async with self.store.transaction() as transaction:
            challenge = await transaction.consume_passkey_challenge(
                ceremony_id,
                purpose,
                now,
                user_id,
            )
        if challenge is None:
            raise _invalid_challenge()
        return challenge

    async def _registration_failure(
        self,
        user_id: UUID,
        now: datetime,
        context: RequestContext,
    ) -> None:
        async with self.store.transaction() as transaction:
            await self._event(
                transaction,
                SecurityEventType.PASSKEY_REGISTRATION_FAILED,
                now,
                context,
                user_id=user_id,
            )

    async def _authentication_failure(
        self,
        user_id: UUID | None,
        now: datetime,
        context: RequestContext,
    ) -> None:
        async with self.store.transaction() as transaction:
            await self._event(
                transaction,
                SecurityEventType.PASSKEY_LOGIN_FAILED,
                now,
                context,
                user_id=user_id,
            )

    async def _event(
        self,
        transaction: PasskeyTransaction,
        event_type: SecurityEventType,
        now: datetime,
        context: RequestContext,
        *,
        user_id: UUID | None = None,
        session_id: UUID | None = None,
        metadata: SecurityMetadata | None = None,
    ) -> None:
        await transaction.add_security_event(
            SecurityEvent.from_request(
                event_type,
                now,
                context=context,
                user_id=user_id,
                session_id=session_id,
                metadata=metadata,
            )
        )

    def _challenge(
        self,
        purpose: PasskeyCeremonyPurpose,
        origin: str,
        now: datetime,
        *,
        user_id: UUID | None = None,
    ) -> PasskeyChallenge:
        return PasskeyChallenge(
            id=uuid4(),
            purpose=purpose,
            challenge=secrets.token_bytes(32),
            origin=origin,
            created_at=now,
            expires_at=now + timedelta(seconds=self.settings.passkey_challenge_ttl_seconds),
            user_id=user_id,
        )

    def _validate_origin(self, origin: str | None) -> str:
        if origin is None:
            raise AuthError(AuthErrorCode.INVALID_ORIGIN, "Origin is required.")
        normalized = canonical_origin(origin)
        if normalized not in self.settings.trusted_origins:
            raise AuthError(AuthErrorCode.INVALID_ORIGIN, "Origin is not trusted.")
        host = (urlsplit(normalized).hostname or "").casefold()
        rp_id = self.settings.passkey_rp_id
        if rp_id is None or (host != rp_id and not host.endswith(f".{rp_id}")):
            raise AuthError(
                AuthErrorCode.INVALID_ORIGIN,
                "Origin is not compatible with passkey_rp_id.",
            )
        return normalized

    def _require_recent_authentication(self, principal: Principal, now: datetime) -> None:
        if principal.must_change_password:
            raise AuthError(
                AuthErrorCode.PASSWORD_CHANGE_REQUIRED,
                "Password change is required before managing passkeys.",
            )
        maximum = timedelta(seconds=self.settings.passkey_registration_max_age_seconds)
        if now - principal.authenticated_at > maximum:
            raise forbidden("Recent authentication is required to manage passkeys.")

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None:
            raise ValueError("clock must return a timezone-aware datetime")
        return value.astimezone(UTC)


def _can_authenticate(user: UserAccount | None, now: datetime) -> bool:
    return user is not None and user.can_authenticate(now)


def _normalize_name(value: str) -> str:
    normalized = " ".join(value.split())
    if not 1 <= len(normalized) <= 100 or any(ord(character) < 32 for character in normalized):
        raise AuthError(AuthErrorCode.PASSKEY_NAME_INVALID, "Passkey name is not valid.")
    return normalized


def _invalid_challenge() -> AuthError:
    return AuthError(
        AuthErrorCode.PASSKEY_CHALLENGE_INVALID,
        "The passkey ceremony is invalid or expired.",
    )


def _invalid_authentication() -> AuthError:
    return AuthError(
        AuthErrorCode.PASSKEY_AUTHENTICATION_INVALID,
        "The passkey authentication response is not valid.",
    )
