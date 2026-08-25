import secrets
from datetime import timedelta
from uuid import UUID, uuid4

from epok_auth._validation import canonical_origin
from epok_auth.config import AuthSettings
from epok_auth.errores import AuthError, AuthErrorCode, invalid_session
from epok_auth.google.models import (
    GoogleChallenge,
    GoogleChallengePurpose,
    GoogleOptions,
)
from epok_auth.google.store import GoogleStore
from epok_auth.tokens import Clock, clock_now


class GoogleChallengeService:
    """Creates and atomically consumes origin-bound Google nonces."""

    def __init__(self, *, store: GoogleStore, settings: AuthSettings, clock: Clock) -> None:
        self.store = store
        self.settings = settings
        self.clock = clock

    async def begin(
        self,
        purpose: GoogleChallengePurpose,
        origin: str | None,
        *,
        user_id: UUID | None = None,
    ) -> GoogleOptions:
        now = clock_now(self.clock)
        challenge = GoogleChallenge(
            id=uuid4(),
            purpose=purpose,
            nonce=secrets.token_urlsafe(32),
            origin=self._validate_origin(origin),
            client_id=self._client_id(),
            user_id=user_id,
            created_at=now,
            expires_at=now + timedelta(seconds=self.settings.google_challenge_ttl_seconds),
        )
        async with self.store.transaction() as transaction:
            if user_id is not None:
                user = await transaction.get_user_by_id(user_id)
                if user is None or not user.can_authenticate(now):
                    raise invalid_session()
            await transaction.delete_expired_google_challenges(now)
            await transaction.insert_google_challenge(challenge)
        return GoogleOptions(
            challenge_id=challenge.id,
            client_id=challenge.client_id,
            nonce=challenge.nonce,
        )

    async def consume(
        self,
        challenge_id: UUID,
        purpose: GoogleChallengePurpose,
        origin: str | None,
        *,
        user_id: UUID | None = None,
    ) -> GoogleChallenge:
        now = clock_now(self.clock)
        expected_origin = self._validate_origin(origin)
        async with self.store.transaction() as transaction:
            challenge = await transaction.consume_google_challenge(
                challenge_id,
                purpose,
                now,
                user_id,
            )
        if (
            challenge is None
            or challenge.origin != expected_origin
            or challenge.client_id != self._client_id()
        ):
            raise AuthError(
                AuthErrorCode.GOOGLE_CHALLENGE_INVALID,
                "The Google authentication challenge is invalid or expired.",
            )
        return challenge

    def _validate_origin(self, origin: str | None) -> str:
        if origin is None:
            raise AuthError(AuthErrorCode.INVALID_ORIGIN, "Origin is required.")
        normalized = canonical_origin(origin)
        if normalized not in self.settings.trusted_origins:
            raise AuthError(AuthErrorCode.INVALID_ORIGIN, "Origin is not trusted.")
        return normalized

    def _client_id(self) -> str:
        client_id = self.settings.google_client_id
        if client_id is None:  # pragma: no cover
            raise RuntimeError("Google Sign-In was not configured")
        return client_id
