from datetime import UTC, datetime
from uuid import UUID

from epok_auth.config import AuthSettings
from epok_auth.models import (
    RequestContext,
    SecurityEvent,
    SecurityEventType,
    SecurityMetadata,
)
from epok_auth.passwords import PasswordManager
from epok_auth.sessions import SessionIssuer
from epok_auth.store import AuthStore, AuthTransaction
from epok_auth.tokens import AccessTokenSigner, Clock, HMACJWTSigner, utc_now

EMPTY_CONTEXT = RequestContext()


class AuthServiceBase:
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
        self.session_issuer = SessionIssuer(settings=settings, signer=self.signer)

    async def _event(
        self,
        transaction: AuthTransaction,
        event_type: SecurityEventType,
        *,
        now: datetime,
        user_id: UUID | None = None,
        session_id: UUID | None = None,
        context: RequestContext = EMPTY_CONTEXT,
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

    def _now(self) -> datetime:
        value = self.clock()
        if value.tzinfo is None:
            raise ValueError("clock must return a timezone-aware datetime")
        return value.astimezone(UTC)
