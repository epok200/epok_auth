from datetime import datetime, timedelta
from uuid import UUID, uuid4

from epok_auth._events import EMPTY_CONTEXT, record_security_event
from epok_auth.config import AuthSettings
from epok_auth.models import (
    Principal,
    RefreshSession,
    RequestContext,
    SecurityEventType,
    SessionBundle,
    UserAccount,
)
from epok_auth.store import AuthTransaction
from epok_auth.tokens import (
    AccessTokenSigner,
    create_csrf_token,
    create_refresh_token,
    token_hash,
)


class SessionIssuer:
    """Creates every authenticated session through one security policy."""

    def __init__(self, *, settings: AuthSettings, signer: AccessTokenSigner) -> None:
        self.settings = settings
        self.signer = signer

    async def issue(
        self,
        transaction: AuthTransaction,
        user: UserAccount,
        *,
        now: datetime,
        family_id: UUID | None = None,
        absolute_expires_at: datetime | None = None,
        authenticated_at: datetime | None = None,
        context: RequestContext = EMPTY_CONTEXT,
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
        principal = principal_from_session(user, session)
        access_token, _ = self.signer.issue(principal, now=now)
        await record_security_event(
            transaction,
            SecurityEventType.SESSION_CREATED,
            now,
            context,
            user_id=user.id,
            session_id=session_id,
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


def principal_from_session(user: UserAccount, session: RefreshSession) -> Principal:
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
