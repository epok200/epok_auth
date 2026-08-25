from datetime import datetime
from uuid import UUID

from epok_auth.models import (
    RequestContext,
    SecurityEvent,
    SecurityEventType,
    SecurityMetadata,
)
from epok_auth.store import AuthTransaction

EMPTY_CONTEXT = RequestContext()


async def record_security_event(
    transaction: AuthTransaction,
    event_type: SecurityEventType,
    now: datetime,
    context: RequestContext = EMPTY_CONTEXT,
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
