from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class EmailLinkPurpose(StrEnum):
    LOGIN = "login"
    PASSWORD_RESET = "password_reset"
    INVITATION = "invitation"


class EmailLinkState(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    FAILED = "failed"
    CONSUMED = "consumed"
    REVOKED = "revoked"


class AuthEmailKind(StrEnum):
    LOGIN = "login"
    PASSWORD_RESET = "password_reset"
    INVITATION = "invitation"
    PASSWORD_CHANGED = "password_changed"


@dataclass(frozen=True, slots=True)
class EmailLink:
    id: UUID
    user_id: UUID
    purpose: EmailLinkPurpose
    generation: int
    token_hash: str = field(repr=False)
    recipient_hash: str = field(repr=False)
    security_version: int
    created_at: datetime
    expires_at: datetime
    browser_hash: str | None = field(default=None, repr=False)
    state: EmailLinkState = EmailLinkState.PENDING
    delivered_at: datetime | None = None
    consumed_at: datetime | None = None
    revoked_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class AuthEmail:
    recipient: str = field(repr=False)
    kind: AuthEmailKind
    action_url: str | None = field(default=None, repr=False)
    expires_at: datetime | None = None
    user_id: UUID | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class PendingEmailLink:
    link_id: UUID
    email: AuthEmail = field(repr=False)


@dataclass(frozen=True, slots=True)
class EmailLinkIssue:
    pending: PendingEmailLink | None = field(default=None, repr=False)
    browser_nonce: str | None = field(default=None, repr=False)
