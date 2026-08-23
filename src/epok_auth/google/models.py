from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID

GOOGLE_ISSUER = "https://accounts.google.com"


class GoogleChallengePurpose(StrEnum):
    LOGIN = "login"
    LINK = "link"


@dataclass(frozen=True, slots=True)
class GoogleChallenge:
    id: UUID
    purpose: GoogleChallengePurpose
    nonce: str = field(repr=False)
    origin: str
    client_id: str
    created_at: datetime
    expires_at: datetime
    user_id: UUID | None = None
    consumed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class ExternalIdentity:
    id: UUID
    user_id: UUID
    issuer: str
    subject: str = field(repr=False)
    email: str | None
    created_at: datetime
    last_login_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class GoogleClaims:
    issuer: str
    subject: str = field(repr=False)
    email: str | None
    email_verified: bool
    hosted_domain: str | None = None
    display_name: str | None = None


@dataclass(frozen=True, slots=True)
class GoogleOptions:
    challenge_id: UUID
    client_id: str
    nonce: str = field(repr=False)
