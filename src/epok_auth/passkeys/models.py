from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID

type PublicKeyOptions = dict[str, object]


class PasskeyCeremonyPurpose(StrEnum):
    REGISTRATION = "registration"
    AUTHENTICATION = "authentication"


@dataclass(frozen=True, slots=True)
class PasskeyChallenge:
    id: UUID
    purpose: PasskeyCeremonyPurpose
    challenge: bytes = field(repr=False)
    origin: str
    created_at: datetime
    expires_at: datetime
    user_id: UUID | None = None
    consumed_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class PasskeyCredential:
    id: UUID
    user_id: UUID
    credential_id: bytes = field(repr=False)
    public_key: bytes = field(repr=False)
    name: str
    sign_count: int
    aaguid: str
    transports: tuple[str, ...]
    device_type: str
    backed_up: bool
    created_at: datetime
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class PasskeyOptions:
    ceremony_id: UUID
    public_key: PublicKeyOptions
