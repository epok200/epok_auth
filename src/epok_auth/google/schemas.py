from datetime import datetime
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, StringConstraints

from epok_auth.google.models import ExternalIdentity, GoogleOptions

GoogleCredential = Annotated[str, StringConstraints(min_length=1, max_length=16_384)]


class GoogleSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GoogleOptionsResponse(BaseModel):
    challenge_id: UUID
    client_id: str
    nonce: str

    @classmethod
    def from_options(cls, options: GoogleOptions) -> Self:
        return cls(
            challenge_id=options.challenge_id,
            client_id=options.client_id,
            nonce=options.nonce,
        )


class FinishGoogleAuthenticationRequest(GoogleSchema):
    challenge_id: UUID
    credential: GoogleCredential


class GoogleIdentityResponse(BaseModel):
    provider: Literal["google"] = "google"
    email: str | None
    linked_at: datetime

    @classmethod
    def from_identity(cls, identity: ExternalIdentity) -> Self:
        return cls(email=identity.email, linked_at=identity.created_at)
