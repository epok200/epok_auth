from datetime import datetime
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from epok_auth.passkeys.adapter import CredentialPayload
from epok_auth.passkeys.models import PasskeyCredential, PasskeyOptions, PublicKeyOptions

Base64Text = Annotated[str, StringConstraints(min_length=1, max_length=131_072)]
CredentialIdText = Annotated[str, StringConstraints(min_length=1, max_length=2048)]
PasskeyName = Annotated[str, StringConstraints(min_length=1, max_length=100)]
AuthenticatorAttachment = Literal["platform", "cross-platform"]
AuthenticatorTransport = Literal["usb", "nfc", "ble", "smart-card", "internal", "cable", "hybrid"]


def _empty_transports() -> list[AuthenticatorTransport]:
    return []


class PasskeySchema(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class RegistrationAuthenticatorResponse(PasskeySchema):
    client_data_json: Base64Text = Field(alias="clientDataJSON")
    attestation_object: Base64Text = Field(alias="attestationObject")
    transports: list[AuthenticatorTransport] = Field(
        default_factory=_empty_transports,
        max_length=8,
    )


class RegistrationCredentialPayload(PasskeySchema):
    id: CredentialIdText
    raw_id: CredentialIdText = Field(alias="rawId")
    response: RegistrationAuthenticatorResponse
    type: Literal["public-key"]
    authenticator_attachment: AuthenticatorAttachment | None = Field(
        default=None,
        alias="authenticatorAttachment",
    )
    client_extension_results: dict[str, object] = Field(
        default_factory=dict,
        alias="clientExtensionResults",
        max_length=32,
    )

    def as_webauthn(self) -> CredentialPayload:
        return self.model_dump(by_alias=True, exclude_none=True)


class AuthenticationAuthenticatorResponse(PasskeySchema):
    client_data_json: Base64Text = Field(alias="clientDataJSON")
    authenticator_data: Base64Text = Field(alias="authenticatorData")
    signature: Base64Text
    user_handle: Base64Text | None = Field(default=None, alias="userHandle")


class AuthenticationCredentialPayload(PasskeySchema):
    id: CredentialIdText
    raw_id: CredentialIdText = Field(alias="rawId")
    response: AuthenticationAuthenticatorResponse
    type: Literal["public-key"]
    authenticator_attachment: AuthenticatorAttachment | None = Field(
        default=None,
        alias="authenticatorAttachment",
    )
    client_extension_results: dict[str, object] = Field(
        default_factory=dict,
        alias="clientExtensionResults",
        max_length=32,
    )

    def as_webauthn(self) -> CredentialPayload:
        return self.model_dump(by_alias=True, exclude_none=True)


class PasskeyOptionsResponse(BaseModel):
    ceremony_id: UUID
    public_key: PublicKeyOptions = Field(alias="publicKey")

    @classmethod
    def from_options(cls, options: PasskeyOptions) -> Self:
        return cls(ceremony_id=options.ceremony_id, publicKey=options.public_key)


class FinishPasskeyRegistrationRequest(PasskeySchema):
    ceremony_id: UUID
    name: PasskeyName
    credential: RegistrationCredentialPayload


class FinishPasskeyAuthenticationRequest(PasskeySchema):
    ceremony_id: UUID
    credential: AuthenticationCredentialPayload


class PasskeyResponse(BaseModel):
    id: UUID
    name: str
    transports: list[str]
    device_type: str
    backed_up: bool
    created_at: datetime
    last_used_at: datetime | None

    @classmethod
    def from_credential(cls, credential: PasskeyCredential) -> Self:
        return cls(
            id=credential.id,
            name=credential.name,
            transports=list(credential.transports),
            device_type=credential.device_type,
            backed_up=credential.backed_up,
            created_at=credential.created_at,
            last_used_at=credential.last_used_at,
        )


class PasskeyListResponse(BaseModel):
    items: list[PasskeyResponse]
