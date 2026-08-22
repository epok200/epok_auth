from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from epok_auth.models import UserAccount
from epok_auth.passkeys.models import PasskeyCredential, PublicKeyOptions

type CredentialPayload = dict[str, object]


class PasskeyVerificationError(Exception):
    """A WebAuthn response failed protocol verification."""


@dataclass(frozen=True, slots=True)
class VerifiedPasskeyRegistration:
    credential_id: bytes
    public_key: bytes
    sign_count: int
    aaguid: str
    transports: tuple[str, ...]
    device_type: str
    backed_up: bool


@dataclass(frozen=True, slots=True)
class VerifiedPasskeyAuthentication:
    credential_id: bytes
    sign_count: int
    device_type: str
    backed_up: bool


class PasskeyAdapter(Protocol):
    def registration_options(
        self,
        user: UserAccount,
        challenge: bytes,
        existing: Sequence[PasskeyCredential],
    ) -> PublicKeyOptions: ...

    def authentication_options(self, challenge: bytes) -> PublicKeyOptions: ...

    def credential_id(self, credential: CredentialPayload) -> bytes: ...

    def verify_registration(
        self,
        credential: CredentialPayload,
        challenge: bytes,
        origin: str,
    ) -> VerifiedPasskeyRegistration: ...

    def verify_authentication(
        self,
        credential: CredentialPayload,
        challenge: bytes,
        origin: str,
        stored: PasskeyCredential,
    ) -> VerifiedPasskeyAuthentication: ...
