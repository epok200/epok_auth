from collections.abc import Sequence

from epok_auth.models import UserAccount
from epok_auth.passkeys.adapter import (
    CredentialPayload,
    PasskeyVerificationError,
    VerifiedPasskeyAuthentication,
    VerifiedPasskeyRegistration,
)
from epok_auth.passkeys.models import PasskeyCredential


class FakePasskeyAdapter:
    def registration_options(
        self,
        user: UserAccount,
        challenge: bytes,
        existing: Sequence[PasskeyCredential],
    ) -> dict[str, object]:
        return {
            "challenge": challenge.hex(),
            "user": {"id": user.id.hex, "name": user.email},
            "excludeCredentials": [credential.id.hex for credential in existing],
        }

    def authentication_options(self, challenge: bytes) -> dict[str, object]:
        return {"challenge": challenge.hex(), "userVerification": "required"}

    def credential_id(self, credential: CredentialPayload) -> bytes:
        value = credential.get("credential_id")
        if not isinstance(value, bytes):
            raise PasskeyVerificationError("missing credential identifier")
        return value

    def verify_registration(
        self,
        credential: CredentialPayload,
        challenge: bytes,
        origin: str,
    ) -> VerifiedPasskeyRegistration:
        del challenge, origin
        if credential.get("valid") is not True:
            raise PasskeyVerificationError("invalid registration")
        credential_id = self.credential_id(credential)
        return VerifiedPasskeyRegistration(
            credential_id=credential_id,
            public_key=b"verified-public-key",
            sign_count=0,
            aaguid="00000000-0000-0000-0000-000000000000",
            transports=("internal",),
            device_type="multi_device",
            backed_up=True,
        )

    def verify_authentication(
        self,
        credential: CredentialPayload,
        challenge: bytes,
        origin: str,
        stored: PasskeyCredential,
    ) -> VerifiedPasskeyAuthentication:
        del challenge, origin
        if credential.get("valid") is not True:
            raise PasskeyVerificationError("invalid authentication")
        device_type = credential.get("device_type", stored.device_type)
        if not isinstance(device_type, str):
            raise PasskeyVerificationError("invalid device type")
        sign_count = credential.get("sign_count", stored.sign_count + 1)
        if not isinstance(sign_count, int):
            raise PasskeyVerificationError("invalid sign count")
        return VerifiedPasskeyAuthentication(
            credential_id=self.credential_id(credential),
            sign_count=sign_count,
            device_type=device_type,
            backed_up=True,
        )
