import json
from collections.abc import Sequence
from json import JSONDecodeError
from typing import cast

from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import options_to_json, parse_authentication_credential_json
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from epok_auth.models import UserAccount
from epok_auth.passkeys.adapter import (
    CredentialPayload,
    PasskeyVerificationError,
    VerifiedPasskeyAuthentication,
    VerifiedPasskeyRegistration,
)
from epok_auth.passkeys.models import PasskeyCredential, PublicKeyOptions


class WebAuthnAdapter:
    """Adapter for Duo Labs py_webauthn with strict passkey defaults."""

    def __init__(self, *, rp_id: str, rp_name: str, timeout_ms: int) -> None:
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.timeout_ms = timeout_ms

    def registration_options(
        self,
        user: UserAccount,
        challenge: bytes,
        existing: Sequence[PasskeyCredential],
    ) -> PublicKeyOptions:
        excluded = [
            PublicKeyCredentialDescriptor(
                id=credential.credential_id,
                transports=[AuthenticatorTransport(value) for value in credential.transports],
            )
            for credential in existing
        ]
        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=user.id.bytes,
            user_name=user.email,
            user_display_name=user.display_name,
            challenge=challenge,
            timeout=self.timeout_ms,
            exclude_credentials=excluded,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                require_resident_key=True,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
        )
        return _options_dict(options_to_json(options))

    def authentication_options(self, challenge: bytes) -> PublicKeyOptions:
        options = generate_authentication_options(
            rp_id=self.rp_id,
            challenge=challenge,
            timeout=self.timeout_ms,
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return _options_dict(options_to_json(options))

    def credential_id(self, credential: CredentialPayload) -> bytes:
        try:
            parsed = parse_authentication_credential_json(credential)
        except WebAuthnException as error:
            raise PasskeyVerificationError("invalid authentication credential") from error
        return bytes(parsed.raw_id)

    def verify_registration(
        self,
        credential: CredentialPayload,
        challenge: bytes,
        origin: str,
    ) -> VerifiedPasskeyRegistration:
        _reject_cross_origin(credential)
        try:
            verified = verify_registration_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=self.rp_id,
                expected_origin=origin,
                require_user_verification=True,
            )
        except WebAuthnException as error:
            raise PasskeyVerificationError("registration verification failed") from error
        if len(verified.credential_id) > 1023:
            raise PasskeyVerificationError("credential identifier is too large")
        transports = _registration_transports(credential)
        return VerifiedPasskeyRegistration(
            credential_id=verified.credential_id,
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
            aaguid=verified.aaguid,
            transports=transports,
            device_type=verified.credential_device_type.value,
            backed_up=verified.credential_backed_up,
        )

    def verify_authentication(
        self,
        credential: CredentialPayload,
        challenge: bytes,
        origin: str,
        stored: PasskeyCredential,
    ) -> VerifiedPasskeyAuthentication:
        _reject_cross_origin(credential)
        try:
            parsed = parse_authentication_credential_json(credential)
            if parsed.response.user_handle != stored.user_id.bytes:
                raise PasskeyVerificationError("user handle did not match credential owner")
            verified = verify_authentication_response(
                credential=parsed,
                expected_challenge=challenge,
                expected_rp_id=self.rp_id,
                expected_origin=origin,
                credential_public_key=stored.public_key,
                credential_current_sign_count=stored.sign_count,
                require_user_verification=True,
            )
        except WebAuthnException as error:
            raise PasskeyVerificationError("authentication verification failed") from error
        if verified.credential_device_type.value != stored.device_type:
            raise PasskeyVerificationError("credential backup eligibility changed")
        return VerifiedPasskeyAuthentication(
            credential_id=verified.credential_id,
            sign_count=verified.new_sign_count,
            device_type=verified.credential_device_type.value,
            backed_up=verified.credential_backed_up,
        )


def _options_dict(value: str) -> PublicKeyOptions:
    parsed: object = json.loads(value)
    if not isinstance(parsed, dict):
        raise RuntimeError("WebAuthn options were not a JSON object")
    values = cast(dict[object, object], parsed)
    return {str(key): item for key, item in values.items()}


def _reject_cross_origin(credential: CredentialPayload) -> None:
    try:
        response = credential["response"]
        if not isinstance(response, dict):
            raise TypeError
        response_values = cast(dict[object, object], response)
        encoded = response_values["clientDataJSON"]
        if not isinstance(encoded, str):
            raise TypeError
        client_data: object = json.loads(base64url_to_bytes(encoded))
        if not isinstance(client_data, dict):
            raise TypeError
    except (JSONDecodeError, KeyError, TypeError, UnicodeDecodeError, ValueError) as error:
        raise PasskeyVerificationError("client data could not be parsed") from error
    client_values = cast(dict[object, object], client_data)
    if "crossOrigin" in client_values:
        cross_origin = client_values["crossOrigin"]
        if not isinstance(cross_origin, bool) or cross_origin:
            raise PasskeyVerificationError("cross-origin WebAuthn ceremonies are not supported")
    if "topOrigin" in client_values:
        raise PasskeyVerificationError("cross-origin WebAuthn ceremonies are not supported")


def _registration_transports(credential: CredentialPayload) -> tuple[str, ...]:
    response = credential.get("response")
    if not isinstance(response, dict):
        return ()
    response_values = cast(dict[object, object], response)
    transports = response_values.get("transports")
    if not isinstance(transports, list):
        return ()
    transport_values = cast(list[object], transports)
    known = {item.value for item in AuthenticatorTransport}
    return tuple(
        sorted({item for item in transport_values if isinstance(item, str) and item in known})
    )
