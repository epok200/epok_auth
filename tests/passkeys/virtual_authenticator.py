import base64
import hashlib
import json
from uuid import UUID

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


class VirtualAuthenticator:
    def __init__(self) -> None:
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = hashlib.sha256(b"epok-auth-virtual-passkey").digest()

    def registration_response(
        self,
        *,
        challenge: bytes,
        rp_id: str,
        origin: str,
        cross_origin: object = False,
        top_origin: str | None = None,
        user_present: bool = True,
        user_verified: bool = True,
        backup_eligible: bool = True,
        backed_up: bool = True,
    ) -> dict[str, object]:
        client_data = _client_data(
            "webauthn.create",
            challenge,
            origin,
            cross_origin,
            top_origin,
        )
        authenticator_data = self._registration_authenticator_data(
            rp_id,
            user_present=user_present,
            user_verified=user_verified,
            backup_eligible=backup_eligible,
            backed_up=backed_up,
        )
        attestation_object = cbor2.dumps(
            {
                "fmt": "none",
                "attStmt": {},
                "authData": authenticator_data,
            }
        )
        credential_id = _base64url(self.credential_id)
        return {
            "id": credential_id,
            "rawId": credential_id,
            "response": {
                "clientDataJSON": _base64url(client_data),
                "attestationObject": _base64url(attestation_object),
                "transports": ["internal", "hybrid"],
            },
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
        }

    def authentication_response(
        self,
        *,
        challenge: bytes,
        rp_id: str,
        origin: str,
        user_id: UUID,
        sign_count: int,
        cross_origin: object = False,
        top_origin: str | None = None,
        user_handle: bytes | None = None,
        user_present: bool = True,
        user_verified: bool = True,
        backup_eligible: bool = True,
        backed_up: bool = True,
        valid_signature: bool = True,
    ) -> dict[str, object]:
        client_data = _client_data(
            "webauthn.get",
            challenge,
            origin,
            cross_origin,
            top_origin,
        )
        flags = _authenticator_flags(
            user_present=user_present,
            user_verified=user_verified,
            backup_eligible=backup_eligible,
            backed_up=backed_up,
        )
        authenticator_data = _rp_id_hash(rp_id) + bytes([flags]) + sign_count.to_bytes(4, "big")
        signed = authenticator_data + hashlib.sha256(client_data).digest()
        signature = self.private_key.sign(signed, ec.ECDSA(hashes.SHA256()))
        if not valid_signature:
            signature = signature[:-1] + bytes([signature[-1] ^ 1])
        credential_id = _base64url(self.credential_id)
        handle = user_id.bytes if user_handle is None else user_handle
        return {
            "id": credential_id,
            "rawId": credential_id,
            "response": {
                "clientDataJSON": _base64url(client_data),
                "authenticatorData": _base64url(authenticator_data),
                "signature": _base64url(signature),
                "userHandle": _base64url(handle),
            },
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
        }

    def _registration_authenticator_data(
        self,
        rp_id: str,
        *,
        user_present: bool,
        user_verified: bool,
        backup_eligible: bool,
        backed_up: bool,
    ) -> bytes:
        public_numbers = self.private_key.public_key().public_numbers()
        cose_key = cbor2.dumps(
            {
                1: 2,
                3: -7,
                -1: 1,
                -2: public_numbers.x.to_bytes(32, "big"),
                -3: public_numbers.y.to_bytes(32, "big"),
            }
        )
        attested_data = (
            bytes(16) + len(self.credential_id).to_bytes(2, "big") + self.credential_id + cose_key
        )
        flags = 0x40 | _authenticator_flags(
            user_present=user_present,
            user_verified=user_verified,
            backup_eligible=backup_eligible,
            backed_up=backed_up,
        )
        return _rp_id_hash(rp_id) + bytes([flags]) + bytes(4) + attested_data


def decode_base64url(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _client_data(
    ceremony_type: str,
    challenge: bytes,
    origin: str,
    cross_origin: object,
    top_origin: str | None,
) -> bytes:
    payload: dict[str, object] = {
        "type": ceremony_type,
        "challenge": _base64url(challenge),
        "origin": origin,
        "crossOrigin": cross_origin,
    }
    if top_origin is not None:
        payload["topOrigin"] = top_origin
    return json.dumps(payload, separators=(",", ":")).encode()


def _authenticator_flags(
    *,
    user_present: bool,
    user_verified: bool,
    backup_eligible: bool,
    backed_up: bool,
) -> int:
    flags = 0
    if user_present:
        flags |= 0x01
    if user_verified:
        flags |= 0x04
    if backup_eligible:
        flags |= 0x08
    if backed_up:
        flags |= 0x10
    return flags


def _rp_id_hash(rp_id: str) -> bytes:
    return hashlib.sha256(rp_id.encode()).digest()
