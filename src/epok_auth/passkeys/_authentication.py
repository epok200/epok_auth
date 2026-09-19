import asyncio
from dataclasses import dataclass, replace
from datetime import datetime
from uuid import UUID

from epok_auth.models import UserAccount
from epok_auth.passkeys.adapter import (
    CredentialPayload,
    PasskeyAdapter,
    PasskeyVerificationError,
)
from epok_auth.passkeys.models import PasskeyCredential
from epok_auth.passkeys.store import PasskeyTransaction


@dataclass(frozen=True, slots=True)
class PasskeyVerificationResult:
    user: UserAccount | None
    credential: PasskeyCredential | None


async def verify_and_update_passkey(
    transaction: PasskeyTransaction,
    adapter: PasskeyAdapter,
    *,
    credential: CredentialPayload,
    challenge: bytes,
    origin: str,
    now: datetime,
    expected_user_id: UUID | None = None,
) -> PasskeyVerificationResult:
    try:
        credential_id = adapter.credential_id(credential)
    except PasskeyVerificationError:
        return PasskeyVerificationResult(None, None)
    stored = await transaction.get_passkey_by_credential_id(
        credential_id,
        for_update=True,
    )
    if (
        stored is None
        or stored.revoked_at is not None
        or (expected_user_id is not None and stored.user_id != expected_user_id)
    ):
        return PasskeyVerificationResult(None, None)
    user = await transaction.get_user_by_id(stored.user_id, for_update=True)
    if user is None or not user.can_authenticate(now):
        return PasskeyVerificationResult(None, None)
    try:
        verified = await asyncio.to_thread(
            adapter.verify_authentication,
            credential,
            challenge,
            origin,
            stored,
        )
    except PasskeyVerificationError:
        return PasskeyVerificationResult(user, None)
    if verified.credential_id != stored.credential_id or verified.device_type != stored.device_type:
        return PasskeyVerificationResult(user, None)
    updated = replace(
        stored,
        sign_count=verified.sign_count,
        backed_up=verified.backed_up,
        last_used_at=now,
    )
    await transaction.update_passkey(updated)
    return PasskeyVerificationResult(user, updated)
