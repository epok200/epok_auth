from collections.abc import Sequence
from contextlib import AbstractAsyncContextManager
from datetime import datetime
from typing import Protocol
from uuid import UUID

from epok_auth.passkeys.models import (
    PasskeyCeremonyPurpose,
    PasskeyChallenge,
    PasskeyCredential,
)
from epok_auth.store import AuthTransaction


class PasskeyTransaction(AuthTransaction, Protocol):
    async def delete_expired_passkey_challenges(self, now: datetime) -> int: ...
    async def insert_passkey_challenge(self, challenge: PasskeyChallenge) -> None: ...
    async def consume_passkey_challenge(
        self,
        challenge_id: UUID,
        purpose: PasskeyCeremonyPurpose,
        now: datetime,
        user_id: UUID | None,
    ) -> PasskeyChallenge | None: ...
    async def count_passkeys(self, user_id: UUID) -> int: ...
    async def list_passkeys(self, user_id: UUID) -> Sequence[PasskeyCredential]: ...
    async def get_passkey_by_id(
        self,
        passkey_id: UUID,
        user_id: UUID,
        *,
        for_update: bool = False,
    ) -> PasskeyCredential | None: ...
    async def get_passkey_by_credential_id(
        self,
        credential_id: bytes,
        *,
        for_update: bool = False,
    ) -> PasskeyCredential | None: ...
    async def insert_passkey(self, credential: PasskeyCredential) -> None: ...
    async def update_passkey(self, credential: PasskeyCredential) -> None: ...


class PasskeyStore(Protocol):
    def transaction(self) -> AbstractAsyncContextManager[PasskeyTransaction]: ...
