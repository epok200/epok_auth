from contextlib import AbstractAsyncContextManager
from datetime import datetime
from typing import Protocol
from uuid import UUID

from epok_auth.google.models import (
    ExternalIdentity,
    GoogleChallenge,
    GoogleChallengePurpose,
)
from epok_auth.store import AuthTransaction


class GoogleTransaction(AuthTransaction, Protocol):
    async def delete_expired_google_challenges(self, now: datetime) -> int: ...
    async def insert_google_challenge(self, challenge: GoogleChallenge) -> None: ...
    async def consume_google_challenge(
        self,
        challenge_id: UUID,
        purpose: GoogleChallengePurpose,
        now: datetime,
        user_id: UUID | None,
    ) -> GoogleChallenge | None: ...
    async def get_external_identity(
        self,
        issuer: str,
        subject: str,
        *,
        for_update: bool = False,
    ) -> ExternalIdentity | None: ...
    async def get_external_identity_for_user(
        self,
        user_id: UUID,
        issuer: str,
        *,
        for_update: bool = False,
    ) -> ExternalIdentity | None: ...
    async def insert_external_identity(self, identity: ExternalIdentity) -> None: ...
    async def update_external_identity(self, identity: ExternalIdentity) -> None: ...
    async def delete_external_identity(self, identity_id: UUID) -> None: ...


class GoogleStore(Protocol):
    def transaction(self) -> AbstractAsyncContextManager[GoogleTransaction]: ...
