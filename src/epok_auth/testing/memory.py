import asyncio
import copy
from collections.abc import AsyncGenerator, Sequence
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID

from epok_auth.models import RefreshSession, SecurityEvent, UserAccount, UserStatus
from epok_auth.passkeys.models import (
    PasskeyCeremonyPurpose,
    PasskeyChallenge,
    PasskeyCredential,
)
from epok_auth.passkeys.store import PasskeyTransaction
from epok_auth.store import StoreConflictError


class MemoryAuthStore:
    """Transactional adapter for tests and examples; never use it in production."""

    def __init__(self) -> None:
        self.users: dict[UUID, UserAccount] = {}
        self.sessions: dict[UUID, RefreshSession] = {}
        self.passkeys: dict[UUID, PasskeyCredential] = {}
        self.passkey_challenges: dict[UUID, PasskeyChallenge] = {}
        self.events: list[SecurityEvent] = []
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[PasskeyTransaction, None]:
        async with self._lock:
            snapshot = copy.deepcopy(
                (
                    self.users,
                    self.sessions,
                    self.passkeys,
                    self.passkey_challenges,
                    self.events,
                )
            )
            try:
                yield _MemoryTransaction(self)
            except BaseException:
                (
                    self.users,
                    self.sessions,
                    self.passkeys,
                    self.passkey_challenges,
                    self.events,
                ) = snapshot
                raise


class _MemoryTransaction:
    def __init__(self, store: MemoryAuthStore) -> None:
        self.store = store

    async def acquire_admin_invariant_lock(self) -> None:
        return None

    async def count_users_with_role(self, role: str, *, active_only: bool) -> int:
        return sum(
            1
            for user in self.store.users.values()
            if role in user.roles and (not active_only or user.status is UserStatus.ACTIVE)
        )

    async def get_user_by_email(
        self,
        email: str,
        *,
        for_update: bool = False,
    ) -> UserAccount | None:
        del for_update
        return next((item for item in self.store.users.values() if item.email == email), None)

    async def get_user_by_id(
        self,
        user_id: UUID,
        *,
        for_update: bool = False,
    ) -> UserAccount | None:
        del for_update
        return self.store.users.get(user_id)

    async def list_users(self, *, limit: int, offset: int) -> Sequence[UserAccount]:
        users = sorted(
            self.store.users.values(),
            key=lambda item: (item.created_at or datetime.min.replace(tzinfo=UTC), str(item.id)),
        )
        return users[offset : offset + limit]

    async def insert_user(self, user: UserAccount) -> None:
        if user.id in self.store.users or any(
            existing.email == user.email for existing in self.store.users.values()
        ):
            raise StoreConflictError("user already exists")
        self.store.users[user.id] = user

    async def update_user(self, user: UserAccount) -> None:
        if user.id not in self.store.users:
            raise KeyError(user.id)
        if any(
            existing.id != user.id and existing.email == user.email
            for existing in self.store.users.values()
        ):
            raise StoreConflictError("user already exists")
        self.store.users[user.id] = user

    async def get_session_by_token_hash(
        self,
        token_hash: str,
        *,
        for_update: bool = False,
    ) -> RefreshSession | None:
        del for_update
        return next(
            (
                session
                for session in self.store.sessions.values()
                if session.token_hash == token_hash
            ),
            None,
        )

    async def get_session_by_id(
        self,
        session_id: UUID,
        *,
        for_update: bool = False,
    ) -> RefreshSession | None:
        del for_update
        return self.store.sessions.get(session_id)

    async def insert_session(self, session: RefreshSession) -> None:
        if session.id in self.store.sessions or any(
            existing.token_hash == session.token_hash for existing in self.store.sessions.values()
        ):
            raise StoreConflictError("session already exists")
        self.store.sessions[session.id] = session

    async def update_session(self, session: RefreshSession) -> None:
        if session.id not in self.store.sessions:
            raise KeyError(session.id)
        self.store.sessions[session.id] = session

    async def revoke_family(self, family_id: UUID, *, revoked_at: datetime) -> int:
        count = 0
        for session_id, session in tuple(self.store.sessions.items()):
            if session.family_id == family_id and session.revoked_at is None:
                self.store.sessions[session_id] = replace(session, revoked_at=revoked_at)
                count += 1
        return count

    async def revoke_user_sessions(self, user_id: UUID, *, revoked_at: datetime) -> int:
        count = 0
        for session_id, session in tuple(self.store.sessions.items()):
            if session.user_id == user_id and session.revoked_at is None:
                self.store.sessions[session_id] = replace(session, revoked_at=revoked_at)
                count += 1
        return count

    async def add_security_event(self, event: SecurityEvent) -> None:
        self.store.events.append(event)

    async def delete_expired_passkey_challenges(self, now: datetime) -> int:
        expired = [
            challenge_id
            for challenge_id, challenge in self.store.passkey_challenges.items()
            if challenge.expires_at <= now
        ]
        for challenge_id in expired:
            del self.store.passkey_challenges[challenge_id]
        return len(expired)

    async def insert_passkey_challenge(self, challenge: PasskeyChallenge) -> None:
        duplicate = challenge.id in self.store.passkey_challenges or any(
            existing.challenge == challenge.challenge
            for existing in self.store.passkey_challenges.values()
        )
        if duplicate:
            raise StoreConflictError("passkey challenge already exists")
        self.store.passkey_challenges[challenge.id] = challenge

    async def consume_passkey_challenge(
        self,
        challenge_id: UUID,
        purpose: PasskeyCeremonyPurpose,
        now: datetime,
        user_id: UUID | None,
    ) -> PasskeyChallenge | None:
        challenge = self.store.passkey_challenges.get(challenge_id)
        if (
            challenge is None
            or challenge.purpose is not purpose
            or challenge.user_id != user_id
            or challenge.consumed_at is not None
            or challenge.expires_at <= now
        ):
            return None
        consumed = replace(challenge, consumed_at=now)
        self.store.passkey_challenges[challenge_id] = consumed
        return consumed

    async def count_passkeys(self, user_id: UUID) -> int:
        return sum(
            credential.user_id == user_id and credential.revoked_at is None
            for credential in self.store.passkeys.values()
        )

    async def list_passkeys(self, user_id: UUID) -> Sequence[PasskeyCredential]:
        credentials = (
            credential
            for credential in self.store.passkeys.values()
            if credential.user_id == user_id and credential.revoked_at is None
        )
        return tuple(sorted(credentials, key=lambda item: (item.created_at, str(item.id))))

    async def get_passkey_by_id(
        self,
        passkey_id: UUID,
        user_id: UUID,
        *,
        for_update: bool = False,
    ) -> PasskeyCredential | None:
        del for_update
        credential = self.store.passkeys.get(passkey_id)
        if credential is None or credential.user_id != user_id:
            return None
        return credential

    async def get_passkey_by_credential_id(
        self,
        credential_id: bytes,
        *,
        for_update: bool = False,
    ) -> PasskeyCredential | None:
        del for_update
        return next(
            (
                credential
                for credential in self.store.passkeys.values()
                if credential.credential_id == credential_id
            ),
            None,
        )

    async def insert_passkey(self, credential: PasskeyCredential) -> None:
        duplicate = credential.id in self.store.passkeys or any(
            existing.credential_id == credential.credential_id
            for existing in self.store.passkeys.values()
        )
        if duplicate:
            raise StoreConflictError("passkey already exists")
        self.store.passkeys[credential.id] = credential

    async def update_passkey(self, credential: PasskeyCredential) -> None:
        if credential.id not in self.store.passkeys:
            raise KeyError(credential.id)
        self.store.passkeys[credential.id] = credential
