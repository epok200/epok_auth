from __future__ import annotations

import asyncio
import copy
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID

from epok_auth.models import RefreshSession, SecurityEvent, UserAccount, UserStatus
from epok_auth.store import AuthTransaction, StoreConflictError


class MemoryAuthStore:
    """Transactional adapter for tests and examples; never use it in production."""

    def __init__(self) -> None:
        self.users: dict[UUID, UserAccount] = {}
        self.sessions: dict[UUID, RefreshSession] = {}
        self.events: list[SecurityEvent] = []
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[AuthTransaction]:
        async with self._lock:
            snapshot = copy.deepcopy((self.users, self.sessions, self.events))
            try:
                yield _MemoryTransaction(self)
            except BaseException:
                self.users, self.sessions, self.events = snapshot
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
