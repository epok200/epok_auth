from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, insert, select, text, update
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from epok_auth.models import RefreshSession, SecurityEvent, UserAccount, UserStatus
from epok_auth.postgres.tables import refresh_session, security_event, user_account
from epok_auth.store import AuthTransaction, StoreConflictError

_ADMIN_LOCK_ID = int.from_bytes(b"EPOKAUTH", byteorder="big", signed=True)


class PostgresAuthStore:
    """Official asynchronous PostgreSQL persistence adapter."""

    def __init__(self, engine: AsyncEngine) -> None:
        self.engine = engine

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        pool_size: int = 5,
        max_overflow: int = 10,
        pool_timeout: float = 5.0,
        pool_pre_ping: bool = True,
        echo: bool = False,
    ) -> PostgresAuthStore:
        engine = create_async_engine(
            async_psycopg_url(url),
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_timeout=pool_timeout,
            pool_pre_ping=pool_pre_ping,
            echo=echo,
        )
        return cls(engine)

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[AuthTransaction]:
        async with self.engine.begin() as connection:
            yield PostgresAuthTransaction(connection)

    async def aclose(self) -> None:
        await self.engine.dispose()


class PostgresAuthTransaction:
    def __init__(self, connection: AsyncConnection) -> None:
        self.connection = connection

    async def acquire_admin_invariant_lock(self) -> None:
        await self.connection.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": _ADMIN_LOCK_ID},
        )

    async def count_users_with_role(self, role: str, *, active_only: bool) -> int:
        statement = select(func.count()).select_from(user_account).where(
            user_account.c.roles.contains([role])
        )
        if active_only:
            statement = statement.where(user_account.c.status == UserStatus.ACTIVE.value)
        result = await self.connection.scalar(statement)
        return int(result or 0)

    async def get_user_by_email(
        self,
        email: str,
        *,
        for_update: bool = False,
    ) -> UserAccount | None:
        statement = select(user_account).where(user_account.c.email == email)
        if for_update:
            statement = statement.with_for_update()
        row = (await self.connection.execute(statement)).mappings().first()
        return _user(row) if row else None

    async def get_user_by_id(
        self,
        user_id: UUID,
        *,
        for_update: bool = False,
    ) -> UserAccount | None:
        statement = select(user_account).where(user_account.c.id == user_id)
        if for_update:
            statement = statement.with_for_update()
        row = (await self.connection.execute(statement)).mappings().first()
        return _user(row) if row else None

    async def list_users(self, *, limit: int, offset: int) -> Sequence[UserAccount]:
        statement = (
            select(user_account)
            .order_by(user_account.c.created_at, user_account.c.id)
            .limit(limit)
            .offset(offset)
        )
        rows = (await self.connection.execute(statement)).mappings().all()
        return tuple(_user(row) for row in rows)

    async def insert_user(self, user: UserAccount) -> None:
        try:
            await self.connection.execute(insert(user_account).values(_user_values(user)))
        except IntegrityError as error:
            raise StoreConflictError("user uniqueness constraint failed") from error

    async def update_user(self, user: UserAccount) -> None:
        try:
            result = await self.connection.execute(
                update(user_account)
                .where(user_account.c.id == user.id)
                .values(_user_values(user))
            )
        except IntegrityError as error:
            raise StoreConflictError("user uniqueness constraint failed") from error
        if result.rowcount != 1:
            raise KeyError(user.id)

    async def get_session_by_token_hash(
        self,
        token_hash: str,
        *,
        for_update: bool = False,
    ) -> RefreshSession | None:
        statement = select(refresh_session).where(refresh_session.c.token_hash == token_hash)
        if for_update:
            statement = statement.with_for_update()
        row = (await self.connection.execute(statement)).mappings().first()
        return _session(row) if row else None

    async def get_session_by_id(
        self,
        session_id: UUID,
        *,
        for_update: bool = False,
    ) -> RefreshSession | None:
        statement = select(refresh_session).where(refresh_session.c.id == session_id)
        if for_update:
            statement = statement.with_for_update()
        row = (await self.connection.execute(statement)).mappings().first()
        return _session(row) if row else None

    async def insert_session(self, session: RefreshSession) -> None:
        try:
            await self.connection.execute(insert(refresh_session).values(_session_values(session)))
        except IntegrityError as error:
            raise StoreConflictError("session uniqueness constraint failed") from error

    async def update_session(self, session: RefreshSession) -> None:
        try:
            result = await self.connection.execute(
                update(refresh_session)
                .where(refresh_session.c.id == session.id)
                .values(_session_values(session))
            )
        except IntegrityError as error:
            raise StoreConflictError("session update constraint failed") from error
        if result.rowcount != 1:
            raise KeyError(session.id)

    async def revoke_family(self, family_id: UUID, *, revoked_at: datetime) -> int:
        result = await self.connection.execute(
            update(refresh_session)
            .where(
                and_(
                    refresh_session.c.family_id == family_id,
                    refresh_session.c.revoked_at.is_(None),
                )
            )
            .values(revoked_at=revoked_at)
        )
        return int(result.rowcount or 0)

    async def revoke_user_sessions(self, user_id: UUID, *, revoked_at: datetime) -> int:
        result = await self.connection.execute(
            update(refresh_session)
            .where(
                and_(
                    refresh_session.c.user_id == user_id,
                    refresh_session.c.revoked_at.is_(None),
                )
            )
            .values(revoked_at=revoked_at)
        )
        return int(result.rowcount or 0)

    async def add_security_event(self, event: SecurityEvent) -> None:
        await self.connection.execute(
            insert(security_event).values(
                event_type=event.event_type.value,
                occurred_at=event.occurred_at,
                user_id=event.user_id,
                session_id=event.session_id,
                request_id=event.request_id,
                ip_address=event.ip_address,
                user_agent=event.user_agent,
                event_metadata=event.metadata,
            )
        )


def _user_values(user: UserAccount) -> dict[str, Any]:
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "password_hash": user.password_hash,
        "status": user.status.value,
        "roles": list(user.roles),
        "scopes": list(user.scopes),
        "must_change_password": user.must_change_password,
        "failed_login_attempts": user.failed_login_attempts,
        "locked_until": user.locked_until,
        "password_changed_at": user.password_changed_at,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    }


def _session_values(session: RefreshSession) -> dict[str, Any]:
    return {
        "id": session.id,
        "user_id": session.user_id,
        "family_id": session.family_id,
        "token_hash": session.token_hash,
        "csrf_hash": session.csrf_hash,
        "created_at": session.created_at,
        "idle_expires_at": session.idle_expires_at,
        "absolute_expires_at": session.absolute_expires_at,
        "authenticated_at": session.authenticated_at,
        "used_at": session.used_at,
        "revoked_at": session.revoked_at,
        "replaced_by_id": session.replaced_by_id,
    }


def _user(row: RowMapping) -> UserAccount:
    return UserAccount(
        id=row["id"],
        email=row["email"],
        display_name=row["display_name"],
        password_hash=row["password_hash"],
        status=UserStatus(row["status"]),
        roles=tuple(row["roles"] or ()),
        scopes=tuple(row["scopes"] or ()),
        must_change_password=row["must_change_password"],
        failed_login_attempts=row["failed_login_attempts"],
        locked_until=row["locked_until"],
        password_changed_at=row["password_changed_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _session(row: RowMapping) -> RefreshSession:
    return RefreshSession(
        id=row["id"],
        user_id=row["user_id"],
        family_id=row["family_id"],
        token_hash=row["token_hash"],
        csrf_hash=row["csrf_hash"],
        created_at=row["created_at"],
        idle_expires_at=row["idle_expires_at"],
        absolute_expires_at=row["absolute_expires_at"],
        authenticated_at=row["authenticated_at"],
        used_at=row["used_at"],
        revoked_at=row["revoked_at"],
        replaced_by_id=row["replaced_by_id"],
    )


def async_psycopg_url(url: str) -> str:
    if url.startswith("postgresql+psycopg://"):
        return url
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url.removeprefix("postgresql://")
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url.removeprefix("postgres://")
    raise ValueError("PostgreSQL URLs must use postgresql:// or postgresql+psycopg://")
