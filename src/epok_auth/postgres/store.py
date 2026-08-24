from collections.abc import AsyncGenerator, Sequence
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Self
from uuid import UUID

from sqlalchemy import and_, delete, func, insert, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from epok_auth.google.models import (
    ExternalIdentity,
    GoogleChallenge,
    GoogleChallengePurpose,
)
from epok_auth.google.store import GoogleTransaction
from epok_auth.models import RefreshSession, SecurityEvent, UserAccount, UserStatus
from epok_auth.passkeys.models import (
    PasskeyCeremonyPurpose,
    PasskeyChallenge,
    PasskeyCredential,
)
from epok_auth.postgres._mapping import (
    challenge_from_row,
    challenge_values,
    external_identity_from_row,
    external_identity_values,
    google_challenge_from_row,
    google_challenge_values,
    passkey_from_row,
    passkey_values,
    session_from_row,
    session_values,
    user_from_row,
    user_values,
)
from epok_auth.postgres.tables import (
    external_identity,
    google_challenge,
    passkey_challenge,
    passkey_credential,
    refresh_session,
    security_event,
    user_account,
)
from epok_auth.store import StoreConflictError

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
    ) -> Self:
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
    async def transaction(self) -> AsyncGenerator[GoogleTransaction, None]:
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
        statement = (
            select(func.count())
            .select_from(user_account)
            .where(user_account.c.roles.contains([role]))
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
        return user_from_row(row) if row else None

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
        return user_from_row(row) if row else None

    async def list_users(self, *, limit: int, offset: int) -> Sequence[UserAccount]:
        statement = (
            select(user_account)
            .order_by(user_account.c.created_at, user_account.c.id)
            .limit(limit)
            .offset(offset)
        )
        rows = (await self.connection.execute(statement)).mappings().all()
        return tuple(user_from_row(row) for row in rows)

    async def insert_user(self, user: UserAccount) -> None:
        try:
            await self.connection.execute(insert(user_account).values(user_values(user)))
        except IntegrityError as error:
            raise StoreConflictError("user uniqueness constraint failed") from error

    async def update_user(self, user: UserAccount) -> None:
        try:
            result = await self.connection.execute(
                update(user_account).where(user_account.c.id == user.id).values(user_values(user))
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
        return session_from_row(row) if row else None

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
        return session_from_row(row) if row else None

    async def insert_session(self, session: RefreshSession) -> None:
        try:
            await self.connection.execute(insert(refresh_session).values(session_values(session)))
        except IntegrityError as error:
            raise StoreConflictError("session uniqueness constraint failed") from error

    async def update_session(self, session: RefreshSession) -> None:
        try:
            result = await self.connection.execute(
                update(refresh_session)
                .where(refresh_session.c.id == session.id)
                .values(session_values(session))
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

    async def delete_expired_passkey_challenges(self, now: datetime) -> int:
        result = await self.connection.execute(
            delete(passkey_challenge).where(passkey_challenge.c.expires_at <= now)
        )
        return int(result.rowcount or 0)

    async def insert_passkey_challenge(self, challenge: PasskeyChallenge) -> None:
        try:
            await self.connection.execute(
                insert(passkey_challenge).values(challenge_values(challenge))
            )
        except IntegrityError as error:
            raise StoreConflictError("passkey challenge uniqueness constraint failed") from error

    async def consume_passkey_challenge(
        self,
        challenge_id: UUID,
        purpose: PasskeyCeremonyPurpose,
        now: datetime,
        user_id: UUID | None,
    ) -> PasskeyChallenge | None:
        user_condition = passkey_challenge.c.user_id.is_(None)
        if user_id is not None:
            user_condition = passkey_challenge.c.user_id == user_id
        statement = (
            update(passkey_challenge)
            .where(
                passkey_challenge.c.id == challenge_id,
                passkey_challenge.c.purpose == purpose.value,
                user_condition,
                passkey_challenge.c.consumed_at.is_(None),
                passkey_challenge.c.expires_at > now,
            )
            .values(consumed_at=now)
            .returning(passkey_challenge)
        )
        row = (await self.connection.execute(statement)).mappings().first()
        return challenge_from_row(row) if row else None

    async def count_passkeys(self, user_id: UUID) -> int:
        statement = (
            select(func.count())
            .select_from(passkey_credential)
            .where(
                passkey_credential.c.user_id == user_id,
                passkey_credential.c.revoked_at.is_(None),
            )
        )
        result = await self.connection.scalar(statement)
        return int(result or 0)

    async def list_passkeys(self, user_id: UUID) -> Sequence[PasskeyCredential]:
        statement = (
            select(passkey_credential)
            .where(
                passkey_credential.c.user_id == user_id,
                passkey_credential.c.revoked_at.is_(None),
            )
            .order_by(passkey_credential.c.created_at, passkey_credential.c.id)
        )
        rows = (await self.connection.execute(statement)).mappings().all()
        return tuple(passkey_from_row(row) for row in rows)

    async def get_passkey_by_id(
        self,
        passkey_id: UUID,
        user_id: UUID,
        *,
        for_update: bool = False,
    ) -> PasskeyCredential | None:
        statement = select(passkey_credential).where(
            passkey_credential.c.id == passkey_id,
            passkey_credential.c.user_id == user_id,
        )
        if for_update:
            statement = statement.with_for_update()
        row = (await self.connection.execute(statement)).mappings().first()
        return passkey_from_row(row) if row else None

    async def get_passkey_by_credential_id(
        self,
        credential_id: bytes,
        *,
        for_update: bool = False,
    ) -> PasskeyCredential | None:
        statement = select(passkey_credential).where(
            passkey_credential.c.credential_id == credential_id
        )
        if for_update:
            statement = statement.with_for_update()
        row = (await self.connection.execute(statement)).mappings().first()
        return passkey_from_row(row) if row else None

    async def insert_passkey(self, credential: PasskeyCredential) -> None:
        try:
            await self.connection.execute(
                insert(passkey_credential).values(passkey_values(credential))
            )
        except IntegrityError as error:
            raise StoreConflictError("passkey uniqueness constraint failed") from error

    async def update_passkey(self, credential: PasskeyCredential) -> None:
        try:
            result = await self.connection.execute(
                update(passkey_credential)
                .where(passkey_credential.c.id == credential.id)
                .values(passkey_values(credential))
            )
        except IntegrityError as error:
            raise StoreConflictError("passkey update constraint failed") from error
        if result.rowcount != 1:
            raise KeyError(credential.id)

    async def delete_expired_google_challenges(self, now: datetime) -> int:
        result = await self.connection.execute(
            delete(google_challenge).where(google_challenge.c.expires_at <= now)
        )
        return int(result.rowcount or 0)

    async def insert_google_challenge(self, challenge: GoogleChallenge) -> None:
        try:
            await self.connection.execute(
                insert(google_challenge).values(google_challenge_values(challenge))
            )
        except IntegrityError as error:
            raise StoreConflictError("Google challenge uniqueness constraint failed") from error

    async def consume_google_challenge(
        self,
        challenge_id: UUID,
        purpose: GoogleChallengePurpose,
        now: datetime,
        user_id: UUID | None,
    ) -> GoogleChallenge | None:
        user_condition = google_challenge.c.user_id.is_(None)
        if user_id is not None:
            user_condition = google_challenge.c.user_id == user_id
        statement = (
            update(google_challenge)
            .where(
                google_challenge.c.id == challenge_id,
                google_challenge.c.purpose == purpose.value,
                user_condition,
                google_challenge.c.consumed_at.is_(None),
                google_challenge.c.expires_at > now,
            )
            .values(consumed_at=now)
            .returning(google_challenge)
        )
        row = (await self.connection.execute(statement)).mappings().first()
        return google_challenge_from_row(row) if row else None

    async def get_external_identity(
        self,
        issuer: str,
        subject: str,
        *,
        for_update: bool = False,
    ) -> ExternalIdentity | None:
        statement = select(external_identity).where(
            external_identity.c.issuer == issuer,
            external_identity.c.subject == subject,
        )
        if for_update:
            statement = statement.with_for_update()
        row = (await self.connection.execute(statement)).mappings().first()
        return external_identity_from_row(row) if row else None

    async def get_external_identity_for_user(
        self,
        user_id: UUID,
        issuer: str,
        *,
        for_update: bool = False,
    ) -> ExternalIdentity | None:
        statement = select(external_identity).where(
            external_identity.c.user_id == user_id,
            external_identity.c.issuer == issuer,
        )
        if for_update:
            statement = statement.with_for_update()
        row = (await self.connection.execute(statement)).mappings().first()
        return external_identity_from_row(row) if row else None

    async def insert_external_identity(self, identity: ExternalIdentity) -> None:
        try:
            await self.connection.execute(
                insert(external_identity).values(external_identity_values(identity))
            )
        except IntegrityError as error:
            raise StoreConflictError("external identity uniqueness constraint failed") from error

    async def update_external_identity(self, identity: ExternalIdentity) -> None:
        try:
            result = await self.connection.execute(
                update(external_identity)
                .where(external_identity.c.id == identity.id)
                .values(external_identity_values(identity))
            )
        except IntegrityError as error:
            raise StoreConflictError("external identity update constraint failed") from error
        if result.rowcount != 1:
            raise KeyError(identity.id)

    async def delete_external_identity(self, identity_id: UUID) -> None:
        result = await self.connection.execute(
            delete(external_identity).where(external_identity.c.id == identity_id)
        )
        if result.rowcount != 1:
            raise KeyError(identity_id)


def async_psycopg_url(url: str) -> str:
    if url.startswith("postgresql+psycopg://"):
        return url
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url.removeprefix("postgresql://")
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url.removeprefix("postgres://")
    raise ValueError("PostgreSQL URLs must use postgresql:// or postgresql+psycopg://")
