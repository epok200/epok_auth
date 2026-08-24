from datetime import datetime
from uuid import UUID

from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection

from epok_auth.email_links.models import EmailLink, EmailLinkPurpose, EmailLinkState
from epok_auth.postgres._mapping import email_link_from_row, email_link_values
from epok_auth.postgres.tables import email_link
from epok_auth.store import StoreConflictError


class PostgresEmailLinkMethods:
    """Email-link persistence methods kept separate from the main adapter."""

    connection: AsyncConnection

    async def delete_old_email_links(self, before: datetime) -> int:
        result = await self.connection.execute(
            delete(email_link).where(email_link.c.created_at < before)
        )
        return int(result.rowcount or 0)

    async def count_email_link_requests(
        self,
        user_id: UUID,
        purpose: EmailLinkPurpose,
        since: datetime,
    ) -> int:
        statement = (
            select(func.count())
            .select_from(email_link)
            .where(
                email_link.c.user_id == user_id,
                email_link.c.purpose == purpose.value,
                email_link.c.created_at >= since,
            )
        )
        result = await self.connection.scalar(statement)
        return int(result or 0)

    async def get_latest_email_link(
        self,
        user_id: UUID,
        purpose: EmailLinkPurpose,
    ) -> EmailLink | None:
        statement = (
            select(email_link)
            .where(
                email_link.c.user_id == user_id,
                email_link.c.purpose == purpose.value,
            )
            .order_by(email_link.c.generation.desc())
            .limit(1)
        )
        row = (await self.connection.execute(statement)).mappings().first()
        return email_link_from_row(row) if row else None

    async def get_email_link(
        self,
        link_id: UUID,
        *,
        for_update: bool = False,
    ) -> EmailLink | None:
        statement = select(email_link).where(email_link.c.id == link_id)
        if for_update:
            statement = statement.with_for_update()
        row = (await self.connection.execute(statement)).mappings().first()
        return email_link_from_row(row) if row else None

    async def get_email_link_by_token_hash(
        self,
        token_hash: str,
        purpose: EmailLinkPurpose,
    ) -> EmailLink | None:
        statement = select(email_link).where(
            email_link.c.token_hash == token_hash,
            email_link.c.purpose == purpose.value,
        )
        row = (await self.connection.execute(statement)).mappings().first()
        return email_link_from_row(row) if row else None

    async def insert_email_link(self, link: EmailLink) -> None:
        try:
            await self.connection.execute(insert(email_link).values(email_link_values(link)))
        except IntegrityError as error:
            raise StoreConflictError("email link uniqueness constraint failed") from error

    async def activate_email_link(
        self,
        link_id: UUID,
        now: datetime,
    ) -> EmailLink | None:
        statement = (
            update(email_link)
            .where(
                email_link.c.id == link_id,
                email_link.c.state == EmailLinkState.PENDING.value,
            )
            .values(state=EmailLinkState.ACTIVE.value, delivered_at=now)
            .returning(email_link)
        )
        row = (await self.connection.execute(statement)).mappings().first()
        return email_link_from_row(row) if row else None

    async def fail_email_link(
        self,
        link_id: UUID,
        now: datetime,
    ) -> EmailLink | None:
        return await self._close_email_link(
            link_id,
            now,
            EmailLinkState.FAILED,
            allowed_states=(EmailLinkState.PENDING,),
        )

    async def revoke_email_link(
        self,
        link_id: UUID,
        now: datetime,
    ) -> EmailLink | None:
        return await self._close_email_link(
            link_id,
            now,
            EmailLinkState.REVOKED,
            allowed_states=(EmailLinkState.PENDING, EmailLinkState.ACTIVE),
        )

    async def revoke_other_active_email_links(
        self,
        user_id: UUID,
        purpose: EmailLinkPurpose,
        active_link_id: UUID,
        now: datetime,
    ) -> int:
        result = await self.connection.execute(
            update(email_link)
            .where(
                email_link.c.user_id == user_id,
                email_link.c.purpose == purpose.value,
                email_link.c.id != active_link_id,
                email_link.c.state == EmailLinkState.ACTIVE.value,
            )
            .values(state=EmailLinkState.REVOKED.value, revoked_at=now)
        )
        return int(result.rowcount or 0)

    async def consume_email_link(
        self,
        link_id: UUID,
        purpose: EmailLinkPurpose,
        now: datetime,
    ) -> EmailLink | None:
        statement = (
            update(email_link)
            .where(
                email_link.c.id == link_id,
                email_link.c.purpose == purpose.value,
                email_link.c.state == EmailLinkState.ACTIVE.value,
                email_link.c.expires_at > now,
            )
            .values(state=EmailLinkState.CONSUMED.value, consumed_at=now)
            .returning(email_link)
        )
        row = (await self.connection.execute(statement)).mappings().first()
        return email_link_from_row(row) if row else None

    async def _close_email_link(
        self,
        link_id: UUID,
        now: datetime,
        state: EmailLinkState,
        *,
        allowed_states: tuple[EmailLinkState, ...],
    ) -> EmailLink | None:
        statement = (
            update(email_link)
            .where(
                email_link.c.id == link_id,
                email_link.c.state.in_(item.value for item in allowed_states),
            )
            .values(state=state.value, revoked_at=now)
            .returning(email_link)
        )
        row = (await self.connection.execute(statement)).mappings().first()
        return email_link_from_row(row) if row else None
