from contextlib import AbstractAsyncContextManager
from datetime import datetime
from typing import Protocol
from uuid import UUID

from epok_auth.email_links.models import EmailLink, EmailLinkPurpose
from epok_auth.store import AuthTransaction


class EmailLinkTransaction(AuthTransaction, Protocol):
    async def delete_old_email_links(self, before: datetime) -> int: ...
    async def count_email_link_requests(
        self,
        user_id: UUID,
        purpose: EmailLinkPurpose,
        since: datetime,
    ) -> int: ...
    async def get_latest_email_link(
        self,
        user_id: UUID,
        purpose: EmailLinkPurpose,
    ) -> EmailLink | None: ...
    async def get_email_link(
        self,
        link_id: UUID,
        *,
        for_update: bool = False,
    ) -> EmailLink | None: ...
    async def get_email_link_by_token_hash(
        self,
        token_hash: str,
        purpose: EmailLinkPurpose,
    ) -> EmailLink | None: ...
    async def insert_email_link(self, link: EmailLink) -> None: ...
    async def activate_email_link(self, link_id: UUID, now: datetime) -> EmailLink | None: ...
    async def fail_email_link(self, link_id: UUID, now: datetime) -> EmailLink | None: ...
    async def revoke_email_link(self, link_id: UUID, now: datetime) -> EmailLink | None: ...
    async def revoke_other_active_email_links(
        self,
        user_id: UUID,
        purpose: EmailLinkPurpose,
        active_link_id: UUID,
        now: datetime,
    ) -> int: ...
    async def consume_email_link(
        self,
        link_id: UUID,
        purpose: EmailLinkPurpose,
        now: datetime,
    ) -> EmailLink | None: ...


class EmailLinkStore(Protocol):
    def transaction(self) -> AbstractAsyncContextManager[EmailLinkTransaction]: ...
