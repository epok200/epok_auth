import pytest
from sqlalchemy import func, select

from epok_auth.config import AuthSettings
from epok_auth.errores import AuthError, AuthErrorCode
from epok_auth.models import SecurityEventType, UserStatus, UserUpdate
from epok_auth.postgres import PostgresAuthStore
from epok_auth.postgres.tables import security_event
from epok_auth.service import AuthService
from tests.test_postgres_integration import database_url as database_url
from tests.test_postgres_integration import reset_database as reset_database
from tests.test_postgres_integration import settings as settings
from tests.test_postgres_integration import store as store

pytestmark = pytest.mark.integration


async def test_postgres_borrowed_transaction_leaves_commit_and_rollback_to_caller(
    store: PostgresAuthStore, settings: AuthSettings
) -> None:
    service = AuthService(store=store, settings=settings)
    created = await service.create_user(email="outer@example.com", display_name="Outer")
    bundle = await service.login(created.user.email, created.temporary_password)
    before = await service.get_user(created.user.id)
    event_count = (
        select(func.count())
        .select_from(security_event)
        .where(
            security_event.c.user_id == created.user.id,
            security_event.c.event_type == SecurityEventType.USER_DISABLED.value,
        )
    )
    async with store.engine.connect() as connection:
        async with connection.begin() as outer:
            async with store.transaction(connection=connection) as transaction:
                await service.update_user(
                    created.user.id,
                    UserUpdate(status=UserStatus.DISABLED),
                    transaction=transaction,
                )
            assert connection.in_transaction()
            await outer.rollback()
    assert await service.get_user(created.user.id) == before
    assert (await service.authenticate(bundle.access_token)).user_id == created.user.id
    async with store.transaction() as transaction:
        session = await transaction.get_session_by_id(bundle.principal.session_id)
        assert session is not None and session.revoked_at is None
    async with store.engine.connect() as connection:
        assert await connection.scalar(event_count) == 0
    async with store.engine.begin() as connection:
        async with store.transaction(connection=connection) as transaction:
            await service.update_user(
                created.user.id, UserUpdate(status=UserStatus.DISABLED), transaction=transaction
            )
    disabled = await service.get_user(created.user.id)
    assert disabled.status is UserStatus.DISABLED
    assert disabled.security_version == before.security_version + 1
    with pytest.raises(AuthError) as invalid_token:
        await service.authenticate(bundle.access_token)
    assert invalid_token.value.code is AuthErrorCode.INVALID_TOKEN
    async with store.transaction() as transaction:
        session = await transaction.get_session_by_id(bundle.principal.session_id)
        assert session is not None and session.revoked_at is not None
    async with store.engine.connect() as connection:
        assert await connection.scalar(event_count) == 1


async def test_postgres_rejects_connection_without_transaction(store: PostgresAuthStore) -> None:
    async with store.engine.connect() as connection:
        with pytest.raises(AuthError) as captured:
            async with store.transaction(connection=connection):
                raise AssertionError("invalid connection was accepted")
        assert captured.value.code is AuthErrorCode.CONFIG_INVALID


async def test_postgres_rejects_connection_from_another_engine(
    store: PostgresAuthStore, database_url: str
) -> None:
    other = PostgresAuthStore.from_url(database_url)
    try:
        async with other.engine.begin() as connection:
            with pytest.raises(AuthError) as captured:
                async with store.transaction(connection=connection):
                    raise AssertionError("foreign engine was accepted")
            assert captured.value.code is AuthErrorCode.CONFIG_INVALID
    finally:
        await other.aclose()
