import pytest

from epok_auth.config import AuthSettings
from epok_auth.errores import AuthError, AuthErrorCode
from epok_auth.models import UserStatus, UserUpdate
from epok_auth.postgres import PostgresAuthStore
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
    assert await service.get_user(created.user.id) == created.user
    async with store.engine.begin() as connection:
        async with store.transaction(connection=connection) as transaction:
            await service.update_user(
                created.user.id, UserUpdate(status=UserStatus.DISABLED), transaction=transaction
            )
    assert (await service.get_user(created.user.id)).status is UserStatus.DISABLED


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
