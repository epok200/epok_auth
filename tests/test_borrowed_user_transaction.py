import pytest

from epok_auth.errores import AuthError
from epok_auth.models import SecurityEventType, UserStatus, UserUpdate
from epok_auth.service import AuthService
from epok_auth.testing import MemoryAuthStore


async def test_user_update_uses_the_callers_transaction(
    service: AuthService, store: MemoryAuthStore
) -> None:
    created = await service.create_user(email="borrowed@example.com", display_name="Borrowed")
    async with store.transaction() as transaction:
        disabled = await service.update_user(
            created.user.id, UserUpdate(status=UserStatus.DISABLED), transaction=transaction
        )
        assert disabled.status is UserStatus.DISABLED
        assert disabled.security_version == created.user.security_version + 1
    assert (await service.get_user(created.user.id)) == disabled
    assert store.events[-1].event_type is SecurityEventType.USER_DISABLED


async def test_failed_outer_transaction_restores_user_and_security_event(
    service: AuthService, store: MemoryAuthStore
) -> None:
    created = await service.create_user(email="rollback@example.com", display_name="Rollback")
    events = tuple(store.events)
    with pytest.raises(RuntimeError, match="rollback caller"):
        async with store.transaction() as transaction:
            await service.update_user(
                created.user.id, UserUpdate(status=UserStatus.DISABLED), transaction=transaction
            )
            raise RuntimeError("rollback caller")
    assert await service.get_user(created.user.id) == created.user
    assert tuple(store.events) == events


async def test_borrowed_transaction_keeps_last_admin_protection(
    service: AuthService, store: MemoryAuthStore
) -> None:
    admin = await service.create_admin(
        email="last-admin@example.com", display_name="Admin", password="Valid-admin-password-Aa1!"
    )
    with pytest.raises(AuthError):
        async with store.transaction() as transaction:
            await service.update_user(
                admin.id, UserUpdate(status=UserStatus.DISABLED), transaction=transaction
            )
    assert await service.get_user(admin.id) == admin
