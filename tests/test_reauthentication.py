from dataclasses import replace
from uuid import uuid4

import pytest

from epok_auth.errores import AuthError, AuthErrorCode
from epok_auth.models import ReauthenticationMethod, SecurityEventType
from epok_auth.passwords import PasswordManager
from epok_auth.service import AuthService
from epok_auth.testing import MemoryAuthStore
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, MutableClock


class UpgradeHash:
    def hash(self, password: str) -> str:
        return f"old:{password}"

    def verify_and_update(self, password: str, encoded_hash: str) -> tuple[bool, str | None]:
        valid = encoded_hash in {f"old:{password}", f"new:{password}"}
        updated = f"new:{password}" if valid and encoded_hash.startswith("old:") else None
        return valid, updated


async def create_session(service: AuthService):
    await service.create_admin(
        email=ADMIN_EMAIL,
        display_name="Admin",
        password=ADMIN_PASSWORD,
    )
    return await service.login(ADMIN_EMAIL, ADMIN_PASSWORD)


@pytest.mark.asyncio
async def test_password_reauthentication_reuses_session_and_upgrades_hash(
    store: MemoryAuthStore,
    settings,
    clock: MutableClock,
) -> None:
    passwords = PasswordManager.recommended(
        minimum=settings.password_min_length,
        maximum=settings.password_max_length,
        password_hash=UpgradeHash(),
    )
    service = AuthService(store=store, settings=settings, passwords=passwords, clock=clock)
    bundle = await create_session(service)
    user = store.users[bundle.principal.user_id]
    store.users[user.id] = replace(user, password_hash=f"old:{ADMIN_PASSWORD}")
    session_count = len(store.sessions)
    session_before = store.sessions[bundle.principal.session_id]
    event_count = len(store.events)

    result = await service.reauthenticate_password(bundle.principal, ADMIN_PASSWORD)

    assert result.user_id == bundle.principal.user_id
    assert result.session_id == bundle.principal.session_id
    assert result.family_id == bundle.principal.family_id
    assert result.method is ReauthenticationMethod.PASSWORD
    assert result.verified_at == clock.value
    assert len(store.sessions) == session_count
    assert store.sessions[bundle.principal.session_id] == session_before
    assert store.users[user.id].password_hash == f"new:{ADMIN_PASSWORD}"
    new_events = store.events[event_count:]
    assert [event.event_type for event in new_events] == [
        SecurityEventType.REAUTHENTICATION_SUCCEEDED
    ]
    assert new_events[0].metadata == {"method": "password"}


@pytest.mark.asyncio
async def test_password_reauthentication_preserves_lockout_policy(
    service: AuthService,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    bundle = await create_session(service)

    for _ in range(3):
        with pytest.raises(AuthError) as captured:
            await service.reauthenticate_password(
                bundle.principal,
                "wrong password value",
            )
        assert captured.value.code is AuthErrorCode.INVALID_CREDENTIALS

    user = store.users[bundle.principal.user_id]
    assert user.failed_login_attempts == 3
    assert user.locked_until is not None
    assert store.sessions[bundle.principal.session_id].revoked_at == clock.value
    failures = [
        event
        for event in store.events
        if event.event_type is SecurityEventType.REAUTHENTICATION_FAILED
    ]
    assert len(failures) == 3
    assert all(event.metadata == {"method": "password"} for event in failures)


@pytest.mark.asyncio
async def test_password_reauthentication_rejects_another_session_family(
    service: AuthService,
) -> None:
    bundle = await create_session(service)
    mismatched = replace(bundle.principal, family_id=uuid4())

    with pytest.raises(AuthError) as captured:
        await service.reauthenticate_password(mismatched, ADMIN_PASSWORD)

    assert captured.value.code is AuthErrorCode.INVALID_TOKEN
