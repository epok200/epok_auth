import pytest

from epok_auth.errors import AuthError, AuthErrorCode
from epok_auth.testing import MemoryAuthStore
from tests.conftest import MutableClock
from tests.google.fakes import ORIGIN, claims, create_harness


@pytest.mark.asyncio
@pytest.mark.security
async def test_recovery_invalidates_a_link_challenge_already_in_progress(
    settings,
    store: MemoryAuthStore,
    clock: MutableClock,
) -> None:
    harness = create_harness(settings, store, clock)
    admin = await harness.auth.create_admin(
        email="admin@example.com",
        display_name="Admin",
        password="recovery race protects private colors",
    )
    session = await harness.auth.login(admin.email, "recovery race protects private colors")
    first = await harness.google.begin_link(session.principal, ORIGIN)
    harness.verifier.add("first-link", claims())
    await harness.google.finish_link(
        session.principal,
        first.challenge_id,
        "first-link",
        ORIGIN,
    )

    in_progress = await harness.google.begin_link(session.principal, ORIGIN)
    await harness.google.recover_password_access(admin.id)
    harness.verifier.add("late-link", claims())

    with pytest.raises(AuthError) as captured:
        await harness.google.finish_link(
            session.principal,
            in_progress.challenge_id,
            "late-link",
            ORIGIN,
        )

    assert captured.value.code is AuthErrorCode.INVALID_TOKEN
    assert store.external_identities == {}
