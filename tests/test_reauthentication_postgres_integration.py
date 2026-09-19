import asyncio
import os
import threading
from collections.abc import AsyncIterator, Iterator

import pytest

psycopg = pytest.importorskip("psycopg")

from epok_auth.config import AuthSettings, Environment
from epok_auth.errores import AuthError, AuthErrorCode
from epok_auth.migrate import check_database, downgrade_database, upgrade_database
from epok_auth.models import Reauthentication, SecurityEventType
from epok_auth.passkeys.adapter import CredentialPayload, VerifiedPasskeyAuthentication
from epok_auth.passkeys.models import PasskeyCredential
from epok_auth.passkeys.service import PasskeyService
from epok_auth.passkeys.webauthn import WebAuthnAdapter
from epok_auth.postgres import PostgresAuthStore
from epok_auth.service import AuthService
from tests.passkeys.virtual_authenticator import VirtualAuthenticator, decode_base64url

pytestmark = pytest.mark.integration

DATABASE_URL = os.getenv("TEST_DATABASE_URL")
ORIGIN = "http://localhost:3000"
RP_ID = "localhost"
PASSWORD = "postgres reauthentication protects private colors"


class PausedWebAuthnAdapter(WebAuthnAdapter):
    def __init__(self, *, rp_id: str, rp_name: str, timeout_ms: int) -> None:
        super().__init__(rp_id=rp_id, rp_name=rp_name, timeout_ms=timeout_ms)
        self.verification_started = threading.Event()
        self.resume_verification = threading.Event()

    def verify_authentication(
        self,
        credential: CredentialPayload,
        challenge: bytes,
        origin: str,
        stored: PasskeyCredential,
    ) -> VerifiedPasskeyAuthentication:
        self.verification_started.set()
        if not self.resume_verification.wait(timeout=10):
            raise RuntimeError("Passkey verification test timed out")
        return super().verify_authentication(credential, challenge, origin, stored)


def sync_url(url: str) -> str:
    return url.replace("postgresql+psycopg://", "postgresql://", 1)


@pytest.fixture(scope="session")
def database_url() -> str:
    if not DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL is required")
    upgrade_database(DATABASE_URL)
    check_database(DATABASE_URL)
    return DATABASE_URL


@pytest.fixture(autouse=True)
def reset_database(database_url: str) -> Iterator[None]:
    with psycopg.connect(sync_url(database_url), autocommit=True) as connection:
        connection.execute("TRUNCATE epok_auth.user_account RESTART IDENTITY CASCADE")
    yield


@pytest.fixture
def settings(database_url: str) -> AuthSettings:
    return AuthSettings(
        environment=Environment.TEST,
        database_url=database_url,
        jwt_secret="reauthentication-test-secret-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        issuer="reauthentication-tests",
        audience="reauthentication-tests-api",
        secure_cookies=False,
        cookie_use_host_prefix=False,
        trusted_origins=(ORIGIN,),
        passkey_rp_id=RP_ID,
    )


@pytest.fixture
async def store(database_url: str) -> AsyncIterator[PostgresAuthStore]:
    value = PostgresAuthStore.from_url(database_url, pool_size=1, max_overflow=4)
    try:
        yield value
    finally:
        await value.aclose()


async def registered_passkey(
    store: PostgresAuthStore,
    settings: AuthSettings,
):
    auth = AuthService(store=store, settings=settings)
    user = await auth.create_admin(
        email="reauthentication@example.com",
        display_name="Reauthentication Admin",
        password=PASSWORD,
    )
    session = await auth.login(user.email, PASSWORD)
    passkeys = PasskeyService(
        store=store,
        settings=settings,
        signer=auth.signer,
        adapter=WebAuthnAdapter(
            rp_id=RP_ID,
            rp_name=settings.effective_passkey_rp_name,
            timeout_ms=settings.passkey_timeout_ms,
        ),
    )
    authenticator = VirtualAuthenticator()
    registration = await passkeys.begin_registration(session.principal, ORIGIN)
    response = authenticator.registration_response(
        challenge=decode_base64url(registration.public_key["challenge"]),
        rp_id=RP_ID,
        origin=ORIGIN,
    )
    credential = await passkeys.finish_registration(
        session.principal,
        registration.ceremony_id,
        "PostgreSQL reauthentication passkey",
        response,
        ORIGIN,
    )
    return auth, passkeys, authenticator, session, credential


@pytest.mark.asyncio
@pytest.mark.security
async def test_passkey_reauthentication_is_atomic_and_does_not_issue_session(
    store: PostgresAuthStore,
    settings: AuthSettings,
    database_url: str,
) -> None:
    _, passkeys, authenticator, session, credential = await registered_passkey(store, settings)
    options = await passkeys.begin_reauthentication(session.principal, ORIGIN)
    response = authenticator.authentication_response(
        challenge=decode_base64url(options.public_key["challenge"]),
        rp_id=RP_ID,
        origin=ORIGIN,
        user_id=session.principal.user_id,
        sign_count=1,
    )

    async def finish() -> Reauthentication | AuthError:
        try:
            return await passkeys.finish_reauthentication(
                session.principal,
                options.ceremony_id,
                response,
                ORIGIN,
            )
        except AuthError as error:
            return error

    outcomes = await asyncio.gather(finish(), finish())
    successes = [item for item in outcomes if isinstance(item, Reauthentication)]
    failures = [item for item in outcomes if isinstance(item, AuthError)]

    with psycopg.connect(sync_url(database_url)) as connection:
        session_count = connection.execute(
            "SELECT count(*) FROM epok_auth.refresh_session"
        ).fetchone()[0]
        stored = connection.execute(
            "SELECT sign_count, last_used_at FROM epok_auth.passkey_credential WHERE id = %s",
            (credential.id,),
        ).fetchone()
        challenge = connection.execute(
            "SELECT family_id, consumed_at FROM epok_auth.passkey_challenge WHERE id = %s",
            (options.ceremony_id,),
        ).fetchone()
        events = connection.execute(
            "SELECT event_type FROM epok_auth.security_event "
            "WHERE event_type LIKE 'reauthentication.%' ORDER BY occurred_at"
        ).fetchall()

    assert len(successes) == 1
    assert len(failures) == 1
    assert failures[0].code is AuthErrorCode.PASSKEY_CHALLENGE_INVALID
    assert session_count == 1
    assert stored == (1, successes[0].verified_at)
    assert challenge == (session.principal.family_id, successes[0].verified_at)
    assert len(events) == 2
    assert {event[0] for event in events} == {
        SecurityEventType.REAUTHENTICATION_FAILED.value,
        SecurityEventType.REAUTHENTICATION_SUCCEEDED.value,
    }


@pytest.mark.asyncio
@pytest.mark.security
async def test_passkey_reauthentication_fails_if_session_is_revoked_during_verification(
    store: PostgresAuthStore,
    settings: AuthSettings,
    database_url: str,
) -> None:
    _, passkeys, authenticator, session, credential = await registered_passkey(store, settings)
    adapter = PausedWebAuthnAdapter(
        rp_id=RP_ID,
        rp_name=settings.effective_passkey_rp_name,
        timeout_ms=settings.passkey_timeout_ms,
    )
    passkeys.adapter = adapter
    options = await passkeys.begin_reauthentication(session.principal, ORIGIN)
    response = authenticator.authentication_response(
        challenge=decode_base64url(options.public_key["challenge"]),
        rp_id=RP_ID,
        origin=ORIGIN,
        user_id=session.principal.user_id,
        sign_count=1,
    )
    finish = asyncio.create_task(
        passkeys.finish_reauthentication(
            session.principal,
            options.ceremony_id,
            response,
            ORIGIN,
        )
    )
    try:
        started = await asyncio.to_thread(adapter.verification_started.wait, 2)
        assert started
        async with store.transaction() as transaction:
            revoked = await transaction.revoke_family(
                session.principal.family_id,
                revoked_at=passkeys.clock(),
            )
    finally:
        adapter.resume_verification.set()

    with pytest.raises(AuthError) as captured:
        await finish

    with psycopg.connect(sync_url(database_url)) as connection:
        stored = connection.execute(
            "SELECT sign_count, last_used_at FROM epok_auth.passkey_credential WHERE id = %s",
            (credential.id,),
        ).fetchone()
        challenge = connection.execute(
            "SELECT consumed_at FROM epok_auth.passkey_challenge WHERE id = %s",
            (options.ceremony_id,),
        ).fetchone()
        success_count = connection.execute(
            "SELECT count(*) FROM epok_auth.security_event "
            "WHERE event_type = 'reauthentication.succeeded'"
        ).fetchone()[0]

    assert revoked == 1
    assert captured.value.code is AuthErrorCode.INVALID_TOKEN
    assert stored == (0, None)
    assert challenge[0] is not None
    assert success_count == 0


@pytest.mark.asyncio
@pytest.mark.security
async def test_passkey_reauthentication_and_logout_share_a_safe_lock_order(
    store: PostgresAuthStore,
    settings: AuthSettings,
) -> None:
    auth, passkeys, authenticator, session, _ = await registered_passkey(store, settings)
    adapter = PausedWebAuthnAdapter(
        rp_id=RP_ID,
        rp_name=settings.effective_passkey_rp_name,
        timeout_ms=settings.passkey_timeout_ms,
    )
    passkeys.adapter = adapter
    options = await passkeys.begin_reauthentication(session.principal, ORIGIN)
    response = authenticator.authentication_response(
        challenge=decode_base64url(options.public_key["challenge"]),
        rp_id=RP_ID,
        origin=ORIGIN,
        user_id=session.principal.user_id,
        sign_count=1,
    )
    finish = asyncio.create_task(
        passkeys.finish_reauthentication(
            session.principal,
            options.ceremony_id,
            response,
            ORIGIN,
        )
    )
    started = await asyncio.to_thread(adapter.verification_started.wait, 2)
    assert started
    logout = asyncio.create_task(
        auth.logout(
            session.refresh_token,
            session.csrf_token,
            session.csrf_token,
            origin=ORIGIN,
        )
    )

    try:
        await asyncio.sleep(0.1)
        assert not logout.done()
    finally:
        adapter.resume_verification.set()

    proof, revoked = await asyncio.wait_for(
        asyncio.gather(finish, logout),
        timeout=5,
    )

    assert proof.user_id == session.principal.user_id
    assert revoked == 1
    with pytest.raises(AuthError) as captured:
        await auth.authenticate(session.access_token)
    assert captured.value.code is AuthErrorCode.INVALID_TOKEN


@pytest.mark.asyncio
async def test_reauthentication_migration_downgrades_and_upgrades_cleanly(
    database_url: str,
    settings: AuthSettings,
) -> None:
    store = PostgresAuthStore.from_url(database_url, pool_size=1)
    try:
        _, passkeys, _, session, _ = await registered_passkey(store, settings)
        await passkeys.begin_reauthentication(session.principal, ORIGIN)
    finally:
        await store.aclose()

    try:
        await asyncio.to_thread(
            downgrade_database,
            database_url,
            "0005_account_activation",
        )
        with psycopg.connect(sync_url(database_url)) as connection:
            family_column = connection.execute(
                "SELECT count(*) FROM information_schema.columns "
                "WHERE table_schema = 'epok_auth' AND table_name = 'passkey_challenge' "
                "AND column_name = 'family_id'"
            ).fetchone()[0]
            reauthentication_rows = connection.execute(
                "SELECT count(*) FROM epok_auth.passkey_challenge "
                "WHERE purpose = 'reauthentication'"
            ).fetchone()[0]
        assert family_column == 0
        assert reauthentication_rows == 0
    finally:
        await asyncio.to_thread(upgrade_database, database_url)
    await asyncio.to_thread(check_database, database_url)
