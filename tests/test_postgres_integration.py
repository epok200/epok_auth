import asyncio
import os
from collections.abc import AsyncIterator, Iterator

import pytest

psycopg = pytest.importorskip("psycopg")

from epok_auth.config import AuthSettings, Environment, GoogleAccountMode
from epok_auth.errors import AuthError, AuthErrorCode
from epok_auth.migrate import check_database, downgrade_database, upgrade_database
from epok_auth.models import UserUpdate
from epok_auth.passkeys.service import PasskeyService
from epok_auth.passkeys.webauthn import WebAuthnAdapter
from epok_auth.postgres import PostgresAuthStore
from epok_auth.service import AuthService
from tests.google.fakes import CLIENT_ID
from tests.passkeys.virtual_authenticator import VirtualAuthenticator, decode_base64url

pytestmark = pytest.mark.integration

ADMIN_PASSWORD = "postgres integration protects private colors"
DATABASE_URL = os.getenv("TEST_DATABASE_URL")
ORIGIN = "http://localhost:3000"
RP_ID = "localhost"


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
        connection.execute(
            """
            TRUNCATE epok_auth.security_event,
                     epok_auth.google_challenge,
                     epok_auth.external_identity,
                     epok_auth.passkey_challenge,
                     epok_auth.passkey_credential,
                     epok_auth.refresh_session,
                     epok_auth.user_account
            RESTART IDENTITY CASCADE
            """
        )
    yield


@pytest.fixture
def settings(database_url: str) -> AuthSettings:
    return AuthSettings(
        environment=Environment.TEST,
        database_url=database_url,
        jwt_secret="postgres-test-secret-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        issuer="postgres-tests",
        audience="postgres-tests-api",
        access_ttl_seconds=300,
        refresh_idle_ttl_seconds=900,
        refresh_absolute_ttl_seconds=3600,
        login_max_attempts=3,
        lockout_seconds=60,
        secure_cookies=False,
        cookie_use_host_prefix=False,
        trusted_origins=(ORIGIN,),
        passkey_rp_id=RP_ID,
        passkey_rp_name="EPOK PostgreSQL tests",
        google_client_id=CLIENT_ID,
        google_account_mode=GoogleAccountMode.OPEN,
    )


@pytest.fixture
async def store(database_url: str) -> AsyncIterator[PostgresAuthStore]:
    value = PostgresAuthStore.from_url(database_url, pool_size=1, max_overflow=4)
    try:
        yield value
    finally:
        await value.aclose()


@pytest.mark.asyncio
async def test_postgres_adapter_supports_complete_user_and_session_flow(
    store: PostgresAuthStore,
    settings: AuthSettings,
    database_url: str,
) -> None:
    service = AuthService(store=store, settings=settings)
    admin = await service.create_admin(
        email="admin@example.com",
        display_name="Admin",
        password=ADMIN_PASSWORD,
    )
    provisioned = await service.create_user(
        email="editor@example.com",
        display_name="Editor",
        roles=("editor",),
        scopes=("catalog:read", "catalog:write"),
    )
    assert {item.id for item in await service.list_users()} == {admin.id, provisioned.user.id}

    first = await service.login("admin@example.com", ADMIN_PASSWORD)
    assert (await service.authenticate(first.access_token)).user_id == admin.id
    second = await service.refresh(
        first.refresh_token,
        first.csrf_token,
        first.csrf_token,
        origin="http://localhost:3000",
    )
    assert second.principal.family_id == first.principal.family_id

    changed = await service.update_user(
        provisioned.user.id,
        UserUpdate(display_name="Senior Editor", scopes=("catalog:read",)),
    )
    assert changed.display_name == "Senior Editor"
    assert changed.scopes == ("catalog:read",)

    reset = await service.reset_password(provisioned.user.id)
    assert reset.user.must_change_password
    assert await service.revoke_user_sessions(admin.id) >= 1

    with psycopg.connect(sync_url(database_url)) as connection:
        user_count = connection.execute("SELECT count(*) FROM epok_auth.user_account").fetchone()[0]
        session_count = connection.execute(
            "SELECT count(*) FROM epok_auth.refresh_session"
        ).fetchone()[0]
        event_count = connection.execute(
            "SELECT count(*) FROM epok_auth.security_event"
        ).fetchone()[0]
    assert user_count == 2
    assert session_count >= 2
    assert event_count >= 8


@pytest.mark.asyncio
async def test_duplicate_user_conflict_rolls_back_transaction(
    store: PostgresAuthStore,
    settings: AuthSettings,
) -> None:
    service = AuthService(store=store, settings=settings)
    await service.create_user(email="duplicate@example.com", display_name="Original")
    with pytest.raises(AuthError) as captured:
        await service.create_user(email="duplicate@example.com", display_name="Duplicate")
    assert captured.value.code is AuthErrorCode.USER_EXISTS
    users = await service.list_users()
    assert len(users) == 1
    assert users[0].display_name == "Original"


@pytest.mark.asyncio
async def test_concurrent_refresh_reuse_detection_is_serialized_by_postgres(
    store: PostgresAuthStore,
    settings: AuthSettings,
) -> None:
    service = AuthService(store=store, settings=settings)
    await service.create_admin(
        email="admin@example.com",
        display_name="Admin",
        password=ADMIN_PASSWORD,
    )
    first = await service.login("admin@example.com", ADMIN_PASSWORD)

    async def rotate() -> object:
        try:
            return await service.refresh(
                first.refresh_token,
                first.csrf_token,
                first.csrf_token,
                origin="http://localhost:3000",
            )
        except AuthError as error:
            return error

    outcomes = await asyncio.gather(rotate(), rotate())
    success = [item for item in outcomes if not isinstance(item, AuthError)]
    failure = [item for item in outcomes if isinstance(item, AuthError)]
    assert len(success) == 1
    assert len(failure) == 1
    assert failure[0].code is AuthErrorCode.INVALID_TOKEN
    with pytest.raises(AuthError):
        await service.authenticate(success[0].access_token)


@pytest.mark.asyncio
async def test_initial_admin_creation_is_serialized_across_connections(
    database_url: str,
    settings: AuthSettings,
) -> None:
    first_store = PostgresAuthStore.from_url(database_url, pool_size=1)
    second_store = PostgresAuthStore.from_url(database_url, pool_size=1)
    first = AuthService(store=first_store, settings=settings)
    second = AuthService(store=second_store, settings=settings)

    async def create(service: AuthService, email: str) -> str:
        try:
            await service.create_admin(
                email=email,
                display_name=email,
                password=ADMIN_PASSWORD,
            )
        except AuthError as error:
            return error.code.value
        return "created"

    try:
        outcomes = await asyncio.gather(
            create(first, "one@example.com"),
            create(second, "two@example.com"),
        )
    finally:
        await first_store.aclose()
        await second_store.aclose()

    assert outcomes.count("created") == 1
    assert outcomes.count(AuthErrorCode.ADMIN_EXISTS.value) == 1


@pytest.mark.asyncio
@pytest.mark.security
async def test_passkey_flow_is_persisted_and_challenge_use_is_atomic(
    store: PostgresAuthStore,
    settings: AuthSettings,
    database_url: str,
) -> None:
    auth = AuthService(store=store, settings=settings)
    user = await auth.create_admin(
        email="passkey@example.com",
        display_name="Passkey Admin",
        password=ADMIN_PASSWORD,
    )
    password_session = await auth.login(user.email, ADMIN_PASSWORD)
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

    registration = await passkeys.begin_registration(password_session.principal, ORIGIN)
    registration_response = authenticator.registration_response(
        challenge=decode_base64url(registration.public_key["challenge"]),
        rp_id=RP_ID,
        origin=ORIGIN,
    )
    credential = await passkeys.finish_registration(
        password_session.principal,
        registration.ceremony_id,
        "PostgreSQL platform passkey",
        registration_response,
        ORIGIN,
    )

    authentication = await passkeys.begin_authentication(ORIGIN)
    authentication_response = authenticator.authentication_response(
        challenge=decode_base64url(authentication.public_key["challenge"]),
        rp_id=RP_ID,
        origin=ORIGIN,
        user_id=user.id,
        sign_count=1,
    )

    async def authenticate(ceremony_id, response) -> object:
        try:
            return await passkeys.finish_authentication(
                ceremony_id,
                response,
                ORIGIN,
            )
        except AuthError as error:
            return error

    outcomes = await asyncio.gather(
        authenticate(authentication.ceremony_id, authentication_response),
        authenticate(authentication.ceremony_id, authentication_response),
    )
    success = [item for item in outcomes if not isinstance(item, AuthError)]
    failure = [item for item in outcomes if isinstance(item, AuthError)]

    assert len(success) == 1
    assert len(failure) == 1
    assert failure[0].code is AuthErrorCode.PASSKEY_CHALLENGE_INVALID
    assert (await auth.authenticate(success[0].access_token)).user_id == user.id

    first_counter = await passkeys.begin_authentication(ORIGIN)
    second_counter = await passkeys.begin_authentication(ORIGIN)
    first_response = authenticator.authentication_response(
        challenge=decode_base64url(first_counter.public_key["challenge"]),
        rp_id=RP_ID,
        origin=ORIGIN,
        user_id=user.id,
        sign_count=2,
    )
    second_response = authenticator.authentication_response(
        challenge=decode_base64url(second_counter.public_key["challenge"]),
        rp_id=RP_ID,
        origin=ORIGIN,
        user_id=user.id,
        sign_count=2,
    )
    counter_outcomes = await asyncio.gather(
        authenticate(first_counter.ceremony_id, first_response),
        authenticate(second_counter.ceremony_id, second_response),
    )
    counter_success = [item for item in counter_outcomes if not isinstance(item, AuthError)]
    counter_failure = [item for item in counter_outcomes if isinstance(item, AuthError)]

    assert len(counter_success) == 1
    assert len(counter_failure) == 1
    assert counter_failure[0].code is AuthErrorCode.PASSKEY_AUTHENTICATION_INVALID

    with psycopg.connect(sync_url(database_url)) as connection:
        stored = connection.execute(
            """
            SELECT sign_count, last_used_at, revoked_at
            FROM epok_auth.passkey_credential
            WHERE id = %s
            """,
            (credential.id,),
        ).fetchone()
        consumed = connection.execute(
            """
            SELECT count(*)
            FROM epok_auth.passkey_challenge
            WHERE id = %s AND consumed_at IS NOT NULL
            """,
            (authentication.ceremony_id,),
        ).fetchone()[0]

    assert stored[0] == 2
    assert stored[1] is not None
    assert stored[2] is None
    assert consumed == 1

    with (
        psycopg.connect(sync_url(database_url), autocommit=True) as connection,
        pytest.raises(psycopg.errors.CheckViolation),
    ):
        connection.execute(
            """
            UPDATE epok_auth.passkey_credential
            SET device_type = 'single_device', backed_up = true
            WHERE id = %s
            """,
            (credential.id,),
        )


def test_passkey_migration_downgrades_and_upgrades_cleanly(database_url: str) -> None:
    try:
        downgrade_database(database_url, "0001_initial")
        with psycopg.connect(sync_url(database_url)) as connection:
            credential_table = connection.execute(
                "SELECT to_regclass('epok_auth.passkey_credential')"
            ).fetchone()[0]
            challenge_table = connection.execute(
                "SELECT to_regclass('epok_auth.passkey_challenge')"
            ).fetchone()[0]
        assert credential_table is None
        assert challenge_table is None
    finally:
        upgrade_database(database_url)
    check_database(database_url)


def test_google_migration_downgrades_and_upgrades_cleanly(database_url: str) -> None:
    try:
        downgrade_database(database_url, "0002_passkeys")
        with psycopg.connect(sync_url(database_url)) as connection:
            identity_table = connection.execute(
                "SELECT to_regclass('epok_auth.external_identity')"
            ).fetchone()[0]
            challenge_table = connection.execute(
                "SELECT to_regclass('epok_auth.google_challenge')"
            ).fetchone()[0]
            columns = connection.execute(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'epok_auth'
                  AND table_name = 'user_account'
                  AND column_name IN ('password_login_enabled', 'google_auto_link_allowed')
                """
            ).fetchall()
        assert identity_table is None
        assert challenge_table is None
        assert columns == []
    finally:
        upgrade_database(database_url)
    check_database(database_url)
