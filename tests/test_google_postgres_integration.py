import asyncio
import os
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import cast
from uuid import UUID

import pytest

psycopg = pytest.importorskip("psycopg")

from epok_auth.config import AuthSettings, Environment, GoogleAccountMode
from epok_auth.errors import AuthError, AuthErrorCode
from epok_auth.google.models import ExternalIdentity
from epok_auth.google.service import GoogleLoginService
from epok_auth.google.store import GoogleStore, GoogleTransaction
from epok_auth.migrate import check_database, upgrade_database
from epok_auth.models import RefreshSession, UserAccount
from epok_auth.postgres import PostgresAuthStore
from epok_auth.service import AuthService
from tests.google.fakes import CLIENT_ID, FakeGoogleVerifier, claims

pytestmark = pytest.mark.integration

ADMIN_PASSWORD = "Google PostgreSQL tests protect private colors"
DATABASE_URL = os.getenv("TEST_DATABASE_URL")
ORIGIN = "http://localhost:3000"


class _InterleavedGoogleTransaction:
    def __init__(
        self,
        transaction: GoogleTransaction,
        store: "_InterleavedGoogleStore",
    ) -> None:
        self.transaction = transaction
        self.store = store

    def __getattr__(self, name: str) -> object:
        return getattr(self.transaction, name)

    async def get_external_identity(
        self,
        issuer: str,
        subject: str,
        *,
        for_update: bool = False,
    ) -> ExternalIdentity | None:
        identity = await self.transaction.get_external_identity(
            issuer,
            subject,
            for_update=for_update,
        )
        task = asyncio.current_task()
        if for_update and task is not None and task.get_name() == "linked-google-login":
            self.store.identity_locked.set()
            await self.store.recovery_waiting.wait()
        return identity

    async def get_external_identity_for_user(
        self,
        user_id: UUID,
        issuer: str,
        *,
        for_update: bool = False,
    ) -> ExternalIdentity | None:
        task = asyncio.current_task()
        if for_update and task is not None and task.get_name() == "google-recovery":
            await self.store.identity_locked.wait()
            self.store.recovery_waiting.set()
        return await self.transaction.get_external_identity_for_user(
            user_id,
            issuer,
            for_update=for_update,
        )

    async def get_user_by_id(
        self,
        user_id: UUID,
        *,
        for_update: bool = False,
    ) -> UserAccount | None:
        task = asyncio.current_task()
        task_name = task.get_name() if task is not None else ""
        if for_update and task is not None and task.get_name() == "google-link-after-recovery":
            self.store.link_waiting.set()
            await self.store.recovery_finished.wait()
        if for_update and task_name == "refresh-against-link":
            self.store.refresh_user_attempted.set()
        user = await self.transaction.get_user_by_id(user_id, for_update=for_update)
        if for_update and task_name == "google-link-against-refresh":
            self.store.link_user_locked.set()
            await self.store.continue_link.wait()
        elif for_update and task_name == "refresh-against-recovery":
            self.store.refresh_user_locked.set()
            await self.store.continue_refresh.wait()
        elif for_update and task_name == "recovery-against-refresh":
            self.store.recovery_user_locked.set()
        return user

    async def get_session_by_token_hash(
        self,
        token_hash: str,
        *,
        for_update: bool = False,
    ) -> RefreshSession | None:
        session = await self.transaction.get_session_by_token_hash(
            token_hash,
            for_update=for_update,
        )
        task = asyncio.current_task()
        task_name = task.get_name() if task is not None else ""
        refresh_race = task_name in {"refresh-against-recovery", "refresh-against-link"}
        if for_update and refresh_race:
            self.store.refresh_session_locked.set()
            await self.store.continue_refresh.wait()
        return session

    async def get_session_by_id(
        self,
        session_id: UUID,
        *,
        for_update: bool = False,
    ) -> RefreshSession | None:
        task = asyncio.current_task()
        if for_update and task is not None and task.get_name() == "google-link-against-refresh":
            self.store.link_session_attempted.set()
        return await self.transaction.get_session_by_id(session_id, for_update=for_update)

    async def revoke_user_sessions(self, user_id: UUID, *, revoked_at: datetime) -> int:
        task = asyncio.current_task()
        if task is not None and task.get_name() == "recovery-against-refresh":
            self.store.recovery_revoke_attempted.set()
        return await self.transaction.revoke_user_sessions(user_id, revoked_at=revoked_at)


class _InterleavedGoogleStore:
    def __init__(self, store: PostgresAuthStore) -> None:
        self.store = store
        self.identity_locked = asyncio.Event()
        self.recovery_waiting = asyncio.Event()
        self.link_waiting = asyncio.Event()
        self.recovery_finished = asyncio.Event()
        self.refresh_session_locked = asyncio.Event()
        self.refresh_user_locked = asyncio.Event()
        self.recovery_user_locked = asyncio.Event()
        self.link_user_locked = asyncio.Event()
        self.link_session_attempted = asyncio.Event()
        self.refresh_user_attempted = asyncio.Event()
        self.recovery_revoke_attempted = asyncio.Event()
        self.continue_refresh = asyncio.Event()
        self.continue_link = asyncio.Event()

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[GoogleTransaction]:
        async with self.store.transaction() as transaction:
            proxy = _InterleavedGoogleTransaction(transaction, self)
            yield cast(GoogleTransaction, proxy)


async def _first_event(*events: asyncio.Event) -> asyncio.Event:
    waits = [asyncio.create_task(event.wait()) for event in events]
    done, pending = await asyncio.wait(waits, timeout=5, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    if not done:
        raise TimeoutError("concurrent operation did not reach the expected lock")
    completed = next(iter(done))
    return events[waits.index(completed)]


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
        jwt_secret="google-postgres-secret-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        issuer="google-postgres-tests",
        audience="google-postgres-tests-api",
        access_ttl_seconds=300,
        refresh_idle_ttl_seconds=900,
        refresh_absolute_ttl_seconds=3600,
        secure_cookies=False,
        cookie_use_host_prefix=False,
        trusted_origins=(ORIGIN,),
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


def _google(
    store: GoogleStore,
    settings: AuthSettings,
    auth: AuthService,
    verifier: FakeGoogleVerifier,
) -> GoogleLoginService:
    return GoogleLoginService(
        store=store,
        settings=settings,
        signer=auth.signer,
        verifier=verifier,
        passwords=auth.passwords,
    )


@pytest.mark.asyncio
@pytest.mark.security
async def test_google_open_login_and_recovery_are_atomic_in_postgres(
    store: PostgresAuthStore,
    settings: AuthSettings,
    database_url: str,
) -> None:
    auth = AuthService(store=store, settings=settings)
    verifier = FakeGoogleVerifier()
    google = _google(store, settings, auth, verifier)
    first, second = await asyncio.gather(
        google.begin_login(ORIGIN),
        google.begin_login(ORIGIN),
    )
    verifier.add("first-google", claims())
    verifier.add("second-google", claims())

    sessions = await asyncio.gather(
        google.finish_login(first.challenge_id, "first-google", ORIGIN),
        google.finish_login(second.challenge_id, "second-google", ORIGIN),
    )
    user_id = sessions[0].principal.user_id
    assert sessions[1].principal.user_id == user_id

    recovered = await google.recover_password_access(user_id)
    with psycopg.connect(sync_url(database_url)) as connection:
        user = connection.execute(
            """
            SELECT password_login_enabled, google_auto_link_allowed, must_change_password
            FROM epok_auth.user_account
            WHERE id = %s
            """,
            (user_id,),
        ).fetchone()
        identity_count = connection.execute(
            "SELECT count(*) FROM epok_auth.external_identity"
        ).fetchone()[0]
        active_sessions = connection.execute(
            """
            SELECT count(*)
            FROM epok_auth.refresh_session
            WHERE user_id = %s AND revoked_at IS NULL
            """,
            (user_id,),
        ).fetchone()[0]

    assert user == (True, False, True)
    assert identity_count == 0
    assert active_sessions == 0
    assert (await auth.login(recovered.user.email, recovered.temporary_password)).principal


@pytest.mark.asyncio
@pytest.mark.security
async def test_linked_login_and_recovery_use_a_deadlock_safe_lock_order(
    store: PostgresAuthStore,
    settings: AuthSettings,
    database_url: str,
) -> None:
    auth = AuthService(store=store, settings=settings)
    verifier = FakeGoogleVerifier()
    google = _google(store, settings, auth, verifier)
    first = await google.begin_login(ORIGIN)
    verifier.add("create-google", claims())
    initial = await google.finish_login(first.challenge_id, "create-google", ORIGIN)

    interleaved_store = _InterleavedGoogleStore(store)
    interleaved = _google(interleaved_store, settings, auth, verifier)
    login_options = await interleaved.begin_login(ORIGIN)
    verifier.add("linked-google", claims())
    login_task = asyncio.create_task(
        interleaved.finish_login(login_options.challenge_id, "linked-google", ORIGIN),
        name="linked-google-login",
    )
    recovery_task = asyncio.create_task(
        interleaved.recover_password_access(initial.principal.user_id),
        name="google-recovery",
    )

    login_result, recovery_result = await asyncio.wait_for(
        asyncio.gather(login_task, recovery_task, return_exceptions=True),
        timeout=10,
    )

    assert not isinstance(login_result, BaseException)
    assert not isinstance(recovery_result, BaseException)
    with psycopg.connect(sync_url(database_url)) as connection:
        identity_count = connection.execute(
            "SELECT count(*) FROM epok_auth.external_identity"
        ).fetchone()[0]
        active_sessions = connection.execute(
            """
            SELECT count(*)
            FROM epok_auth.refresh_session
            WHERE user_id = %s AND revoked_at IS NULL
            """,
            (initial.principal.user_id,),
        ).fetchone()[0]

    assert identity_count == 0
    assert active_sessions == 0
    assert (
        await auth.login(recovery_result.user.email, recovery_result.temporary_password)
    ).principal


@pytest.mark.asyncio
@pytest.mark.security
async def test_recovery_wins_against_an_in_flight_relink(
    store: PostgresAuthStore,
    settings: AuthSettings,
    database_url: str,
) -> None:
    auth = AuthService(store=store, settings=settings)
    verifier = FakeGoogleVerifier()
    google = _google(store, settings, auth, verifier)
    admin = await auth.create_admin(
        email="admin@example.com",
        display_name="Admin",
        password=ADMIN_PASSWORD,
    )
    session = await auth.login(admin.email, ADMIN_PASSWORD)
    first = await google.begin_link(session.principal, ORIGIN)
    verifier.add("first-link", claims())
    await google.finish_link(session.principal, first.challenge_id, "first-link", ORIGIN)

    interleaved_store = _InterleavedGoogleStore(store)
    interleaved = _google(interleaved_store, settings, auth, verifier)
    second = await interleaved.begin_link(session.principal, ORIGIN)
    verifier.add("second-link", claims())
    link_task = asyncio.create_task(
        interleaved.finish_link(
            session.principal,
            second.challenge_id,
            "second-link",
            ORIGIN,
        ),
        name="google-link-after-recovery",
    )
    await asyncio.wait_for(interleaved_store.link_waiting.wait(), timeout=5)
    try:
        recovered = await google.recover_password_access(admin.id)
    finally:
        interleaved_store.recovery_finished.set()

    with pytest.raises(AuthError) as captured:
        await asyncio.wait_for(link_task, timeout=5)

    assert captured.value.code is AuthErrorCode.INVALID_TOKEN
    with psycopg.connect(sync_url(database_url)) as connection:
        identity_count = connection.execute(
            "SELECT count(*) FROM epok_auth.external_identity"
        ).fetchone()[0]
        active_sessions = connection.execute(
            """
            SELECT count(*)
            FROM epok_auth.refresh_session
            WHERE user_id = %s AND revoked_at IS NULL
            """,
            (admin.id,),
        ).fetchone()[0]

    assert identity_count == 0
    assert active_sessions == 0
    assert (await auth.login(admin.email, recovered.temporary_password)).principal


@pytest.mark.asyncio
@pytest.mark.security
async def test_recovery_and_refresh_share_a_deadlock_safe_lock_order(
    store: PostgresAuthStore,
    settings: AuthSettings,
    database_url: str,
) -> None:
    auth = AuthService(store=store, settings=settings)
    verifier = FakeGoogleVerifier()
    google = _google(store, settings, auth, verifier)
    options = await google.begin_login(ORIGIN)
    verifier.add("recovery-refresh", claims())
    initial = await google.finish_login(
        options.challenge_id,
        "recovery-refresh",
        ORIGIN,
    )

    interleaved_store = _InterleavedGoogleStore(store)
    interleaved_auth = AuthService(store=interleaved_store, settings=settings)
    interleaved_google = _google(
        interleaved_store,
        settings,
        interleaved_auth,
        verifier,
    )
    refresh_task = asyncio.create_task(
        interleaved_auth.refresh(
            initial.refresh_token,
            initial.csrf_token,
            initial.csrf_token,
            origin=ORIGIN,
        ),
        name="refresh-against-recovery",
    )
    first_lock = await _first_event(
        interleaved_store.refresh_session_locked,
        interleaved_store.refresh_user_locked,
    )
    recovery_task = asyncio.create_task(
        interleaved_google.recover_password_access(initial.principal.user_id),
        name="recovery-against-refresh",
    )

    if first_lock is interleaved_store.refresh_session_locked:
        await asyncio.wait_for(interleaved_store.recovery_user_locked.wait(), timeout=5)
        await asyncio.wait_for(interleaved_store.recovery_revoke_attempted.wait(), timeout=5)
    interleaved_store.continue_refresh.set()

    refresh_result, recovery_result = await asyncio.wait_for(
        asyncio.gather(refresh_task, recovery_task, return_exceptions=True),
        timeout=10,
    )

    assert not isinstance(refresh_result, BaseException)
    assert not isinstance(recovery_result, BaseException)
    with psycopg.connect(sync_url(database_url)) as connection:
        identity_count = connection.execute(
            "SELECT count(*) FROM epok_auth.external_identity"
        ).fetchone()[0]
        active_sessions = connection.execute(
            """
            SELECT count(*)
            FROM epok_auth.refresh_session
            WHERE user_id = %s AND revoked_at IS NULL
            """,
            (initial.principal.user_id,),
        ).fetchone()[0]

    assert identity_count == 0
    assert active_sessions == 0
    assert (
        await auth.login(recovery_result.user.email, recovery_result.temporary_password)
    ).principal


@pytest.mark.asyncio
@pytest.mark.security
async def test_link_and_refresh_share_a_deadlock_safe_lock_order(
    store: PostgresAuthStore,
    settings: AuthSettings,
    database_url: str,
) -> None:
    auth = AuthService(store=store, settings=settings)
    verifier = FakeGoogleVerifier()
    google = _google(store, settings, auth, verifier)
    admin = await auth.create_admin(
        email="admin@example.com",
        display_name="Admin",
        password=ADMIN_PASSWORD,
    )
    initial = await auth.login(admin.email, ADMIN_PASSWORD)
    first = await google.begin_link(initial.principal, ORIGIN)
    verifier.add("initial-link", claims())
    await google.finish_link(initial.principal, first.challenge_id, "initial-link", ORIGIN)

    interleaved_store = _InterleavedGoogleStore(store)
    interleaved_auth = AuthService(store=interleaved_store, settings=settings)
    interleaved_google = _google(
        interleaved_store,
        settings,
        interleaved_auth,
        verifier,
    )
    second = await interleaved_google.begin_link(initial.principal, ORIGIN)
    verifier.add("repeated-link", claims())
    link_task = asyncio.create_task(
        interleaved_google.finish_link(
            initial.principal,
            second.challenge_id,
            "repeated-link",
            ORIGIN,
        ),
        name="google-link-against-refresh",
    )
    await asyncio.wait_for(interleaved_store.link_user_locked.wait(), timeout=5)
    refresh_task = asyncio.create_task(
        interleaved_auth.refresh(
            initial.refresh_token,
            initial.csrf_token,
            initial.csrf_token,
            origin=ORIGIN,
        ),
        name="refresh-against-link",
    )
    first_lock = await _first_event(
        interleaved_store.refresh_session_locked,
        interleaved_store.refresh_user_attempted,
    )

    interleaved_store.continue_link.set()
    if first_lock is interleaved_store.refresh_session_locked:
        await asyncio.wait_for(interleaved_store.link_session_attempted.wait(), timeout=5)
        interleaved_store.continue_refresh.set()

    link_result, refresh_result = await asyncio.wait_for(
        asyncio.gather(link_task, refresh_task, return_exceptions=True),
        timeout=10,
    )

    assert not isinstance(link_result, BaseException)
    assert not isinstance(refresh_result, BaseException)
    assert (await auth.authenticate(refresh_result.access_token)).user_id == admin.id
    with psycopg.connect(sync_url(database_url)) as connection:
        identity_count = connection.execute(
            "SELECT count(*) FROM epok_auth.external_identity"
        ).fetchone()[0]
    assert identity_count == 1
