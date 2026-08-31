import asyncio
import os
from collections.abc import AsyncIterator, Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import pytest

from epok_auth.config import AuthSettings, Environment
from epok_auth.email_links.activation import AccountActivationService
from epok_auth.email_links.mailer import EmailLinkMailer
from epok_auth.email_links.models import AuthEmail, EmailLinkState
from epok_auth.email_links.service import EmailLinkService
from epok_auth.errors import AuthError, AuthErrorCode
from epok_auth.migrate import check_database, downgrade_database, upgrade_database
from epok_auth.models import UserStatus
from epok_auth.postgres import PostgresAuthStore
from epok_auth.service import AuthService
from epok_auth.store import StoreConflictError

psycopg = pytest.importorskip("psycopg")

pytestmark = pytest.mark.integration

DATABASE_URL = os.getenv("TEST_DATABASE_URL")
ORIGIN = "http://localhost:3000"
FIRST_PASSWORD = "postgres activation protects private colors"


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
            TRUNCATE epok_auth.email_link,
                     epok_auth.security_event,
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
        jwt_secret="postgres-email-link-test-secret-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        issuer="postgres-email-link-tests",
        audience="postgres-email-link-tests-api",
        access_ttl_seconds=300,
        refresh_idle_ttl_seconds=900,
        refresh_absolute_ttl_seconds=3600,
        secure_cookies=False,
        cookie_use_host_prefix=False,
        trusted_origins=(ORIGIN,),
        email_link_login_url=f"{ORIGIN}/login",
        email_link_password_reset_url=f"{ORIGIN}/reset-password",
        email_link_invitation_url=f"{ORIGIN}/invitation",
        email_link_activation_url=f"{ORIGIN}/activation",
    )


@pytest.fixture
async def store(database_url: str) -> AsyncIterator[PostgresAuthStore]:
    value = PostgresAuthStore.from_url(database_url, pool_size=1, max_overflow=4)
    try:
        yield value
    finally:
        await value.aclose()


class CapturingSender:
    def __init__(self) -> None:
        self.emails: list[AuthEmail] = []

    async def send(self, email: AuthEmail) -> None:
        self.emails.append(email)


class FailingSender:
    async def send(self, email: AuthEmail) -> None:
        raise RuntimeError(f"provider rejected {email.action_url}")


def token_from(email: AuthEmail) -> str:
    assert email.action_url is not None
    return parse_qs(urlsplit(email.action_url).fragment)["token"][0]


@pytest.mark.asyncio
async def test_postgres_email_links_are_transactional_and_single_use(
    store: PostgresAuthStore,
    settings: AuthSettings,
    database_url: str,
) -> None:
    auth = AuthService(store=store, settings=settings)
    provisioned = await auth.create_user(email="magic@example.com", display_name="Magic")
    user = replace(
        provisioned.user,
        must_change_password=False,
        email_link_login_enabled=True,
    )
    async with store.transaction() as transaction:
        await transaction.update_user(user)

    links = EmailLinkService(
        store=store,
        settings=settings,
        signer=auth.signer,
        passwords=auth.passwords,
        clock=auth.clock,
    )
    sender = CapturingSender()
    issue = await links.request_login(user.email)
    assert issue.pending is not None and issue.browser_nonce is not None
    assert await EmailLinkMailer(links, sender).deliver(issue.pending) is True

    action_url = sender.emails[-1].action_url
    assert action_url is not None
    token = parse_qs(urlsplit(action_url).fragment)["token"][0]
    with psycopg.connect(sync_url(database_url)) as connection:
        stored_hashes = connection.execute(
            """
            SELECT token_hash, recipient_hash, browser_hash
            FROM epok_auth.email_link
            WHERE id = %s
            """,
            (issue.pending.link_id,),
        ).fetchone()
    assert stored_hashes is not None
    assert all(len(value) == 64 for value in stored_hashes)
    assert token not in str(stored_hashes)
    bundle = await links.login(token, issue.browser_nonce)
    assert bundle.principal.user_id == user.id

    async with store.transaction() as transaction:
        stored = await transaction.get_email_link(issue.pending.link_id)
        assert stored is not None
        assert stored.state is EmailLinkState.CONSUMED
    with pytest.raises(StoreConflictError):
        async with store.transaction() as transaction:
            await transaction.insert_email_link(stored)
    with pytest.raises(AuthError) as replay:
        await links.login(token, issue.browser_nonce)
    assert replay.value.code is AuthErrorCode.EMAIL_LINK_INVALID

    failed_issue = await links.request_login(user.email)
    assert failed_issue.pending is not None
    with pytest.raises(AuthError) as failed_delivery:
        await EmailLinkMailer(links, FailingSender()).deliver(failed_issue.pending)
    assert failed_delivery.value.code is AuthErrorCode.EMAIL_DELIVERY_FAILED
    assert token not in str(failed_delivery.value)
    async with store.transaction() as transaction:
        failed = await transaction.get_email_link(failed_issue.pending.link_id)
        assert failed is not None
        assert failed.state is EmailLinkState.FAILED

    fenced_issue = await links.request_login(user.email)
    assert fenced_issue.pending is not None
    async with store.transaction() as transaction:
        current = await transaction.get_user_by_id(user.id, for_update=True)
        assert current is not None
        await transaction.update_user(
            replace(current, security_version=current.security_version + 1)
        )
    assert await links.mark_delivered(fenced_issue.pending.link_id) is False


def test_email_link_migration_downgrades_and_upgrades_cleanly(database_url: str) -> None:
    try:
        downgrade_database(database_url, "0003_google_identity")
        with psycopg.connect(sync_url(database_url)) as connection:
            table = connection.execute("SELECT to_regclass('epok_auth.email_link')").fetchone()[0]
            columns = connection.execute(
                """
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'epok_auth'
                  AND table_name = 'user_account'
                  AND column_name IN ('email_link_login_enabled', 'security_version')
                """
            ).fetchall()
        assert table is None
        assert columns == []
    finally:
        upgrade_database(database_url)
    check_database(database_url)


def test_account_activation_migration_downgrade_fails_closed(database_url: str) -> None:
    user_id = uuid4()
    now = datetime.now(UTC)
    try:
        with psycopg.connect(sync_url(database_url)) as connection:
            connection.execute(
                """
                INSERT INTO epok_auth.user_account (
                    id, email, display_name, password_hash, status, roles, scopes
                ) VALUES (
                    %s, 'pending@example.com', 'Pending', 'unusable',
                    'pending_activation', '["user"]'::jsonb, '[]'::jsonb
                )
                """,
                (user_id,),
            )
            connection.execute(
                """
                INSERT INTO epok_auth.email_link (
                    id, user_id, purpose, generation, token_hash, recipient_hash,
                    browser_hash, security_version, state, created_at, expires_at
                ) VALUES (
                    %s, %s, 'activation', 1, %s, %s, NULL, 0, 'pending', %s, %s
                )
                """,
                (uuid4(), user_id, "a" * 64, "b" * 64, now, now + timedelta(hours=1)),
            )

        downgrade_database(database_url, "0004_email_links")

        with psycopg.connect(sync_url(database_url)) as connection:
            status = connection.execute(
                "SELECT status FROM epok_auth.user_account WHERE id = %s",
                (user_id,),
            ).fetchone()[0]
            links = connection.execute(
                "SELECT count(*) FROM epok_auth.email_link WHERE user_id = %s",
                (user_id,),
            ).fetchone()[0]
        assert status == "disabled"
        assert links == 0
    finally:
        upgrade_database(database_url)
    check_database(database_url)


@pytest.mark.asyncio
async def test_concurrent_initial_admin_activation_creates_one_account_and_link(
    store: PostgresAuthStore,
    settings: AuthSettings,
    database_url: str,
) -> None:
    auth = AuthService(store=store, settings=settings)
    activation = AccountActivationService(
        store=store,
        settings=settings,
        passwords=auth.passwords,
        clock=auth.clock,
    )

    async def bootstrap():
        return await activation.ensure_initial_admin(
            email="owner@example.com",
            display_name="Owner",
        )

    results = await asyncio.gather(bootstrap(), bootstrap())
    created = next(result for result in results if result.pending is not None)
    existing = next(result for result in results if result.pending is None)

    with psycopg.connect(sync_url(database_url)) as connection:
        users = connection.execute(
            "SELECT count(*) FROM epok_auth.user_account WHERE roles @> '[\"admin\"]'::jsonb"
        ).fetchone()[0]
        links = connection.execute(
            "SELECT count(*) FROM epok_auth.email_link WHERE purpose = 'activation'"
        ).fetchone()[0]
    assert created.user.id == existing.user.id
    assert users == 1
    assert links == 1

    assert created.pending is not None
    email_links = EmailLinkService(
        store=store,
        settings=settings,
        signer=auth.signer,
        passwords=auth.passwords,
        clock=auth.clock,
    )
    await EmailLinkMailer(email_links, CapturingSender()).deliver(created.pending)
    activated = await activation.activate(token_from(created.pending.email), FIRST_PASSWORD)
    assert activated.status is UserStatus.ACTIVE


@pytest.mark.asyncio
async def test_concurrent_email_link_consumption_creates_one_session(
    store: PostgresAuthStore,
    settings: AuthSettings,
    database_url: str,
) -> None:
    auth = AuthService(store=store, settings=settings)
    provisioned = await auth.create_user(email="race@example.com", display_name="Race")
    user = replace(
        provisioned.user,
        must_change_password=False,
        email_link_login_enabled=True,
    )
    async with store.transaction() as transaction:
        await transaction.update_user(user)
    links = EmailLinkService(
        store=store,
        settings=settings,
        signer=auth.signer,
        passwords=auth.passwords,
        clock=auth.clock,
    )
    sender = CapturingSender()
    issue = await links.request_login(user.email)
    assert issue.pending is not None and issue.browser_nonce is not None
    await EmailLinkMailer(links, sender).deliver(issue.pending)
    token = parse_qs(urlsplit(sender.emails[-1].action_url or "").fragment)["token"][0]

    async def consume() -> str:
        try:
            bundle = await links.login(token, issue.browser_nonce or "")
        except AuthError as error:
            return error.code.value
        return str(bundle.principal.session_id)

    outcomes = await asyncio.gather(consume(), consume())
    assert outcomes.count(AuthErrorCode.EMAIL_LINK_INVALID.value) == 1
    assert len(set(outcomes)) == 2

    with psycopg.connect(sync_url(database_url)) as connection:
        sessions = connection.execute(
            "SELECT count(*) FROM epok_auth.refresh_session WHERE user_id = %s",
            (user.id,),
        ).fetchone()[0]
    assert sessions == 1
