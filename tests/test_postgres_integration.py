from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Iterator

import pytest

psycopg = pytest.importorskip("psycopg")

from epok_auth.config import AuthSettings, Environment
from epok_auth.errors import AuthError, AuthErrorCode
from epok_auth.migrate import check_database, upgrade_database
from epok_auth.models import UserUpdate
from epok_auth.postgres import PostgresAuthStore
from epok_auth.service import AuthService

pytestmark = pytest.mark.integration

ADMIN_PASSWORD = "postgres integration protects private colors"
DATABASE_URL = os.getenv("TEST_DATABASE_URL")


def sync_url(url: str) -> str:
    return url.replace("postgresql+psycopg://", "postgresql://", 1)


@pytest.fixture(scope="session")
def database_url() -> str:
    if not DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL is required")

    # A host application such as Colors owns its own public Alembic history. The
    # package must never read, overwrite, or delete that revision state.
    with psycopg.connect(sync_url(DATABASE_URL), autocommit=True) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS public.alembic_version (
                version_num varchar(32) PRIMARY KEY
            )
            """
        )
        connection.execute("TRUNCATE public.alembic_version")
        connection.execute(
            "INSERT INTO public.alembic_version (version_num) VALUES ('host_0001')"
        )

    upgrade_database(DATABASE_URL)
    check_database(DATABASE_URL)

    with psycopg.connect(sync_url(DATABASE_URL)) as connection:
        host_revision = connection.execute(
            "SELECT version_num FROM public.alembic_version"
        ).fetchone()
        package_revision = connection.execute(
            "SELECT version_num FROM public.epok_auth_alembic_version"
        ).fetchone()
    assert host_revision == ("host_0001",)
    assert package_revision == ("0001_initial",)
    return DATABASE_URL


@pytest.fixture(autouse=True)
def reset_database(database_url: str) -> Iterator[None]:
    with psycopg.connect(sync_url(database_url), autocommit=True) as connection:
        connection.execute(
            """
            TRUNCATE epok_auth.security_event,
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
        trusted_origins=("http://localhost:3000",),
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
