from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from epok_auth.config import AuthSettings, Environment
from epok_auth.service import AuthService
from epok_auth.testing import MemoryAuthStore

ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "violet rivers protect private colors"
NEW_PASSWORD = "amber galaxies protect private formulas"
USER_EMAIL = "analyst@example.com"


@dataclass(slots=True)
class MutableClock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value

    def advance(self, **delta: int) -> None:
        self.value += timedelta(**delta)


@pytest.fixture
def clock() -> MutableClock:
    return MutableClock(datetime(2026, 8, 4, 12, 0, tzinfo=UTC))


@pytest.fixture
def settings() -> AuthSettings:
    return AuthSettings(
        environment=Environment.TEST,
        jwt_secret="test-secret-with-high-entropy-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        issuer="epok-auth-tests",
        audience="epok-auth-tests-api",
        access_ttl_seconds=300,
        refresh_idle_ttl_seconds=900,
        refresh_absolute_ttl_seconds=3600,
        login_max_attempts=3,
        lockout_seconds=120,
        password_min_length=15,
        password_max_length=128,
        secure_cookies=False,
        cookie_use_host_prefix=False,
        trusted_origins=("http://localhost:3000",),
    )


@pytest.fixture
def store() -> MemoryAuthStore:
    return MemoryAuthStore()


@pytest.fixture
def service(
    store: MemoryAuthStore,
    settings: AuthSettings,
    clock: MutableClock,
) -> AuthService:
    return AuthService(store=store, settings=settings, clock=clock)
