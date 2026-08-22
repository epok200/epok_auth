from dataclasses import dataclass

import pytest

from epok_auth.errors import AuthError, AuthErrorCode
from epok_auth.passwords import PasswordManager, PasswordVerification

GOOD = "sapphire rivers protect industrial formulas"


def test_hash_and_verify_with_argon2() -> None:
    manager = PasswordManager.recommended(minimum=15, maximum=128)
    encoded = manager.hash(GOOD)
    assert encoded.startswith("$argon2")
    result = manager.verify(GOOD, encoded)
    assert result.valid is True
    assert manager.verify("wrong-password-value", encoded).valid is False


@pytest.mark.parametrize(
    "password",
    [
        "too short",
        "x" * 129,
        "123456789012345",
        "correct horse battery staple",
        "PASSWORDPASSWORD",
    ],
)
def test_rejects_invalid_or_common_passwords(password: str) -> None:
    manager = PasswordManager.recommended(minimum=15, maximum=128)
    with pytest.raises(AuthError) as captured:
        manager.hash(password)
    assert captured.value.code is AuthErrorCode.PASSWORD_INVALID
    assert captured.value.status_code == 422


def test_login_uses_dummy_hash_for_unknown_account() -> None:
    manager = PasswordManager.recommended(minimum=15, maximum=128)
    result = manager.verify_for_login(GOOD, None)
    assert result == PasswordVerification(valid=False)


@dataclass
class FakeHash:
    hash_calls: int = 0
    verify_calls: int = 0

    def hash(self, password: str) -> str:
        self.hash_calls += 1
        return f"encoded:{password}"

    def verify_and_update(self, password: str, encoded_hash: str) -> tuple[bool, str | None]:
        self.verify_calls += 1
        valid = encoded_hash == f"encoded:{password}"
        return valid, "encoded:updated" if valid else None


def test_verify_and_update_is_exposed_only_for_valid_passwords() -> None:
    fake = FakeHash()
    manager = PasswordManager.recommended(password_hash=fake)
    encoded = manager.hash(GOOD)
    result = manager.verify(GOOD, encoded)
    assert result.valid
    assert result.updated_hash == "encoded:updated"
    rejected = manager.verify("wrong-password-value", encoded)
    assert rejected.valid is False
    assert rejected.updated_hash is None


def test_very_large_login_input_is_rejected_without_expensive_hashing() -> None:
    fake = FakeHash()
    manager = PasswordManager.recommended(password_hash=fake)
    before = fake.verify_calls
    result = manager.verify_for_login("x" * 5000, None)
    assert result.valid is False
    # A bounded dummy verification is allowed, but the huge input is never hashed.
    assert fake.hash_calls == 1
    assert fake.verify_calls - before <= 1
