import copy
import json
import logging
import pickle

import pytest

import epok_auth
from epok_auth.errores import AppError, CodigoError, Severidad, registrar
from epok_auth.errores.catalogo import UNKNOWN_ERROR_DETAIL
from epok_auth.errores.http import STATUS_HTTP, error_response, headers_http, status_http
from epok_auth.errors import AuthError, AuthErrorCode, invalid_credentials, invalid_session


def test_public_error_imports_remain_compatible() -> None:
    assert epok_auth.AuthError is AuthError is AppError
    assert epok_auth.AuthErrorCode is AuthErrorCode is CodigoError


def test_auth_error_initializes_exception_and_aliases() -> None:
    error = AuthError(AuthErrorCode.INPUT_INVALID, "safe", severity=Severidad.WARNING)

    assert error.args == ("safe",)
    assert str(error) == "safe"
    assert error.codigo is error.code is AuthErrorCode.INPUT_INVALID
    assert error.detalle == error.detail == "safe"
    assert error.severidad is error.severity is Severidad.WARNING


def test_auth_error_defaults_severity_by_code() -> None:
    assert AuthError(AuthErrorCode.INPUT_INVALID, "safe").severity is Severidad.WARNING
    assert AuthError(AuthErrorCode.CONFIG_INVALID, "safe").severity is Severidad.ERROR
    assert AuthError(AuthErrorCode.UNKNOWN, "safe").severity is Severidad.ERROR


def test_auth_error_copies_headers_and_round_trips() -> None:
    headers = {"X-Epok-Test": "present"}
    error = AuthError(
        AuthErrorCode.CONFIG_INVALID,
        "safe",
        418,
        headers,
        Severidad.CRITICAL,
    )
    headers["Changed"] = "yes"

    for restored in (copy.copy(error), copy.deepcopy(error), pickle.loads(pickle.dumps(error))):
        assert restored is not error
        assert restored.code is AuthErrorCode.CONFIG_INVALID
        assert restored.detail == "safe"
        assert restored.status_code_override == 418
        assert restored.headers_override == {"X-Epok-Test": "present"}
        assert restored.severity is Severidad.CRITICAL


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (AuthErrorCode.INVALID_CREDENTIALS, 401),
        (AuthErrorCode.INVALID_TOKEN, 401),
        (AuthErrorCode.INVALID_CSRF, 403),
        (AuthErrorCode.INVALID_ORIGIN, 403),
        (AuthErrorCode.PASSWORD_INVALID, 422),
        (AuthErrorCode.PASSWORD_CHANGE_REQUIRED, 403),
        (AuthErrorCode.FORBIDDEN, 403),
        (AuthErrorCode.USER_NOT_FOUND, 404),
        (AuthErrorCode.USER_EXISTS, 409),
        (AuthErrorCode.ADMIN_EXISTS, 409),
        (AuthErrorCode.LAST_ADMIN_REQUIRED, 409),
        (AuthErrorCode.INPUT_INVALID, 422),
        (AuthErrorCode.REFRESH_CONFLICT, 409),
        (AuthErrorCode.CONFIG_INVALID, 500),
        (AuthErrorCode.PASSKEY_CHALLENGE_INVALID, 400),
        (AuthErrorCode.PASSKEY_REGISTRATION_INVALID, 400),
        (AuthErrorCode.PASSKEY_AUTHENTICATION_INVALID, 400),
        (AuthErrorCode.PASSKEY_EXISTS, 409),
        (AuthErrorCode.PASSKEY_NOT_FOUND, 404),
        (AuthErrorCode.PASSKEY_LIMIT_REACHED, 409),
        (AuthErrorCode.PASSKEY_NAME_INVALID, 422),
        (AuthErrorCode.UNKNOWN, 500),
    ],
)
def test_http_status_is_centralized_by_error_code(
    code: AuthErrorCode,
    expected: int,
) -> None:
    assert status_http(AuthError(code, "safe")) == expected


def test_http_catalog_covers_every_error_code() -> None:
    assert set(STATUS_HTTP) == set(AuthErrorCode)


def test_legacy_http_overrides_remain_supported() -> None:
    error = AuthError(
        AuthErrorCode.CONFIG_INVALID,
        "safe",
        418,
        {"X-Epok-Test": "present"},
    )

    assert error.status_code == 418
    assert error.headers == {"X-Epok-Test": "present"}


def test_bearer_headers_are_resolved_without_shared_mutation() -> None:
    first = headers_http(invalid_session())
    assert first is not None
    first["Changed"] = "yes"

    assert headers_http(invalid_session()) == {"WWW-Authenticate": "Bearer"}


def test_error_response_uses_safe_public_contract() -> None:
    response = error_response(invalid_credentials(), "request-1")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert json.loads(response.body) == {
        "code": AuthErrorCode.INVALID_CREDENTIALS.value,
        "detail": "The email or password is not valid.",
        "request_id": "request-1",
    }


def test_passkey_authentication_failure_is_not_an_http_auth_challenge() -> None:
    error = AuthError(AuthErrorCode.PASSKEY_AUTHENTICATION_INVALID, "safe")
    response = error_response(error, None)

    assert response.status_code == 400
    assert "www-authenticate" not in response.headers


def test_registrar_records_known_error_without_exception_repr(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="epok_auth")

    code = registrar(invalid_session(), contexto="/auth/me")

    assert code is AuthErrorCode.INVALID_TOKEN
    assert caplog.messages == ["[AUTH_TOKEN_INVALID] The session is not valid. (/auth/me)"]


def test_registrar_uses_default_warning_for_client_errors(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="epok_auth")

    registrar(AuthError(AuthErrorCode.INPUT_INVALID, "safe"))

    assert caplog.records[0].levelno == logging.WARNING


def test_registrar_redacts_unknown_error_detail(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.ERROR, logger="epok_auth")

    code = registrar(RuntimeError("private-value"))

    assert code is AuthErrorCode.UNKNOWN
    assert caplog.messages == [f"[AUTH_UNKNOWN] {UNKNOWN_ERROR_DETAIL}"]
    assert "private-value" not in caplog.text


def test_unknown_auth_error_never_exposes_detail(
    caplog: pytest.LogCaptureFixture,
) -> None:
    error = AuthError(AuthErrorCode.UNKNOWN, "private-value")
    caplog.set_level(logging.ERROR, logger="epok_auth")

    registrar(error)
    response = error_response(error, "request-1")

    assert caplog.messages == [f"[AUTH_UNKNOWN] {UNKNOWN_ERROR_DETAIL}"]
    assert json.loads(response.body)["detail"] == UNKNOWN_ERROR_DETAIL
    assert "private-value" not in caplog.text
    assert b"private-value" not in response.body
