from fastapi.responses import JSONResponse

from epok_auth.errores.catalogo import UNKNOWN_ERROR_DETAIL, AuthErrorCode
from epok_auth.errores.excepcion import AuthError

STATUS_HTTP = {
    AuthErrorCode.UNKNOWN: 500,
    AuthErrorCode.INVALID_CREDENTIALS: 401,
    AuthErrorCode.INVALID_TOKEN: 401,
    AuthErrorCode.INVALID_CSRF: 403,
    AuthErrorCode.INVALID_ORIGIN: 403,
    AuthErrorCode.PASSWORD_INVALID: 422,
    AuthErrorCode.PASSWORD_CHANGE_REQUIRED: 403,
    AuthErrorCode.FORBIDDEN: 403,
    AuthErrorCode.USER_NOT_FOUND: 404,
    AuthErrorCode.USER_EXISTS: 409,
    AuthErrorCode.ADMIN_EXISTS: 409,
    AuthErrorCode.LAST_ADMIN_REQUIRED: 409,
    AuthErrorCode.INPUT_INVALID: 422,
    AuthErrorCode.REFRESH_CONFLICT: 409,
    AuthErrorCode.CONFIG_INVALID: 500,
    AuthErrorCode.PASSKEY_CHALLENGE_INVALID: 400,
    AuthErrorCode.PASSKEY_REGISTRATION_INVALID: 400,
    AuthErrorCode.PASSKEY_AUTHENTICATION_INVALID: 400,
    AuthErrorCode.PASSKEY_EXISTS: 409,
    AuthErrorCode.PASSKEY_NOT_FOUND: 404,
    AuthErrorCode.PASSKEY_LIMIT_REACHED: 409,
    AuthErrorCode.PASSKEY_NAME_INVALID: 422,
    AuthErrorCode.GOOGLE_CHALLENGE_INVALID: 400,
    AuthErrorCode.GOOGLE_CREDENTIAL_INVALID: 401,
    AuthErrorCode.GOOGLE_IDENTITY_CONFLICT: 409,
    AuthErrorCode.GOOGLE_IDENTITY_NOT_FOUND: 404,
    AuthErrorCode.GOOGLE_SERVICE_UNAVAILABLE: 503,
    AuthErrorCode.EMAIL_LINK_INVALID: 400,
    AuthErrorCode.EMAIL_LINK_SESSION_EXISTS: 409,
    AuthErrorCode.EMAIL_DELIVERY_FAILED: 503,
}

HEADERS_HTTP = {
    AuthErrorCode.INVALID_CREDENTIALS: {"WWW-Authenticate": "Bearer"},
    AuthErrorCode.INVALID_TOKEN: {"WWW-Authenticate": "Bearer"},
    AuthErrorCode.GOOGLE_CREDENTIAL_INVALID: {"WWW-Authenticate": "Google-ID-Token"},
}


def status_http(error: AuthError) -> int:
    override = error.status_code_override
    if override is not None:
        return override
    return STATUS_HTTP.get(error.code, 500)


def headers_http(error: AuthError) -> dict[str, str] | None:
    override = error.headers_override
    if override is not None:
        return override
    headers = HEADERS_HTTP.get(error.code)
    return headers.copy() if headers is not None else None


def error_response(error: AuthError, request_id: str | None) -> JSONResponse:
    status = status_http(error)
    detail = error.detail
    if error.code is AuthErrorCode.UNKNOWN:
        detail = UNKNOWN_ERROR_DETAIL

    content = {
        "code": error.code.value,
        "detail": detail,
        "request_id": request_id,
    }
    return JSONResponse(
        status_code=status,
        content=content,
        headers=headers_http(error),
    )
