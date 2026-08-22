import logging

from epok_auth.errores.catalogo import UNKNOWN_ERROR_DETAIL, AuthErrorCode, Severidad
from epok_auth.errores.excepcion import AuthError

_LOG_LEVEL = {
    Severidad.INFO: logging.INFO,
    Severidad.WARNING: logging.WARNING,
    Severidad.ERROR: logging.ERROR,
    Severidad.CRITICAL: logging.CRITICAL,
}
_logger = logging.getLogger("epok_auth")


def registrar(error: Exception, contexto: str = "") -> AuthErrorCode:
    if isinstance(error, AuthError):
        code = error.code
        severity = error.severity
        detail = error.detail
    else:
        code = AuthErrorCode.UNKNOWN
        severity = Severidad.ERROR
        detail = type(error).__name__

    if code is AuthErrorCode.UNKNOWN:
        detail = UNKNOWN_ERROR_DETAIL

    context = f" ({contexto})" if contexto else ""
    _logger.log(_LOG_LEVEL[severity], "[%s] %s%s", code.value, detail, context)
    return code
