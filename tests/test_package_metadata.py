from importlib.metadata import version

import epok_auth
from epok_auth.fastapi import (
    AuthHttpTransport,
    ChangePasswordRequest,
    LoginRequest,
    PrincipalResponse,
    SessionResponse,
)


def test_runtime_version_matches_distribution_metadata() -> None:
    assert epok_auth.__version__ == version("epok-auth")


def test_product_router_contracts_are_public() -> None:
    assert AuthHttpTransport.__module__ == "epok_auth.fastapi.transport"
    assert LoginRequest.__module__ == "epok_auth.fastapi.schemas"
    assert ChangePasswordRequest.__module__ == "epok_auth.fastapi.schemas"
    assert PrincipalResponse.__module__ == "epok_auth.fastapi.schemas"
    assert SessionResponse.__module__ == "epok_auth.fastapi.schemas"
