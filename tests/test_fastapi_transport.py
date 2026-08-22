from fastapi import Request, Response

from epok_auth.fastapi.transport import AuthHttpTransport


def test_http_transport_extracts_request_context_and_disables_cache() -> None:
    request = Request(
        {
            "type": "http",
            "headers": [
                (b"x-request-id", b"header-request"),
                (b"user-agent", b"test-client"),
            ],
            "client": ("203.0.113.10", 443),
            "state": {"request_id": "state-request"},
        }
    )
    response = Response()

    context = AuthHttpTransport.request_context(request)
    AuthHttpTransport.disable_cache(response)

    assert context.request_id == "state-request"
    assert context.ip_address == "203.0.113.10"
    assert context.user_agent == "test-client"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
