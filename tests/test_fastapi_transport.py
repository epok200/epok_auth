from datetime import UTC, datetime
from uuid import uuid4

from fastapi import Request, Response

from epok_auth.fastapi import AuthHttpTransport
from epok_auth.models import SecurityEvent, SecurityEventType


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


def test_http_transport_normalizes_uuid_for_security_events() -> None:
    request_id = uuid4()
    request = Request(
        {
            "type": "http",
            "headers": [],
            "state": {"request_id": request_id},
        }
    )

    context = AuthHttpTransport.request_context(request)
    event = SecurityEvent.from_request(
        SecurityEventType.LOGIN_SUCCEEDED,
        datetime.now(UTC),
        context=context,
    )

    assert context.request_id == str(request_id)
    assert event.request_id == str(request_id)


def test_http_transport_falls_back_to_header_for_empty_state() -> None:
    request = Request(
        {
            "type": "http",
            "headers": [(b"x-request-id", b"header-request")],
            "state": {"request_id": ""},
        }
    )

    context = AuthHttpTransport.request_context(request)

    assert context.request_id == "header-request"
