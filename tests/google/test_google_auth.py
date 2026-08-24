import json
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from google.auth.exceptions import TransportError
from google.oauth2 import id_token

from epok_auth.google.adapter import GoogleServiceUnavailableError, GoogleVerificationError
from epok_auth.google.google_auth import GoogleAuthVerifier, _verified_claims
from tests.google.fakes import CLIENT_ID


class _CertificateHandler(BaseHTTPRequestHandler):
    certificates: ClassVar[dict[str, str]] = {}
    requests: ClassVar[int] = 0

    def do_GET(self) -> None:
        type(self).requests += 1
        payload = json.dumps(type(self).certificates).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "public, max-age=3600")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, message_format: str, *args: object) -> None:
        del message_format, args


@contextmanager
def _certificate_server(certificate: str):
    _CertificateHandler.certificates = {"test-key": certificate}
    _CertificateHandler.requests = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CertificateHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/certs"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _key_and_certificate() -> tuple[rsa.RSAPrivateKey, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "epok-auth test")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    return key, pem


def _token(
    key: rsa.RSAPrivateKey,
    *,
    nonce: str,
    audience: str = CLIENT_ID,
    overrides: dict[str, object] | None = None,
) -> str:
    now = datetime.now(UTC)
    payload = {
        "iss": "https://accounts.google.com",
        "sub": "verified-google-subject",
        "aud": audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "nonce": nonce,
        "email": "verified@gmail.com",
        "email_verified": True,
        "name": "Verified Person",
    }
    if overrides:
        payload.update(overrides)
    return jwt.encode(payload, key, algorithm="RS256", headers={"kid": "test-key"})


def test_official_google_adapter_verifies_signature_claims_nonce_and_certificate_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key, certificate = _key_and_certificate()
    nonce = "nonce-with-enough-randomness"
    credential = _token(key, nonce=nonce)

    with _certificate_server(certificate) as certificates_url:
        monkeypatch.setattr(id_token, "_GOOGLE_OAUTH2_CERTS_URL", certificates_url)
        verifier = GoogleAuthVerifier(timeout_seconds=2)
        first = verifier.verify(credential, audience=CLIENT_ID, nonce=nonce)
        second = verifier.verify(credential, audience=CLIENT_ID, nonce=nonce)
        verifier.close()

    assert first == second
    assert first.subject == "verified-google-subject"
    assert first.email == "verified@gmail.com"
    assert first.email_verified is True
    assert _CertificateHandler.requests == 1


def test_official_google_adapter_rejects_wrong_audience_and_nonce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key, certificate = _key_and_certificate()
    credential = _token(key, nonce="expected-nonce", audience="other.apps.googleusercontent.com")

    with _certificate_server(certificate) as certificates_url:
        monkeypatch.setattr(id_token, "_GOOGLE_OAUTH2_CERTS_URL", certificates_url)
        verifier = GoogleAuthVerifier(timeout_seconds=2)
        with pytest.raises(GoogleVerificationError):
            verifier.verify(credential, audience=CLIENT_ID, nonce="expected-nonce")
        with pytest.raises(GoogleVerificationError):
            verifier.verify(
                _token(key, nonce="different-nonce"),
                audience=CLIENT_ID,
                nonce="expected-nonce",
            )
        with pytest.raises(GoogleVerificationError):
            verifier.verify(
                _token(
                    key,
                    nonce="expected-nonce",
                    overrides={"iss": "https://issuer.example"},
                ),
                audience=CLIENT_ID,
                nonce="expected-nonce",
            )
        verifier.close()


def test_official_google_adapter_translates_transport_failure_without_token_leak() -> None:
    verifier = GoogleAuthVerifier()
    credential = "private-google-token"

    def unavailable(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TransportError("certificate endpoint failed")

    verifier._transport = unavailable  # type: ignore[assignment]
    with pytest.raises(GoogleServiceUnavailableError) as captured:
        verifier.verify(credential, audience=CLIENT_ID, nonce="nonce")

    assert credential not in str(captured.value)


@pytest.mark.parametrize("credential", ["", "x" * 8193])
def test_official_google_adapter_bounds_credential_before_network(credential: str) -> None:
    verifier = GoogleAuthVerifier()

    with pytest.raises(GoogleVerificationError):
        verifier.verify(credential, audience=CLIENT_ID, nonce="nonce")

    verifier.close()


def test_official_google_adapter_rejects_missing_subject_and_invalid_optional_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key, certificate = _key_and_certificate()

    with _certificate_server(certificate) as certificates_url:
        monkeypatch.setattr(id_token, "_GOOGLE_OAUTH2_CERTS_URL", certificates_url)
        verifier = GoogleAuthVerifier(timeout_seconds=2)
        with pytest.raises(GoogleVerificationError):
            verifier.verify(
                _token(key, nonce="nonce", overrides={"sub": None}),
                audience=CLIENT_ID,
                nonce="nonce",
            )
        with pytest.raises(GoogleVerificationError):
            verifier.verify(
                _token(key, nonce="nonce", overrides={"email": 123}),
                audience=CLIENT_ID,
                nonce="nonce",
            )
        without_email = verifier.verify(
            _token(key, nonce="nonce", overrides={"email": None}),
            audience=CLIENT_ID,
            nonce="nonce",
        )
        verifier.close()

    assert without_email.email is None


def test_google_claim_parser_rejects_non_google_issuer() -> None:
    with pytest.raises(GoogleVerificationError):
        _verified_claims(
            {
                "iss": "https://issuer.example",
                "sub": "subject",
                "nonce": "nonce",
            },
            "nonce",
        )
