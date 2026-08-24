# Security assurance manifest

This document maps beta capabilities to executable evidence. It is not a claim that vulnerabilities are impossible.

## 0.4.0 validation snapshot

The current Magic Link branch was validated locally on 2026-08-24 with:

- 374 Python tests, including 25 cases against PostgreSQL 17;
- 98.40% branch-aware coverage across the complete package;
- 42 focused email-link tests with 100% statement and branch coverage;
- a real Chromium flow covering fragment cleanup, browser binding and session cookies;
- Ruff, Pyright strict, `pip-audit` and the Magic Link npm audit passing;
- wheel and source distribution allowlists with no tests, docs, examples or environment files;
- isolated Python 3.12 installation of wheel and sdist for the base package, CLI and all extras.

Python 3.13, Python 3.14, CodeQL and clean-runner CI remain release-gate evidence, not claims of
this local snapshot.

## Release evidence snapshot

The `0.3.0` release was accepted by the standalone library gate after all of the
following completed successfully on a clean GitHub runner:

- 321 tests pass with disposable PostgreSQL, including migration and concurrency cases;
- the passkey and Google browser reference clients pass their real Chromium flows;
- branch-aware coverage reaches 98.16%;
- 299 non-integration tests pass on Python 3.12, 3.13 and 3.14;
- PostgreSQL 17 migrates from an empty database and Alembic reports no metadata drift;
- Ruff formatting, lint and security rules pass;
- Pyright strict passes for production source;
- `pip-audit` reports no known vulnerable installed dependency;
- wheel and sdist build, packaged migrations and `py.typed` are present;
- the wheel installs into an isolated environment and its public API and CLI execute;
- CodeQL `security-extended` completes successfully;
- the aggregate `CI / merge-gate` is green.

The gate also verifies Pyright strict, `pip-audit`, both npm audits, artifact allowlists and
isolated base and full-extra installations. This evidence applies to the standalone library;
product deployment still requires the controls listed at the end of this document.

## Capability map

| Capability | Security invariant | Evidence |
|---|---|---|
| Password hashing | No plaintext password is persisted | `test_passwords.py`, PostgreSQL flow |
| Unknown-user login | Unknown and wrong-password responses are equivalent | `test_service_sessions.py`, `test_fastapi.py` |
| Lockout | Threshold locks and revokes existing sessions | service tests |
| JWT verification | Algorithm, issuer, audience, type and temporal claims are constrained | `test_tokens.py` |
| Refresh storage | Only token/CSRF hashes are persisted | model/store tests and DB assertions |
| Rotation | A refresh credential has one valid use | service and PostgreSQL integration tests |
| Replay detection | Reusing an old refresh revokes its family | memory and PostgreSQL concurrency tests |
| Immediate revocation | Logout, disable, lock and password change invalidate access | service and HTTP tests |
| Session lifetime | Idle refresh never extends the absolute deadline | session expiry tests |
| CSRF/Origin | Cookie operations require correlation and trusted origin | service and HTTP abuse tests |
| Passkey registration | Real WebAuthn attestation is verified before unique credential persistence | `tests/passkeys/test_webauthn_flow.py`, HTTP and PostgreSQL flow |
| Passkey authentication | Real signed assertions issue the standard authoritative session | virtual authenticator, HTTP and PostgreSQL flow |
| Passkey replay | Ceremony challenge is temporary and consumed atomically once | service, real adapter and PostgreSQL concurrency tests |
| Passkey origin binding | Trusted Origin, RP ID, client origin and cross-origin flags fail closed | service and real adapter adversarial tests |
| Passkey ownership | Discoverable `userHandle` matches the credential owner | real adapter adversarial tests |
| Passkey lifecycle | Multiple credentials can be listed and individually revoked | service and HTTP flow tests |
| Browser passkey client | Unit mocks cover binary conversion and headless Chromium completes the real six-route ceremony with a virtual WebAuthn authenticator | `browser.test.mjs`, `browser.e2e.test.mjs` |
| Google token verification | The official client verifies a generated RS256 token against a live cached certificate endpoint | `tests/google/test_google_auth.py` |
| Google nonce replay | Origin-bound challenges expire and are consumed before token verification | Google service and HTTP security tests |
| Google account policy | Linked-only, preauthorized and open modes fail closed for unknown, unverified and non-authoritative emails | `tests/google/test_service_modes.py` |
| Google email takeover defense | Existing unlinked email requires an administrative flag or recent explicit local link | Google mode and link tests |
| Google domain policy | Hosted-domain allowlist applies to linking and every later login | `tests/google/test_service_security.py` |
| Google concurrency | Concurrent first login creates one external identity and preserves valid sessions | memory and PostgreSQL integration tests |
| Google recovery | Identity removal, temporary password, session revocation and event commit atomically | service, HTTP and PostgreSQL tests |
| Google browser client | Chromium exercises the official-button contract, failure retry and real epok-auth cookies through the sandbox | `examples/google/browser.e2e.test.mjs` |
| Magic Link secrecy | Random tokens are hashed at rest, omitted from representations and transported in URL fragments | `tests/email_links/test_service.py`, model and PostgreSQL assertions |
| Magic Link replay | Provider-activated links expire and commit one atomic consumption | email-link service, HTTP and PostgreSQL tests |
| Magic Link browser binding | Login requires the HttpOnly nonce cookie created by the requesting browser | email-link service and HTTP abuse tests |
| Magic Link browser client | Chromium proves fragment cleanup, foreign-browser rejection and real session cookies | `examples/email_links/browser.e2e.test.mjs` |
| Email replacement | A pending or failed replacement never revokes the previous active link | email-link service delivery tests |
| Password recovery | Password changes without auto-login and revokes every existing session | email-link service and HTTP flows |
| Invitation boundary | Only a pre-provisioned account activates, without creating a session or admin access | email-link service and HTTP flows |
| SMTP delivery | TLS modes, credential redaction, rendering and safe provider errors are tested | `tests/email_links/test_smtp.py` |
| Durable email dispatch | Production requires an injected queue, links stay pending until worker delivery and queue failures preserve generic responses | dispatcher and artifact smoke tests |
| Security fencing | Credential, permission, Google and passkey changes invalidate previously issued links | cross-feature service tests |
| Last administrator | Concurrent operations cannot remove the final active admin | memory and PostgreSQL invariant tests |
| Secret redaction | Validation and auth responses do not echo submitted secrets | HTTP and CLI tests |
| Audit IP integrity | Direct clients cannot spoof event IPs with forwarding headers | HTTP abuse tests |
| Configuration | Production rejects weak secrets, insecure cookies and ambiguous origins | `test_config.py` |
| Migration safety | epok-auth owns a dedicated Alembic history, preserves a host application's history and adopts only trusted legacy epok-auth revisions | PostgreSQL 17 job, `test_migrate.py` and `test_migration_isolation_integration.py` |
| Packaging | Built wheel imports and exposes CLI in an isolated environment | GitHub Actions package job |
| Optional Google install | Base artifact imports without Google dependencies and the `google` extra loads the official adapter | artifact smoke tests |
| Compatibility | Core suite passes Python 3.12, 3.13 and 3.14 | GitHub Actions matrix |
| Persistence | Migrations, drift check and concurrency run against PostgreSQL 17 | GitHub Actions PostgreSQL job |
| Dependencies | Locked installed environment has no known audited vulnerability | `pip-audit` quality step |
| Static analysis | Extended CodeQL analysis completes successfully | GitHub Actions CodeQL job |

A beta is mergeable only when `CI / merge-gate` and `CodeQL / analyze` are green. Product deployment additionally requires application authorization, secret management, network controls and Colors parity testing.
