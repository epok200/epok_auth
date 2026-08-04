# epok-auth

**FastAPI-first authentication and revocable session security for private B2B applications.**

`epok-auth` packages the security plumbing that FastAPI intentionally leaves to the application: local users, Argon2id passwords, short-lived access JWTs, opaque rotating refresh tokens, authoritative PostgreSQL sessions, immediate revocation, CSRF protection, administrative provisioning, audit events, and reusable FastAPI dependencies.

The library is deliberately **not** an identity provider and does not own product authorization. Your application still decides what `catalog:write`, `EDITOR`, a tenant membership, or access to a specific resource means.

> **Status:** `0.1.0a1` is an active pre-release. The implementation is being hardened against PostgreSQL 17 and integrated into Colors before a production tag is declared. Public APIs may change until `1.0`.

## The intended developer experience

```python
from contextlib import asynccontextmanager

from fastapi import FastAPI
from epok_auth import AuthSettings, EpokAuth

settings = AuthSettings()  # reads EPOK_AUTH_* variables and fails closed

auth = EpokAuth.postgres(settings=settings)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await auth.aclose()


app = FastAPI(lifespan=lifespan)
auth.install(app, prefix="/api/v1/auth", include_admin=True)

private = auth.protected_router(prefix="/api/v1/private")


@private.get("/hello")
async def hello():
    return {"message": "authenticated"}


app.include_router(private)
```

That installation exposes the production contracts for login, refresh, logout, current principal, password change, and—when requested—the minimal administrative user lifecycle.

A router can be protected with a single dependency:

```python
from fastapi import APIRouter, Depends
from epok_auth import Principal

router = APIRouter(dependencies=[Depends(auth.authenticated)])


@router.get("/me")
async def endpoint(principal: Principal = Depends(auth.current_user)):
    return {"email": principal.email}
```

Roles and scopes remain generic primitives:

```python
@router.post("/ingest")
async def ingest(
    principal: Principal = Depends(auth.require_scopes("catalog:write")),
):
    ...
```

## What v0.1 implements

| Capability | v0.1 behavior |
|---|---|
| Local identity | UUID users, normalized email, active/disabled state, roles and scopes |
| Passwords | Argon2id through `pwdlib`, dummy verification, rehash-on-login, configurable policy |
| Administrative provisioning | Initial admin CLI, create/list/update/disable/reset users, temporary credentials |
| Access credential | Short-lived JWT with strict issuer, audience, algorithm, type and time validation |
| Refresh credential | High-entropy opaque token; only its SHA-256 digest is persisted |
| Rotation | Every accepted refresh consumes the old credential and creates a replacement |
| Replay detection | Reuse of a consumed refresh revokes its complete session family |
| Revocation | Access is checked against authoritative session and user state in PostgreSQL |
| Session lifetime | Sliding inactivity deadline plus a fixed absolute family deadline |
| Browser security | Secure/HttpOnly/host-only cookies, CSRF binding, Origin allowlist and no-store responses |
| Abuse resistance | Uniform login failures, account lockout hooks, bounded inputs and safe errors |
| FastAPI | Ready routers, OpenAPI contracts, principal caching and role/scope/recent-auth dependencies |
| Persistence | Official asynchronous PostgreSQL adapter and packaged Alembic migrations |
| Audit | Structured security events for identity, login, session and administrative transitions |

Google OIDC, invitations, recovery delivery, TOTP, passkeys, Redis coordination, and asymmetric signing are deliberately staged in the [roadmap](ROADMAP.md) rather than being half-implemented in the first production slice.

## Install

During pre-release development:

```bash
uv add 'epok-auth[postgres] @ git+https://github.com/epok200/epok_auth.git@codex/auth-foundation'
```

After the first tagged release:

```bash
uv add 'epok-auth[postgres]'
```

The core package supports Python 3.12–3.14. PostgreSQL support is an explicit extra; Redis is optional and is not an authority for v0.1.

## Configuration

Generate key material:

```bash
epok-auth generate-secret
```

Minimal production environment:

```dotenv
EPOK_AUTH_ENVIRONMENT=production
EPOK_AUTH_DATABASE_URL=postgresql://epok_auth:replace-me@postgres.internal/app
EPOK_AUTH_JWT_SECRET=<generated-secret>
EPOK_AUTH_ISSUER=https://auth.colors.example
EPOK_AUTH_AUDIENCE=colors-api
EPOK_AUTH_TRUSTED_ORIGINS=https://colors.example
```

Production validation intentionally rejects weak secrets, example issuers, insecure cookies, wildcard origins, insufficient password length, and incompatible cookie settings:

```bash
epok-auth check-config
```

Apply the packaged schema and create the first administrator:

```bash
epok-auth upgrade-db
epok-auth create-admin
```

The administrator password is read through a hidden confirmation prompt and is never printed.

## Installed routes

With the default prefix:

```text
POST /api/v1/auth/login
POST /api/v1/auth/refresh
POST /api/v1/auth/logout
GET  /api/v1/auth/me
POST /api/v1/auth/change-password
```

With `include_admin=True`:

```text
GET   /api/v1/auth/users
POST  /api/v1/auth/users
GET   /api/v1/auth/users/{user_id}
PATCH /api/v1/auth/users/{user_id}
POST  /api/v1/auth/users/{user_id}/reset-password
POST  /api/v1/auth/users/{user_id}/revoke-sessions
```

There is no public registration endpoint in v0.1. That is an intentional B2B default.

## Nuxt BFF integration

The BFF is **not part of the Python library**. It is the recommended browser boundary and is documented as an integration example.

In the recommended topology:

```text
Vue browser -> opaque Nuxt session cookie -> Nitro BFF -> access/refresh -> FastAPI
```

Vue never receives the access or refresh credential. Nitro consumes the FastAPI login response server-side, stores backend credentials in a server-side session store, and forwards only the authenticated user representation to the browser. See [`examples/nuxt_bff`](examples/nuxt_bff) and [`docs/bff.md`](docs/bff.md).

## Security model

The key properties are described in the [threat model](docs/threat-model.md). Automated evidence for each implemented control is indexed in the [security assurance manifest](docs/security-assurance.md).

This repository does **not** claim a third-party security certification or proof of absence of vulnerabilities. It does provide explicit invariants, adversarial regression tests, PostgreSQL concurrency tests, static analysis, dependency review, CodeQL, and a private disclosure process.

## Development

```bash
uv sync --all-extras --group dev
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest --cov=epok_auth --cov-report=term-missing
uv build
```

PostgreSQL integration tests require a disposable database:

```bash
export TEST_DATABASE_URL='postgresql://epok_auth:epok_auth@127.0.0.1:5432/epok_auth_test'
uv run pytest -m integration
```

## Project boundaries

`epok-auth` owns authentication primitives, credentials, sessions, revocation, generic roles/scopes, web transports and audit events.

The consuming product owns tenants, memberships, resource-level authorization, business profiles, message content, infrastructure, network topology and user interface.

Service-to-service authentication is intentionally outside this repository.

## License and security reports

MIT licensed. Please report vulnerabilities through the private process described in [`SECURITY.md`](SECURITY.md), not through a public issue.
