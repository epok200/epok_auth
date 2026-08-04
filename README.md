# epok-auth

**FastAPI-first authentication with PostgreSQL-authoritative, revocable sessions.**

`epok-auth` is designed for private B2B web applications that need secure local accounts without rebuilding password handling, session rotation, revocation, CSRF protection, administration, and FastAPI dependencies for every product.

> **Status:** `0.1.0b1` beta candidate. The standalone library gate is green. Colors integration and application-level parity remain required before using this beta in that product. Public APIs may still change before `1.0`.
>
> **Practical testing:** see the Spanish step-by-step guide in [`docs/USAGE_ES.md`](docs/USAGE_ES.md).

## Validated beta gate

The clean beta tree is continuously validated by GitHub Actions. The current candidate has passed:

| Gate | Evidence |
|---|---|
| Functional and adversarial tests | 101/101 passing |
| Branch coverage | 94.80% |
| Python compatibility | 3.12, 3.13 and 3.14 |
| PostgreSQL | PostgreSQL 17 migration, zero Alembic drift, integration and concurrency tests |
| Static quality | Ruff formatting/lint/security rules and Pyright strict on production source |
| Dependencies | Reproducible `uv.lock` and `pip-audit` |
| Distribution | Wheel and sdist build, packaged migrations, `py.typed`, isolated install and CLI smoke test |
| Code scanning | CodeQL `security-extended` |

The repository does not claim that vulnerabilities are impossible. The green gate establishes reproducible evidence for the defined beta threat model and invariants.

## What the beta includes

- Argon2id password hashing through `pwdlib`, with rehash support and dummy verification;
- local users, active/disabled state, roles, scopes, administrative provisioning and reset;
- short-lived access JWTs with strict issuer, audience, algorithm, type and time validation;
- opaque refresh credentials stored only as SHA-256 hashes;
- refresh rotation, session families and reuse detection;
- immediate access revocation through authoritative PostgreSQL session state;
- inactivity and absolute session deadlines;
- secure cookies, CSRF correlation and strict Origin allowlists;
- account lockout, uniform login failures and security-event persistence;
- plug-and-play FastAPI routers and dependencies;
- packaged Alembic migrations and an operational CLI;
- a Nuxt/Nitro BFF reference where Vue never receives access or refresh tokens.

Google OIDC, TOTP/MFA, passkeys, Redis coordination, multi-tenancy and service-to-service authentication remain outside this beta. See [ROADMAP.md](ROADMAP.md).

## Installation

Until the beta is published to PyPI, consume the reviewed commit or Git tag explicitly. After publication:

```bash
uv add "epok-auth[postgres]"
```

Generate a secret and configure the application:

```bash
uv run epok-auth generate-secret
```

```dotenv
EPOK_AUTH_ENVIRONMENT=production
EPOK_AUTH_DATABASE_URL=postgresql://colors:password@postgres/colors
EPOK_AUTH_JWT_SECRET=<generated-secret>
EPOK_AUTH_ISSUER=colors-auth
EPOK_AUTH_AUDIENCE=colors-api
EPOK_AUTH_TRUSTED_ORIGINS=https://colors.example.com
```

Production configuration is **fail-closed**: weak secrets, insecure cookies, generic issuer/audience values, missing PostgreSQL, and ambiguous origins prevent startup.

## Database and initial administrator

```bash
uv run epok-auth check-config
uv run epok-auth upgrade-db
uv run epok-auth check-db
uv run epok-auth create-admin
```

The first administrator is serialized transactionally. A second initial-admin creation attempt fails rather than racing.

## FastAPI integration

```python
from fastapi import Depends, FastAPI

from epok_auth import AuthSettings, EpokAuth, Principal

settings = AuthSettings()
auth = EpokAuth.postgres(settings=settings)

app = FastAPI()
auth.install(
    app,
    prefix="/api/v1/auth",
    include_admin=True,
)

catalog = auth.protected_router(prefix="/api/v1/catalog")


@catalog.get("")
async def get_catalog(
    principal: Principal = Depends(auth.authenticated),
) -> dict[str, str]:
    return {"viewer": principal.email}


@catalog.post("")
async def update_catalog(
    principal: Principal = Depends(auth.require_scopes("catalog:write")),
) -> dict[str, str]:
    return {"editor": principal.email}


app.include_router(catalog)
```

`auth.install()` exposes:

```text
POST /api/v1/auth/login
POST /api/v1/auth/refresh
POST /api/v1/auth/logout
POST /api/v1/auth/change-password
GET  /api/v1/auth/me
```

With `include_admin=True` it also exposes protected user administration under `/api/v1/auth/users`.

## Application boundary

`epok-auth` owns authentication capabilities:

- credentials and account state;
- sessions, rotation and revocation;
- generic roles/scopes;
- browser transport protections;
- authentication audit events.

The consuming product still owns:

- tenants and memberships;
- domain permissions;
- resource-level authorization;
- business profiles and data;
- frontend UI and infrastructure.

A role named `editor` has no meaning until Colors decides what an editor can do.

## Nuxt BFF

The BFF is **not implemented inside the Python library**. The repository includes a reference integration under [`examples/nuxt-bff`](examples/nuxt-bff) that demonstrates this boundary:

```text
Browser ── HttpOnly opaque session cookie ──> Nuxt/Nitro
Nuxt/Nitro ── protected access/refresh ──> FastAPI + epok-auth
```

Vue receives only safe user/session state. Access and refresh credentials remain server-side.

## Security model

The beta is designed around these invariants:

- knowledge of the source code does not grant access;
- PostgreSQL is the authority for session validity;
- refresh credentials are one-time, opaque and hashed at rest;
- replay revokes the whole session family;
- changing a password, disabling or locking a user revokes sessions;
- unsafe production configuration fails before serving traffic;
- authentication errors do not echo secrets or distinguish unknown users.

Read [SECURITY.md](SECURITY.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), and [docs/SECURITY_ASSURANCE.md](docs/SECURITY_ASSURANCE.md).

## Development

```bash
uv sync --locked --all-extras --group dev
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest
```

Pull requests must pass the GitHub Actions `CI / merge-gate`, including PostgreSQL 17, Python 3.12–3.14, branch coverage, dependency auditing, packaging and isolated installation. `CodeQL` must also pass.
