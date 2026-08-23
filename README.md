# epok-auth

**FastAPI-first authentication with PostgreSQL-authoritative, revocable sessions.**

`epok-auth` is designed for private B2B web applications that need secure local accounts without rebuilding password handling, session rotation, revocation, CSRF protection, administration, and FastAPI dependencies for every product.

> **Status:** `0.2.1` is the public beta on PyPI with WebAuthn passkeys. This branch is an
> unreleased `0.3` candidate that adds Google Sign-In and keeps the existing version until review
> and release approval. Public APIs may still change before `1.0`.
>
> **Practical testing:** see the Spanish step-by-step guide in [`docs/USAGE_ES.md`](docs/USAGE_ES.md).

## Validated beta gate

The clean beta tree is continuously validated by GitHub Actions. The current release has passed:

| Gate | Evidence |
|---|---|
| Functional and adversarial tests | 205/205 passing, plus two browser client proofs |
| Branch coverage | 94.53% |
| Python compatibility | 3.12, 3.13 and 3.14 |
| PostgreSQL | PostgreSQL 17 migration, zero Alembic drift, integration and concurrency tests |
| Static quality | Ruff formatting/lint/security rules and Pyright strict on production source |
| Dependencies | Reproducible `uv.lock` and `pip-audit` |
| Distribution | Wheel and sdist build, packaged migrations, `py.typed`, isolated install and CLI smoke test |
| Code scanning | CodeQL `security-extended` |

The repository does not claim that vulnerabilities are impossible. The green gate establishes reproducible evidence for the defined beta threat model and invariants.

## What the source candidate includes

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
- WebAuthn passkey registration, discoverable login, listing and revocation;
- Google Sign-In with linked-only, preauthorized and open account policies;
- packaged Alembic migrations and an operational CLI;
- a Nuxt/Nitro BFF reference where Vue never receives access or refresh tokens.

Generic OIDC providers, TOTP/MFA, Redis coordination, multi-tenancy and service-to-service authentication remain outside this beta. See [ROADMAP.md](ROADMAP.md).

## Installation

Google Sign-In on an existing adapter:

```bash
uv add "epok-auth[google]"
```

Complete production stack:

```bash
uv add "epok-auth[google,postgres,passkeys]"
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
EPOK_AUTH_PASSKEY_RP_ID=example.com
EPOK_AUTH_PASSKEY_RP_NAME=Colors
EPOK_AUTH_GOOGLE_CLIENT_ID=123456789-example.apps.googleusercontent.com
EPOK_AUTH_GOOGLE_ACCOUNT_MODE=linked_only
```

Production configuration is **fail-closed**: weak secrets, insecure cookies, generic issuer/audience values, missing PostgreSQL, and ambiguous origins prevent startup.

## Publication

The version has one source of truth in `pyproject.toml` and is exposed at runtime through `importlib.metadata`:

```bash
uv version --short
uv version --bump beta
uv version --bump stable
uv version --bump patch
```

`uv version --short` prints the current project version, not the installed version of `uv`.

Local PyPI credentials belong in an ignored `.env.secret` file. The complete release pipeline is a single Python command:

```bash
cp .env.secret.example .env.secret
uv run scripts/publish.py --validate-only
uv run scripts/publish.py --dry-run
uv run scripts/publish.py
```

The normal command validates Python 3.12 through 3.14, launches disposable PostgreSQL 17, runs migrations, drift checks, integration, concurrency and coverage, builds and installs wheel/sdist, simulates the upload, publishes after an exact-version confirmation, pushes the tag and verifies the public PyPI installation.

The script uses inline PEP 723 dependencies and `uv run --isolated`, so it does not replace the developer's project `.venv`. The legacy `bash scripts/publish.sh` command remains as a thin alias. See [docs/PUBLISHING.md](docs/PUBLISHING.md) for the complete procedure.

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
    include_passkeys=True,
    include_google=True,
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
POST /api/v1/auth/passkeys/registration/options
POST /api/v1/auth/passkeys/registration/verify
POST /api/v1/auth/passkeys/authentication/options
POST /api/v1/auth/passkeys/authentication/verify
GET  /api/v1/auth/passkeys
DELETE /api/v1/auth/passkeys/{passkey_id}
POST /api/v1/auth/google/options
POST /api/v1/auth/google/verify
POST /api/v1/auth/google/link/options
POST /api/v1/auth/google/link/verify
POST /api/v1/auth/users/{user_id}/google/recover
```

The recovery route and the rest of user administration appear only with `include_admin=True`.

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

## Documentation

- [Development process and quality gates](DEVELOPMENT.md)
- [Minimal usage and test guide in Spanish](docs/USAGE_ES.md)
- [Passkeys integration guide in Spanish](docs/PASSKEYS_ES.md)
- [Google Sign-In integration guide in Spanish](docs/GOOGLE_ES.md)
- [Publishing and versioning](docs/PUBLISHING.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Security assurance](docs/SECURITY_ASSURANCE.md)
- [Security policy](SECURITY.md)

## Security model

The beta is designed around these invariants:

- knowledge of the source code does not grant access;
- PostgreSQL is the authority for session validity;
- refresh credentials are one-time, opaque and hashed at rest;
- replay revokes the whole session family;
- changing a password, disabling or locking a user revokes sessions;
- unsafe production configuration fails before serving traffic;
- authentication errors do not echo secrets or distinguish unknown users.

## Development

```bash
uv sync --locked --all-extras --group dev
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest
```

Pull requests must pass the GitHub Actions `CI / merge-gate`, including PostgreSQL 17, Python 3.12 through 3.14, branch coverage, dependency auditing, packaging and isolated installation. `CodeQL` must also pass.
