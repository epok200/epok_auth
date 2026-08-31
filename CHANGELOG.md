# Changelog

## 0.4.1 - 2026-08-30

- add a typed `load_auth_settings()` entry point for environment-backed configuration.

## 0.4.0 - 2026-08-25

- add opt-in Magic Link login bound to the requesting browser;
- add single-use password recovery and pre-provisioned account invitations;
- add native Gmail-compatible SMTP delivery plus injectable sender and durable dispatcher contracts;
- keep links pending until the provider accepts the email and preserve older active links on
  delivery failure;
- invalidate stale links after password, account access, Google identity or passkey changes;
- add reversible PostgreSQL persistence, persistent per-account limits and security events;
- add FastAPI routes with generic request responses, Origin validation, secure cookies and
  `no-store`;
- add unit, HTTP, abuse, SMTP, migration, PostgreSQL and Chromium flow tests;
- document provider integration, durable worker boundaries and the NIST email assurance limit.
- centralize account credential transitions and refresh-session validity in domain models;
- unify clock normalization, security-event recording and capability syntax validation;
- replace runtime assertions with explicit guards and simplify passkey authentication branches;
- split local FastAPI routers and security configuration rules without changing the public API.

## 0.3.0 - 2026-08-24

- add optional Google Sign-In through the official `google-auth` verifier;
- add linked-only, preauthorized and open account policies with safe defaults;
- persist canonical external identities and origin-bound, single-use nonce challenges;
- add explicit account linking and atomic administrative recovery;
- reject in-flight links after recovery revokes their persisted session;
- standardize user and session lock ordering across link, recovery and refresh;
- reject open registration when the default role equals the administrative role;
- prevent password attempts from locking Google-only accounts;
- add HTTP, policy, concurrency, protocol, PostgreSQL and browser flow tests;
- add a local Google button sandbox and Spanish integration guide;
- isolate epok-auth Alembic history from host applications and safely adopt published legacy
  revisions.

## 0.2.1 - 2026-08-21

- correct the public release status, installation command and validation evidence;
- preserve the tested `0.2.0` runtime without functional changes.

## 0.2.0 - 2026-08-21

- add optional WebAuthn passkeys through the maintained `webauthn` adapter;
- add discoverable passkey registration, authentication, listing and revocation APIs;
- persist single-use challenges and multiple credentials through a reversible PostgreSQL migration;
- issue the same authoritative session contract from password and passkey authentication;
- test real ES256 WebAuthn ceremonies, HTTP flows, replay defenses and PostgreSQL concurrency;
- package and smoke-test both the base install and the optional `passkeys` extra;
- split the authentication service by responsibility and centralize session issuance;
- centralize typed authentication errors with safe logging and HTTP translation;
- preserve legacy error imports and per-error HTTP overrides through the pre-1.0 transition;
- replace the duplicated shell release implementation with a Rich/Typer Python orchestrator;
- run the release CLI through isolated PEP 723 dependencies;
- validate Python 3.12, 3.13 and 3.14 locally without replacing the project `.venv`;
- execute PostgreSQL 17 migrations, drift, integration, concurrency and coverage locally;
- build and smoke-test both wheel and source distribution;
- publish, create the annotated tag and verify the public PyPI installation in one command;
- add regression tests for `.env.secret` parsing and Docker port discovery;
- retain `scripts/publish.sh` as a compatibility alias.

## 0.1.0 - 2026-08-05

Promoted the validated local-authentication foundation from beta to the first stable
package release. Passkeys are not included in this version.

## 0.1.0b1 - 2026-08-04

First public beta and production-candidate foundation for the Colors integration:

- local user administration;
- Argon2id credentials with dummy verification and rehash support;
- strict short-lived access JWTs;
- opaque rotating refresh sessions;
- session families, reuse detection and immediate revocation;
- idle and absolute session deadlines;
- CSRF correlation and Origin protection;
- PostgreSQL-authoritative sessions and security events;
- packaged Alembic migrations with drift checking;
- FastAPI routers, dependencies and administrative endpoints;
- operational CLI and Nuxt BFF reference;
- reproducible `uv.lock` and isolated package installation;
- single-source versioning through `pyproject.toml`, `uv version` and `importlib.metadata`;
- guarded local publication through `uv build --no-sources` and `uv publish`;
- ignored local PyPI credentials with repository safeguards;
- CodeQL, dependency audit, strict typing and Ruff security rules;
- branch-aware coverage above 90%;
- Python 3.12, 3.13 and 3.14 validation;
- PostgreSQL 17 integration and concurrency validation.

The standalone beta is published on PyPI and tagged as `v0.1.0b1`. Colors backend/frontend parity, deployment configuration and application authorization remain required before product rollout.
