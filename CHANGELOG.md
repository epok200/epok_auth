# Changelog

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
