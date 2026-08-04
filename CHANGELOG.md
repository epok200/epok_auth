# Changelog

## 0.1.0b1 — unreleased beta candidate

First production-candidate beta for the Colors integration:

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
- CodeQL, dependency audit, strict typing and Ruff security rules;
- 101 passing tests with 94.80% branch-aware coverage;
- Python 3.12, 3.13 and 3.14 validation;
- PostgreSQL 17 integration and concurrency validation.

The standalone beta gate is green. Colors backend/frontend parity, deployment configuration and application authorization remain required before product rollout.
