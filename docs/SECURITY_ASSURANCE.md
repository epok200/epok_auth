# Security assurance manifest

This document maps beta capabilities to executable evidence. It is not a claim that vulnerabilities are impossible.

## Candidate evidence snapshot

The `0.1.0b1` candidate is accepted by the standalone library gate only after all of the following complete successfully on a clean GitHub runner:

- 101 tests pass, including PostgreSQL integration and concurrency cases;
- branch-aware coverage reaches 94.80%;
- the non-integration suite passes on Python 3.12, 3.13 and 3.14;
- PostgreSQL 17 migrates from an empty database and Alembic reports no metadata drift;
- Ruff formatting, lint and security rules pass;
- Pyright strict passes for production source;
- `pip-audit` reports no known vulnerable installed dependency;
- wheel and sdist build, packaged migrations and `py.typed` are present;
- the wheel installs into an isolated environment and its public API and CLI execute;
- CodeQL `security-extended` completes successfully;
- the aggregate `CI / merge-gate` is green.

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
| Last administrator | Concurrent operations cannot remove the final active admin | memory and PostgreSQL invariant tests |
| Secret redaction | Validation and auth responses do not echo submitted secrets | HTTP and CLI tests |
| Configuration | Production rejects weak secrets, insecure cookies and ambiguous origins | `test_config.py` |
| Migration safety | Empty-database migration commits and schema metadata remains drift-free | PostgreSQL 17 job and `test_migrate.py` |
| Packaging | Built wheel imports and exposes CLI in an isolated environment | GitHub Actions package job |
| Compatibility | Core suite passes Python 3.12, 3.13 and 3.14 | GitHub Actions matrix |
| Persistence | Migrations, drift check and concurrency run against PostgreSQL 17 | GitHub Actions PostgreSQL job |
| Dependencies | Locked installed environment has no known audited vulnerability | `pip-audit` quality step |
| Static analysis | Extended CodeQL analysis completes successfully | GitHub Actions CodeQL job |

A beta is mergeable only when `CI / merge-gate` and `CodeQL / analyze` are green. Product deployment additionally requires application authorization, secret management, network controls and Colors parity testing.
