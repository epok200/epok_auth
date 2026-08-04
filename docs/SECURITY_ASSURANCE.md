# Security assurance manifest

This document maps beta capabilities to executable evidence. It is not a claim that vulnerabilities are impossible.

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
| Packaging | Built wheel imports and exposes CLI in an isolated environment | GitHub Actions package job |
| Compatibility | Core suite passes Python 3.12, 3.13 and 3.14 | GitHub Actions matrix |
| Persistence | Migrations, drift check and concurrency run against PostgreSQL 17 | GitHub Actions PostgreSQL job |

A beta is mergeable only when `CI / merge-gate` is green.
