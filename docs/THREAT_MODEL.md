# Threat model

## Protected assets

- password verifiers;
- active browser sessions;
- access and refresh credentials;
- user and role state;
- security-event integrity;
- private application data protected by the consuming API.

## Trust boundaries

1. The browser is untrusted.
2. The Nuxt BFF, when used, is a server-side security boundary.
3. FastAPI is the authorization enforcement point.
4. PostgreSQL is authoritative for users and session validity.
5. Redis, when introduced, is only an optimization and never the authority.

## In-scope attackers

- remote unauthenticated attacker;
- attacker with a stolen password;
- attacker with a stolen refresh credential;
- attacker replaying an already rotated credential;
- malicious cross-site origin;
- compromised or buggy browser JavaScript;
- attacker attempting resource exhaustion through credential inputs;
- concurrent requests attempting to violate session/admin invariants;
- attacker with a read-only database dump.

## Primary controls

| Threat | Control |
|---|---|
| Password database disclosure | Argon2id hashes; no plaintext credentials |
| User enumeration | Uniform login response and dummy verification |
| Brute force | Per-account lockout plus consumer edge-rate-limit hooks |
| Refresh theft | Opaque high-entropy value; hash only at rest; rotation |
| Refresh replay | Family relation and fail-closed family revocation |
| Access theft after logout | Authoritative session lookup on protected requests |
| CSRF | SameSite cookies, correlated CSRF value and Origin allowlist |
| XSS token exfiltration | Recommended BFF keeps access/refresh outside Vue |
| Infinite sliding session | Separate idle and absolute deadlines |
| Last-admin removal | Transactional invariant lock and active-admin count |
| Unsafe deployment | Production configuration validation fails closed |
| Malformed JWT | Fixed algorithm, issuer/audience/type/claim/time validation |

## Explicit non-goals in 0.1

- phishing-resistant authentication without WebAuthn;
- centralized SSO or identity-provider behavior;
- service-to-service authentication;
- infrastructure TLS, mTLS, firewall or network configuration;
- domain-specific authorization;
- protection after a fully compromised FastAPI/BFF host or signing secret.

## Residual risks

- Account lockout can be abused for denial of service; deploy edge and IP-based rate controls.
- Strict refresh reuse detection can revoke a legitimate family when clients refresh concurrently; BFFs must implement single-flight refresh.
- HS256 requires protecting one symmetric signing secret; asymmetric signing is roadmap work.
- BFF architecture reduces token exposure but does not make XSS harmless; CSP and frontend hygiene remain required.
