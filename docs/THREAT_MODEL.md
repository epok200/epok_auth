# Threat model

## Protected assets

- password verifiers;
- passkey public keys, credential identifiers and ceremony challenges;
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
- attacker replaying or substituting a WebAuthn ceremony response;
- attacker presenting a passkey response from another Origin or RP ID;
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
| Passkey phishing or origin substitution | Browser origin binding, exact trusted Origin and RP ID verification |
| Passkey challenge replay | Random temporary challenge consumed atomically once before verification |
| Passkey credential cloning signal | Signature counter verification and serialized credential update |
| Cross-origin WebAuthn ceremony | Explicit rejection of `crossOrigin` and `topOrigin` client data |
| Passkey owner substitution | Discoverable credential `userHandle` must match the stored user UUID |
| Concurrent passkey registration | User lock, credential uniqueness and transactional per-user limit |
| Forged forwarding headers | Audit events use the ASGI peer address and never parse client-supplied forwarding headers |

## Explicit non-goals in 0.2

- attestation trust decisions about authenticator manufacturers;
- passkeys as an automatic MFA or step-up policy;
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
- Public passkey option endpoints still need edge rate limiting against resource exhaustion.
- A product must provide recovery before making passkeys its only usable account access path.
- Deployments behind a proxy must configure trusted proxy addresses in the ASGI server so
  `request.client` is rewritten only for trusted hops.
