# Threat model

## Protected assets

- password verifiers;
- passkey public keys, credential identifiers and ceremony challenges;
- Google external identity links and nonce challenges;
- email-link hashes, browser nonces and short-lived delivery payloads;
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
6. Google certificate and identity claims are an external trust boundary verified by the official
   backend client.
7. The configured SMTP or email API is an external delivery boundary. Provider acceptance is not
   proof of inbox delivery.

## In-scope attackers

- remote unauthenticated attacker;
- attacker with a stolen password;
- attacker with a stolen refresh credential;
- attacker replaying an already rotated credential;
- attacker replaying or substituting a WebAuthn ceremony response;
- attacker presenting a passkey response from another Origin or RP ID;
- attacker forging, replaying or substituting a Google ID token;
- attacker attempting to seize an existing local email through Google Sign-In;
- attacker using an unauthorized Google Workspace domain;
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
| Forged Google identity | Official `google-auth` verifier checks signature, issuer, audience and time claims |
| Google token replay | Random nonce is bound to client ID, Origin and purpose, then consumed atomically once |
| Local email takeover | Existing emails never auto-link without an explicit administrative flag or recent local session |
| Open signup receives library admin | Startup rejects `default_user_role == admin_role` in open mode; new scopes are empty |
| Google subject collision | Unique `(issuer, subject)` and `(user_id, issuer)` database constraints |
| Untrusted Workspace | Optional `hd` allowlist applies to login, auto-link and explicit link |
| Google-only password DoS | Password login executes dummy verification but cannot increment lockout state when disabled |
| Lost Google access | Administrative recovery removes the identity, restores a temporary password and revokes sessions atomically |
| Recovery races | Link revalidates its persisted session inside the write transaction; recovery, link and refresh use a tested lock order |
| Email-link database disclosure | Only token, recipient and browser hashes are persisted |
| Email-link replay | Expiry, generation, state and atomic one-time consumption |
| Login link forwarding | A separate HttpOnly browser nonce is required |
| Stale recovery link | Account `security_version` changes across every security-sensitive mutation |
| Email replacement failure | The old active link remains valid until a newer delivery is accepted |
| Email account enumeration | Generic public responses and persistent per-account request limits |
| Email dispatch outage | Generic `202`, failed-link audit event and no provider detail in logs |
| Token leakage through logs/history | URL fragment transport, `repr=False`, no `GET` consumption and `no-store` |

## Explicit non-goals in 0.4.0

- attestation trust decisions about authenticator manufacturers;
- passkeys as an automatic MFA or step-up policy;
- centralized SSO or identity-provider behavior;
- generic OIDC providers or access to Google APIs;
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
- Public Google option and verification endpoints still need edge rate limiting.
- Public email-link request endpoints need edge and IP-based rate limiting in addition to the
  persistent per-account limit.
- A Google verification outage prevents new Google sessions until certificates can be validated;
  existing local sessions continue under normal session policy.
- Incorrect OAuth client Origins or hosted-domain policy can deny legitimate access; configuration
  rollout must include a recovery administrator.
- A product must provide recovery before making passkeys its only usable account access path.
- Email is not an out-of-band authenticator under NIST SP 800-63B. Magic Links are opt-in AAL1
  access, not MFA and not a sole recovery mechanism for administrators, passkeys, Google or MFA.
- SMTP acceptance does not prove inbox delivery. Durable products need a provider, queue and
  operational delivery monitoring.
- Deployments behind a proxy must configure trusted proxy addresses in the ASGI server so
  `request.client` is rewritten only for trusted hops.
