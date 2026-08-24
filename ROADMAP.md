# Roadmap

## 0.1 - Colors production beta

Local users, administrative provisioning, Argon2id, short access JWTs, opaque rotating refresh sessions, family reuse detection, authoritative PostgreSQL revocation, CSRF/Origin controls, FastAPI integration, migrations, CLI and BFF reference.

## 0.2 - Passkeys

WebAuthn registration and discoverable authentication, multiple credentials, factor
revocation, single-use challenges, PostgreSQL persistence, FastAPI APIs and a browser
reference client. Published in `0.2.1`.

## 0.3 - Google Sign-In

Google Identity Services, ID token verification with the official client, external identities keyed
by issuer and subject, linked-only, preauthorized and open account policies, explicit linking,
administrative recovery, PostgreSQL persistence and a browser sandbox. Implemented in the current
public `0.3.0` release.

## 0.4 - Magic Links and email delivery

Browser-bound Magic Link login, single-use password recovery, pre-provisioned invitations, native
SMTP, injectable provider adapters, security fencing, PostgreSQL persistence and complete FastAPI
flows. Implemented in `0.4.0`.

## 0.5 - Account operations

User-visible session and device management, recovery codes, delivery observability and optional
Redis coordination or rate limiting.

## 0.6 - Generic OpenID Connect

Additional OIDC providers and provider interfaces based on standard OIDC clients.

## 0.7 - MFA and step-up

TOTP, recovery codes, factor administration, recent-authentication policies and step-up requirements for sensitive operations.

## 0.8 - Distributed verification

Asymmetric signing, `kid`, JWKS, key rotation, distributed API validation and optional Redis-backed coordination.

## 1.0 - Stable API

Requires production validation in Colors, a second independent consumer, stabilized migrations, compatibility policy and specialized security review.

Service-to-service authentication is intentionally a separate future project.
