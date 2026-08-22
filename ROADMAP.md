# Roadmap

## 0.1 - Colors production beta

Local users, administrative provisioning, Argon2id, short access JWTs, opaque rotating refresh sessions, family reuse detection, authoritative PostgreSQL revocation, CSRF/Origin controls, FastAPI integration, migrations, CLI and BFF reference.

## 0.2 - Passkeys

WebAuthn registration and discoverable authentication, multiple credentials, factor
revocation, single-use challenges, PostgreSQL persistence, FastAPI APIs and a browser
reference client. Implemented in the current unreleased candidate.

## 0.3 - Invitations and recovery

One-time invitation tokens, recovery workflows, callback interfaces for email/WhatsApp, user-visible session/device management, recovery codes and optional Redis coordination/rate limiting.

## 0.4 - OpenID Connect

Google OIDC, external identities keyed by issuer and subject, preauthorized B2B account linking and provider interfaces based on standard OIDC clients.

## 0.5 - MFA and step-up

TOTP, recovery codes, factor administration, recent-authentication policies and step-up requirements for sensitive operations.

## 0.6 - Distributed verification

Asymmetric signing, `kid`, JWKS, key rotation, distributed API validation and optional Redis-backed coordination.

## 1.0 - Stable API

Requires production validation in Colors, a second independent consumer, stabilized migrations, compatibility policy and specialized security review.

Service-to-service authentication is intentionally a separate future project.
