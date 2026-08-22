# Development process

This document defines how `epok-auth` is designed, built, verified, released, and
maintained. It is a working agreement, not a description of an idealized process.

## Methodology

The project uses iterative, risk-driven development with continuous verification.
It does not claim to use Scrum. The current team and release model do not need fixed
sprints, prescribed roles, or ceremony overhead.

This methodology fits the project because:

- authentication failures can compromise every consuming product;
- the public API and database schema need deliberate compatibility decisions;
- a small team benefits from short, auditable increments;
- automated evidence is more useful than large batches of unreviewed code;
- releases are infrequent enough to validate deeply before publication.

Work is divided into the smallest increment that proves one useful behavior. Each
increment moves through requirements, design, construction, verification, and review.
A larger feature is complete only after its increments work together and the complete
release gate passes.

## Engineering principles

1. Secure defaults must work without undocumented consumer code.
2. The simplest safe public API wins over configurability without a current use case.
3. Standard protocols and cryptography belong to mature, maintained dependencies.
4. Product policy, persistence invariants, sessions, and audit events remain explicit.
5. PostgreSQL is authoritative for production identity and session state.
6. Errors fail closed without exposing credentials, secrets, or account existence.
7. Public behavior is proven through tests, not through implementation assumptions.
8. Compatibility is preserved unless an approved change explicitly replaces it.
9. Python modules stay cohesive and below 600 lines.
10. Documentation, migration behavior, and installation are part of the product.

## Ease of use standard

A feature is not usable merely because its classes can be imported. It must provide a
short and reproducible path from installation to a safe working integration.

Every public capability must satisfy the applicable requirements below. A requirement can
be marked not applicable only with a concrete reason in the approved design.

- one documented `uv add` command with the required extras;
- one settings example containing only values the consumer must choose;
- one minimal FastAPI integration example;
- safe defaults for every optional setting;
- startup failure with an actionable message when required configuration is missing;
- no import failure when an optional extra or feature is not enabled;
- stable request, response, exception, and migration contracts;
- an isolated wheel installation smoke test;
- an end-to-end happy-path test when correctness depends on a browser ceremony or external
  protocol;
- explicit documentation of recovery, revocation, and operational limits.

The primary integration example should fit on one screen. Advanced configuration is
documented separately so it does not obscure the safe default path.

## Development lifecycle

The lifecycle is iterative. Evidence discovered in a later stage can return an
increment to any earlier stage.

| Stage | Entry criteria | Verification | Exit criteria |
|---|---|---|---|
| 1. Conception | A concrete consumer problem or security requirement exists | Confirm that the library, rather than the consuming product, owns the problem | Objective, non-goals, and expected consumer value are written |
| 2. Requirements | The objective is understood | Enumerate normal, failure, abuse, recovery, and compatibility cases | Acceptance criteria and residual risks are explicit |
| 3. Design | Requirements are stable enough to compare solutions | Review public API, state, trust boundaries, dependencies, migrations, and complexity budget | Critical design receives explicit approval before code |
| 4. Construction | Design and increment scope are approved | Keep the change inside its approved files and complexity budget | The increment is implemented without unapproved layers or scope |
| 5. Verification | The increment builds locally | Run focused tests, full regression tests, static checks, security checks, and relevant integration tests | Executable evidence covers normal and adversarial behavior |
| 6. Release | The complete candidate satisfies its acceptance criteria | Run the clean release pipeline, inspect artifacts, and apply semantic versioning | Immutable artifacts and release notes represent the reviewed source |
| 7. Deployment | A released artifact and consumer rollout plan exist | Validate consumer configuration, migrations, authorization, secrets, network controls, observability, backup, and rollback readiness | The approved version is deployed with health and security signals available |
| 8. Operation | A consumer runs the deployed version | Observe failures, security events, dependency advisories, and integration feedback | Incidents are resolved and evidence feeds the next increment |

## Work states

The real workflow uses these states:

1. `proposed`: objective and ownership are being established;
2. `designed`: requirements, non-goals, files, and complexity budget are documented;
3. `approved`: critical changes have explicit authorization;
4. `in progress`: one bounded increment is under construction;
5. `review`: the diff is complete and independently inspected;
6. `verified`: required automated and manual evidence is green;
7. `released`: an immutable version is published;
8. `deployed`: a consumer runs the approved version with operational controls active;
9. `operating`: consumer behavior and security signals are monitored.

A work item can move backward whenever review or evidence invalidates an assumption.

## Risk classification and approval

### Critical changes

The following changes require a written design and explicit approval before code:

- authentication or authorization behavior;
- public request, response, exception, or configuration contracts;
- database entities, migrations, locks, and transaction boundaries;
- credentials, tokens, cookies, cryptography, or secret handling;
- concurrency, replay protection, recovery, or revocation;
- production routing, deployment, or release behavior.

The design must include current cases, the minimal solution, exact files, expected line
count, compatibility impact, failure modes, tests, and rollback or downgrade behavior.

Critical features are implemented in independently reviewable increments. Each increment
stops for diff inspection before the next one expands the trusted code base.

### Standard changes

Backward-compatible documentation, test maintenance, and isolated fixes can proceed with
a shorter written rationale. They still require proportionate verification and review.

### Urgent fixes

An urgent security or production fix may use a shortened design when delay increases
risk. Explicit approval before code remains mandatory for critical changes; only the
length of the design and deferrable evidence may be reduced. The change must remain narrow,
receive review, pass the relevant gates, and create a follow-up item for any evidence that
could not be collected safely before release.

## Construction rules

- Reuse an existing component before adding a new layer.
- Model state, invariants, and lifecycle behavior with small classes and composition. Keep pure,
  stateless transformations as functions instead of wrapping them in ceremonial classes.
- Type public boundaries and reusable contracts. Give repeated compound types one semantic alias at
  module level, and do not annotate obvious local variables merely to increase type coverage.
- Add a Protocol only when at least two real implementations or a real test boundary exist.
- Use adapters for third-party protocols and translate their failures at the boundary.
- Keep network, HTTP, domain, and persistence concerns in their respective layers.
- Keep cross-module data in explicit Pydantic models or immutable dataclasses.
- Do not use anonymous dictionaries as mutable internal contracts.
- Keep database state changes and their security events in the same transaction.
- Do not catch broad exceptions unless the process boundary must prevent termination.
- Do not add recovery, caching, retries, state machines, or distributed coordination without
  a current requirement.
- Remove dead code, unused imports, obsolete comments, and unsupported compatibility paths
  while touching their owning component.

Public APIs must remain small. Convenience wrappers are justified only when they remove a
real integration step without hiding a security decision.

## Verification strategy

Tests describe behavior and use Arrange, Act, Assert. They verify observable contracts,
not private implementation details.

The required layers are:

1. unit tests for pure policy, normalization, models, and adapters;
2. service tests for state transitions, failures, and security events;
3. HTTP contract tests for status, headers, cookies, cache behavior, and safe errors;
4. PostgreSQL tests for migrations, constraints, locking, rollback, and concurrency;
5. end-to-end tests for browser or external protocol integrations;
6. package tests for wheel, source distribution, public imports, CLI, and optional extras.

Security-sensitive work must include adversarial cases such as replay, stale state,
malformed input, enumeration, cross-origin requests, concurrent requests, and revoked
credentials. A fake can isolate policy tests, but at least one test must exercise every
real security adapter.

Required pull request gates are:

- Python 3.12, 3.13, and 3.14 compatibility;
- PostgreSQL 17 migrations with no metadata drift;
- branch coverage of at least 90 percent;
- Ruff formatting, lint, and security rules;
- Pyright strict for production code;
- dependency vulnerability auditing;
- Node conversion tests plus a real headless Chromium WebAuthn ceremony;
- wheel and source distribution build and isolated installation;
- `CI / merge-gate` green after quality, tests, PostgreSQL, coverage, and package jobs;
- the separate `CodeQL / Analyze` security check green.

Coverage is a floor, not proof of correctness. Critical invariants need named behavior and
abuse-case tests even when the covered lines are already counted.

## Review rules

Every significant feature receives two reviews:

1. an implementation review for correctness, simplicity, contracts, and maintainability;
2. an independent audit against the approved requirements, threat model, and evidence.

Review findings identify a file and line when possible and use these priorities:

- `P0`: security, data integrity, or release blocker;
- `P1`: required correctness, compatibility, or maintainability fix;
- `P2`: worthwhile improvement that does not block the current increment.

No increment is complete with an open P0 or P1. A deferred P2 must have a documented reason.

## Security and dependency policy

- Threats and residual risks belong in `docs/THREAT_MODEL.md`.
- Capability claims and executable evidence belong in `docs/SECURITY_ASSURANCE.md`.
- Security reports follow `SECURITY.md` and coordinated disclosure.
- Dependency additions require an ownership decision, maintenance review, license review,
  version bounds, a locked resolution, and tests at the adapter boundary.
- Cryptographic or protocol behavior is never copied from a dependency into project code.
- Optional capabilities use extras and must not break the base installation.
- Secrets, private keys, real tokens, customer data, and production credentials never enter
  source control, fixtures, logs, exceptions, or security-event metadata.

Dependency advisories are reviewed as part of normal maintenance. A vulnerable dependency
with a reachable security impact triggers an urgent fix and a new patch or beta release.

## Release and deployment

Semantic versioning follows these rules:

- incompatible public behavior requires a major release;
- a backward-compatible capability requires a minor release;
- a backward-compatible fix requires a patch release;
- before 1.0, substantial compatible capabilities normally advance the minor version.

The release candidate must come from a clean `main`, match `origin/main`, pass CI and
CodeQL, and pass `uv run scripts/publish.py --dry-run`. Publication uses the process in
`docs/PUBLISHING.md`. Published artifacts and version tags are immutable.

A library release is not automatically a product deployment. Each consumer must still
validate configuration, migrations, authorization, network controls, secret management,
frontend or BFF behavior, observability, backup, and rollback readiness.

## Operation and incident response

Operational ownership includes:

- reviewing authentication failures and security-event anomalies;
- monitoring dependency and platform advisories;
- validating backups and migration recovery in consuming products;
- documenting known integration failures and safe mitigations;
- preserving evidence needed to reproduce concurrency or security defects.

For an incident:

1. contain the affected capability or deployment;
2. preserve logs and evidence without exposing secrets;
3. determine affected versions and attacker prerequisites;
4. implement and verify the smallest safe correction;
5. release through the guarded pipeline;
6. communicate impact and required consumer action;
7. add a regression test and update the threat model or process.

## Definition of done

An increment is done only when:

- its approved behavior and non-goals are satisfied;
- public installation and use remain simple and documented;
- migrations and downgrade behavior are explicit when persistence changes;
- normal, failure, abuse, and concurrency cases have proportionate tests;
- security events contain useful context without sensitive material;
- the complete regression suite and relevant external adapters are green;
- all new and touched Python modules remain below 600 lines;
- documentation and assurance claims match executable behavior;
- an independent review has no open P0 or P1;
- the diff contains no unrelated or speculative architecture.

## Process review

This document is reviewed after a security incident, a failed release, a material change
in team structure, the addition of a new consumer, or at least once per minor release.
Changes to methodology, gates, supported Python or PostgreSQL versions, release flow, or
operational ownership must update this document in the same increment.

When the written process and actual repository behavior disagree, either the automation or
this document must be corrected before the next release. An outdated process is not treated
as a control.
