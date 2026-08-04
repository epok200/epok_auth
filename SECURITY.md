# Security policy

## Supported versions

The project is pre-1.0. Only the latest published beta is eligible for security fixes. Production consumers should pin an exact release and follow security advisories.

## Reporting a vulnerability

Do **not** open a public issue containing exploit details, credentials, customer data or a working proof of concept.

Use GitHub's private vulnerability reporting for this repository. Include:

- affected version or commit;
- attacker prerequisites;
- expected and observed behavior;
- minimal reproduction without real secrets or customer information;
- potential impact;
- suggested mitigation, when known.

Reports will be acknowledged, triaged and handled through coordinated disclosure. A report may be rejected when it requires intentionally insecure consumer configuration that the library already rejects or documents as unsupported.

## Security guarantees and limits

`epok-auth` provides tested authentication primitives and safe defaults. It does not claim that any system is vulnerability-free. Security also depends on:

- TLS termination and network controls;
- secret storage and rotation;
- the consumer's domain authorization;
- dependency and operating-system maintenance;
- secure BFF/frontend integration;
- monitoring, backups and incident response.

Never commit production secrets, database URLs, private keys, real tokens or customer fixtures.
