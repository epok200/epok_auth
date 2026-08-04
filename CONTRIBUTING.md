# Contributing

All changes enter through a pull request. Direct pushes to `main` are not part of the supported workflow.

Authentication, cryptography, cookie, CSRF, migration and concurrency changes require:

1. a stated security invariant;
2. a functional test;
3. an adversarial or regression test;
4. PostgreSQL coverage when persistence semantics change;
5. an update to the assurance manifest when the threat model changes.

Run:

```bash
uv sync --all-extras --group dev
uv run ruff format .
uv run ruff check .
uv run pyright
uv run pytest
```

No contribution may introduce custom cryptographic algorithms or log credential material.
