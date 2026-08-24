from release_support import ROOT, Pipeline, ReleaseContext


def run_browser_proofs(pipeline: Pipeline, context: ReleaseContext) -> None:
    """Install, audit and execute the browser proofs."""

    tools = context.tools
    pipeline.run(
        "Install browser proof dependencies",
        [tools.npm, "ci", "--prefix", "examples/passkeys"],
    )
    pipeline.run(
        "Audit browser proof dependencies",
        [
            tools.npm,
            "audit",
            "--prefix",
            "examples/passkeys",
            "--audit-level",
            "high",
        ],
    )
    pipeline.run(
        "Install Chromium for the browser proof",
        [
            str(ROOT / "examples/passkeys/node_modules/.bin/playwright"),
            "install",
            "chromium",
        ],
    )
    pipeline.run(
        "Browser passkey unit and end-to-end proofs",
        [
            tools.node,
            "--test",
            "examples/passkeys/browser.test.mjs",
            "examples/passkeys/browser.e2e.test.mjs",
        ],
    )
    pipeline.run(
        "Install Google browser proof dependencies",
        [tools.npm, "ci", "--prefix", "examples/google"],
    )
    pipeline.run(
        "Audit Google browser proof dependencies",
        [
            tools.npm,
            "audit",
            "--prefix",
            "examples/google",
            "--audit-level",
            "high",
        ],
    )
    pipeline.run(
        "Browser Google Sign-In proof",
        [tools.node, "--test", "examples/google/browser.e2e.test.mjs"],
    )
    pipeline.run(
        "Install Magic Link browser proof dependencies",
        [tools.npm, "ci", "--prefix", "examples/email_links"],
    )
    pipeline.run(
        "Audit Magic Link browser proof dependencies",
        [
            tools.npm,
            "audit",
            "--prefix",
            "examples/email_links",
            "--audit-level",
            "high",
        ],
    )
    pipeline.run(
        "Browser Magic Link proof",
        [tools.node, "--test", "examples/email_links/browser.e2e.test.mjs"],
    )
