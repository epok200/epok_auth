# /// script
# requires-python = ">=3.12"
# dependencies = [
#   "packaging>=24,<27",
#   "rich>=13,<16",
#   "typer>=0.20,<1",
# ]
# ///

from __future__ import annotations

import ast
import os
import re
import secrets
import shlex
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from packaging.version import InvalidVersion, Version
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

PROJECT_NAME = "epok-auth"
ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = ROOT / "dist"
SECRET_FILE = ROOT / ".env.secret"
PUBLISH_URL = "https://upload.pypi.org/legacy/"
CHECK_URL = "https://pypi.org/simple/"
SUPPORTED_PYTHONS = ("3.12", "3.13", "3.14")
TOKEN_NAME = "UV_PUBLISH_TOKEN"
TOKEN_PLACEHOLDER = "REPLACE_WITH_YOUR_TOKEN"
TOKEN_PATTERN = re.compile(r"^pypi-[A-Za-z0-9_-]+$")

console = Console()


class ReleaseError(RuntimeError):
    """A release invariant was not satisfied."""


@dataclass(frozen=True, slots=True)
class Toolchain:
    git: str
    uv: str
    docker: str


@dataclass(frozen=True, slots=True)
class ReleaseContext:
    tools: Toolchain
    version: str
    commit: str
    publish_token: str | None


@dataclass(frozen=True, slots=True)
class PostgresRuntime:
    container_name: str
    database_url: str


@dataclass(frozen=True, slots=True)
class StepResult:
    name: str
    duration_seconds: float


class Pipeline:
    def __init__(self) -> None:
        self.results: list[StepResult] = []

    def run(
        self,
        title: str,
        command: list[str],
        *,
        env: dict[str, str] | None = None,
        capture: bool = False,
        quiet: bool = False,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)

        if not quiet:
            console.rule(f"[bold cyan]{title}")
            console.print(f"[dim]$ {shlex.join(command)}[/dim]")

        started = time.monotonic()
        completed = subprocess.run(  # noqa: S603 - trusted release commands only.
            command,
            cwd=ROOT,
            env=merged_env,
            check=False,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )
        elapsed = time.monotonic() - started

        if check and completed.returncode != 0:
            if capture:
                if completed.stdout:
                    console.print(completed.stdout.rstrip())
                if completed.stderr:
                    console.print(completed.stderr.rstrip(), style="red")
            raise ReleaseError(
                f"Step '{title}' failed with exit code {completed.returncode}:\n"
                f"{shlex.join(command)}"
            )

        if check:
            self.results.append(StepResult(title, elapsed))
            if not quiet:
                console.print(f"[bold green]✓[/bold green] {title} [dim]({elapsed:.1f}s)[/dim]")
        return completed

    def capture(self, command: list[str], *, check: bool = True) -> str:
        completed = self.run(
            "internal command",
            command,
            capture=True,
            quiet=True,
            check=check,
        )
        return (completed.stdout or "").strip()

    def summary(self, context: ReleaseContext, *, mode: str, tagged: bool) -> None:
        table = Table(title="epok-auth release summary", show_header=False)
        table.add_column("Field", style="bold")
        table.add_column("Value")
        table.add_row("Version", context.version)
        table.add_row("Commit", context.commit[:12])
        table.add_row("Mode", mode)
        table.add_row("Completed checks", str(len(self.results)))
        if mode == "published":
            table.add_row("PyPI", "verified")
            table.add_row("Tag", f"v{context.version}" if tagged else "not created")
        else:
            table.add_row("PyPI", "not uploaded")
            table.add_row("Tag", "not created")
        console.print(table)


def _require_command(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise ReleaseError(f"Required command is not installed or not on PATH: {name}")
    return path


def _parse_secret_value(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    if value[0] in {"'", '"'}:
        try:
            parsed = ast.literal_eval(value)
        except (SyntaxError, ValueError) as error:
            raise ReleaseError(f"{TOKEN_NAME} has invalid quoting in .env.secret.") from error
        if not isinstance(parsed, str):
            raise ReleaseError(f"{TOKEN_NAME} must be a string.")
        return parsed
    if any(character.isspace() for character in value):
        raise ReleaseError(f"Unquoted {TOKEN_NAME} cannot contain whitespace.")
    return value


def parse_secret_text(text: str) -> str | None:
    """Parse the tiny .env.secret contract without executing shell code."""

    token: str | None = None
    for line_number, original in enumerate(text.splitlines(), start=1):
        line = original.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, raw_value = original.partition("=")
        if separator != "=" or key.strip() != TOKEN_NAME:
            raise ReleaseError(
                f".env.secret line {line_number} is invalid; only "
                f"{TOKEN_NAME}=... and comments are allowed."
            )
        if token is not None:
            raise ReleaseError(f".env.secret must define {TOKEN_NAME} only once.")
        token = _parse_secret_value(raw_value)
    return token


def _load_publish_token() -> str | None:
    file_token = (
        parse_secret_text(SECRET_FILE.read_text(encoding="utf-8")) if SECRET_FILE.exists() else None
    )
    environment_token = os.environ.get(TOKEN_NAME)
    if file_token and environment_token and file_token != environment_token:
        raise ReleaseError(
            f"{TOKEN_NAME} differs between the environment and .env.secret; "
            "keep one source of truth."
        )
    return file_token or environment_token


def _validate_publish_token(token: str | None) -> str:
    if not token:
        raise ReleaseError(
            f"{TOKEN_NAME} is required. Copy .env.secret.example to .env.secret "
            "and add your PyPI token."
        )
    if TOKEN_PLACEHOLDER in token or TOKEN_PATTERN.fullmatch(token) is None:
        raise ReleaseError(f"{TOKEN_NAME} does not look like a real PyPI API token.")
    return token


def _git_return_code(pipeline: Pipeline, git: str, arguments: list[str]) -> int:
    completed = pipeline.run(
        "internal Git command",
        [git, *arguments],
        check=False,
        capture=True,
        quiet=True,
    )
    return completed.returncode


def _validate_repository(
    pipeline: Pipeline,
    tools: Toolchain,
    *,
    allow_existing_tag: bool,
) -> tuple[str, str]:
    branch = pipeline.capture([tools.git, "branch", "--show-current"])
    if branch != "main":
        raise ReleaseError(
            f"Releases are allowed only from main; current branch: {branch or 'detached'}."
        )

    status = pipeline.capture([tools.git, "status", "--porcelain", "--untracked-files=normal"])
    if status:
        raise ReleaseError(f"The working tree must be clean before releasing:\n{status}")

    if _git_return_code(pipeline, tools.git, ["remote", "get-url", "origin"]) != 0:
        raise ReleaseError("An origin remote is required.")

    pipeline.run(
        "Fetch origin/main",
        [tools.git, "fetch", "--quiet", "origin", "refs/heads/main"],
        quiet=True,
    )
    local_commit = pipeline.capture([tools.git, "rev-parse", "HEAD"])
    remote_commit = pipeline.capture([tools.git, "rev-parse", "FETCH_HEAD"])
    if local_commit != remote_commit:
        raise ReleaseError(
            "Local main must exactly match origin/main before releasing.\n"
            f"local:  {local_commit}\nremote: {remote_commit}"
        )

    tracked_secret = _git_return_code(
        pipeline,
        tools.git,
        ["ls-files", "--error-unmatch", ".env.secret"],
    )
    if tracked_secret == 0:
        raise ReleaseError(".env.secret is tracked by Git. Remove it before releasing.")
    ignored_secret = _git_return_code(
        pipeline,
        tools.git,
        ["check-ignore", "-q", ".env.secret"],
    )
    if ignored_secret != 0:
        raise ReleaseError(".env.secret is not ignored by Git.")

    version_text = pipeline.capture([tools.uv, "version", "--short"])
    try:
        parsed_version = Version(version_text)
    except InvalidVersion as error:
        raise ReleaseError(f"Invalid PEP 440 project version: {version_text}") from error
    if parsed_version.local is not None:
        raise ReleaseError("PyPI releases cannot use a local version suffix (+...).")

    tag = f"v{version_text}"
    tag_exists_locally = (
        _git_return_code(
            pipeline,
            tools.git,
            ["rev-parse", "--verify", "--quiet", f"refs/tags/{tag}"],
        )
        == 0
    )
    tag_exists_remotely = (
        _git_return_code(
            pipeline,
            tools.git,
            ["ls-remote", "--exit-code", "--tags", "origin", f"refs/tags/{tag}"],
        )
        == 0
    )
    if not allow_existing_tag and (tag_exists_locally or tag_exists_remotely):
        raise ReleaseError(f"Tag {tag} already exists. Bump the version first.")

    return version_text, local_commit


def _project_run(tools: Toolchain, python_version: str, *command: str) -> list[str]:
    return [
        tools.uv,
        "run",
        "--isolated",
        "--locked",
        "--all-extras",
        "--group",
        "dev",
        "--python",
        python_version,
        "--",
        *command,
    ]


def _wait_for_postgres(
    pipeline: Pipeline,
    tools: Toolchain,
    container_name: str,
) -> None:
    for _ in range(60):
        completed = pipeline.run(
            "Wait for PostgreSQL",
            [
                tools.docker,
                "exec",
                container_name,
                "pg_isready",
                "-U",
                "epok_auth",
                "-d",
                "epok_auth_release",
            ],
            check=False,
            capture=True,
            quiet=True,
        )
        if completed.returncode == 0:
            return
        time.sleep(1)
    pipeline.run(
        "PostgreSQL logs",
        [tools.docker, "logs", container_name],
        check=False,
    )
    raise ReleaseError("PostgreSQL 17 did not become ready within 60 seconds.")


def parse_docker_port(output: str) -> int:
    first_line = next((line.strip() for line in output.splitlines() if line.strip()), "")
    if not first_line or ":" not in first_line:
        raise ReleaseError(f"Could not parse Docker port mapping: {output!r}")
    try:
        return int(first_line.rsplit(":", 1)[1])
    except ValueError as error:
        raise ReleaseError(f"Could not parse Docker port mapping: {output!r}") from error


def _start_postgres(pipeline: Pipeline, tools: Toolchain) -> PostgresRuntime:
    container_name = f"epok-auth-release-{os.getpid()}-{secrets.token_hex(4)}"
    pipeline.run(
        "Start disposable PostgreSQL 17",
        [
            tools.docker,
            "run",
            "--rm",
            "--detach",
            "--name",
            container_name,
            "--env",
            "POSTGRES_USER=epok_auth",
            "--env",
            "POSTGRES_PASSWORD=epok_auth",
            "--env",
            "POSTGRES_DB=epok_auth_release",
            "--publish",
            "127.0.0.1::5432",
            "postgres:17-alpine",
        ],
        capture=True,
        quiet=True,
    )
    try:
        _wait_for_postgres(pipeline, tools, container_name)
        port_output = pipeline.capture([tools.docker, "port", container_name, "5432/tcp"])
        port = parse_docker_port(port_output)
        database_url = (
            f"postgresql+psycopg://epok_auth:epok_auth@127.0.0.1:{port}/epok_auth_release"
        )
        return PostgresRuntime(container_name, database_url)
    except Exception:
        pipeline.run(
            "Remove failed PostgreSQL container",
            [tools.docker, "rm", "--force", container_name],
            check=False,
            quiet=True,
        )
        raise


def _stop_postgres(
    pipeline: Pipeline,
    tools: Toolchain,
    runtime: PostgresRuntime | None,
) -> None:
    if runtime is None:
        return
    pipeline.run(
        "Remove disposable PostgreSQL container",
        [tools.docker, "rm", "--force", runtime.container_name],
        check=False,
        quiet=True,
    )
    console.print("[green]✓[/green] Disposable PostgreSQL container removed.")


def _run_quality_and_tests(
    pipeline: Pipeline,
    context: ReleaseContext,
) -> None:
    tools = context.tools
    pipeline.run("Lockfile is reproducible", [tools.uv, "lock", "--check"])
    pipeline.run(
        "Formatting",
        _project_run(tools, "3.12", "ruff", "format", "--check", "."),
    )
    pipeline.run(
        "Lint and security rules",
        _project_run(tools, "3.12", "ruff", "check", "."),
    )
    pipeline.run("Strict typing", _project_run(tools, "3.12", "pyright"))
    pipeline.run(
        "Compile Python modules",
        _project_run(
            tools,
            "3.12",
            "python",
            "-m",
            "compileall",
            "-q",
            "src",
            "tests",
            "examples/minimal",
            "scripts/publish.py",
        ),
    )
    pipeline.run(
        "Dependency vulnerability audit",
        _project_run(
            tools,
            "3.12",
            "pip-audit",
            "--local",
            "--progress-spinner",
            "off",
        ),
    )

    for python_version in SUPPORTED_PYTHONS:
        pipeline.run(
            f"Unit, HTTP and adversarial tests on Python {python_version}",
            _project_run(
                tools,
                python_version,
                "pytest",
                "-m",
                "not integration",
                "-q",
            ),
        )

    runtime: PostgresRuntime | None = None
    try:
        runtime = _start_postgres(pipeline, tools)
        database_env = {"TEST_DATABASE_URL": runtime.database_url}
        migration_code = (
            "import os; "
            "from epok_auth.migrate import upgrade_database; "
            "upgrade_database(os.environ['TEST_DATABASE_URL'])"
        )
        drift_code = (
            "import os; "
            "from epok_auth.migrate import check_database; "
            "check_database(os.environ['TEST_DATABASE_URL'])"
        )
        pipeline.run(
            "Migrate an empty PostgreSQL 17 database",
            _project_run(tools, "3.12", "python", "-c", migration_code),
            env=database_env,
        )
        pipeline.run(
            "Assert zero Alembic metadata drift",
            _project_run(tools, "3.12", "python", "-c", drift_code),
            env=database_env,
        )
        pipeline.run(
            "PostgreSQL integration and concurrency tests",
            _project_run(tools, "3.12", "pytest", "-m", "integration", "-q"),
            env=database_env,
        )
        pipeline.run(
            "Branch-aware coverage gate",
            _project_run(
                tools,
                "3.12",
                "pytest",
                "--cov=epok_auth",
                "--cov-branch",
                "--cov-report=term-missing",
                "--cov-fail-under=90",
            ),
            env=database_env,
        )
    finally:
        _stop_postgres(pipeline, tools, runtime)


def _artifact_paths() -> tuple[Path, Path]:
    wheels = sorted(DIST_DIR.glob("*.whl"))
    sdists = sorted(DIST_DIR.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        found = ", ".join(path.name for path in sorted(DIST_DIR.glob("*")))
        raise ReleaseError(
            "Exactly one wheel and one source distribution are required; "
            f"found: {found or 'nothing'}."
        )
    return wheels[0], sdists[0]


def _venv_python(environment: Path) -> Path:
    if os.name == "nt":
        return environment / "Scripts" / "python.exe"
    return environment / "bin" / "python"


def _venv_cli(environment: Path) -> Path:
    if os.name == "nt":
        return environment / "Scripts" / "epok-auth.exe"
    return environment / "bin" / "epok-auth"


def _smoke_test_artifact(
    pipeline: Pipeline,
    context: ReleaseContext,
    artifact: Path,
    environment: Path,
) -> None:
    pipeline.run(
        f"Create environment for {artifact.name}",
        [context.tools.uv, "venv", str(environment), "--python", "3.12"],
    )
    python = _venv_python(environment)
    pipeline.run(
        f"Install {artifact.name}",
        [
            context.tools.uv,
            "pip",
            "install",
            "--python",
            str(python),
            str(artifact),
        ],
    )
    check_code = (
        "import os; "
        "from importlib.metadata import version; "
        "import epok_auth; "
        "from epok_auth import AuthSettings, EpokAuth; "
        "expected=os.environ['EPOK_AUTH_EXPECTED_VERSION']; "
        "assert version('epok-auth') == expected; "
        "assert epok_auth.__version__ == expected; "
        "assert AuthSettings is not None and EpokAuth is not None"
    )
    pipeline.run(
        f"Verify {artifact.name}",
        [str(python), "-c", check_code],
        env={"EPOK_AUTH_EXPECTED_VERSION": context.version},
    )
    pipeline.run(
        f"Verify CLI from {artifact.name}",
        [str(_venv_cli(environment)), "--help"],
        capture=True,
        quiet=True,
    )


def _build_and_smoke_test(
    pipeline: Pipeline,
    context: ReleaseContext,
) -> tuple[Path, Path]:
    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR)
    pipeline.run(
        "Build wheel and source distribution",
        [context.tools.uv, "build", "--no-sources"],
    )
    wheel, sdist = _artifact_paths()

    with tempfile.TemporaryDirectory(prefix="epok-auth-release-") as temporary:
        temporary_path = Path(temporary)
        _smoke_test_artifact(
            pipeline,
            context,
            wheel,
            temporary_path / "wheel",
        )
        _smoke_test_artifact(
            pipeline,
            context,
            sdist,
            temporary_path / "sdist",
        )

    status = pipeline.capture(
        [context.tools.git, "status", "--porcelain", "--untracked-files=no"]
    )
    if status:
        raise ReleaseError(f"Release checks modified tracked files. Review the working tree:\n{status}")
    return wheel, sdist


def _publish_arguments(context: ReleaseContext, *, dry_run: bool) -> list[str]:
    command = [
        context.tools.uv,
        "publish",
        "--publish-url",
        PUBLISH_URL,
        "--check-url",
        CHECK_URL,
    ]
    if dry_run:
        command.insert(2, "--dry-run")
    return command


def _verify_public_install(
    pipeline: Pipeline,
    context: ReleaseContext,
    *,
    attempts: int = 6,
) -> None:
    requirement = f"{PROJECT_NAME}[postgres]=={context.version}"
    command = [
        context.tools.uv,
        "run",
        "--no-project",
        "--refresh-package",
        PROJECT_NAME,
        "--with",
        requirement,
        "--",
        "python",
        "-c",
        "import epok_auth; print(epok_auth.__version__)",
    ]
    for attempt in range(1, attempts + 1):
        completed = pipeline.run(
            f"Verify public PyPI installation ({attempt}/{attempts})",
            command,
            capture=True,
            quiet=True,
            check=False,
        )
        output = (completed.stdout or "").strip()
        if completed.returncode == 0 and output == context.version:
            console.print(f"[green]✓[/green] PyPI installation verified: {context.version}")
            return
        if attempt < attempts:
            delay = min(2**attempt, 20)
            console.print(f"[yellow]PyPI has not propagated yet; retrying in {delay}s.[/yellow]")
            time.sleep(delay)
    raise ReleaseError(
        "The upload completed, but the public installation could not yet be verified. "
        "Do not republish the same version; verify PyPI later."
    )


def _create_and_push_tag(
    pipeline: Pipeline,
    context: ReleaseContext,
) -> None:
    tag = f"v{context.version}"
    pipeline.run(
        f"Create annotated tag {tag}",
        [
            context.tools.git,
            "tag",
            "-a",
            tag,
            "-m",
            f"{PROJECT_NAME} {context.version}",
        ],
    )
    try:
        pipeline.run(
            f"Push tag {tag}",
            [context.tools.git, "push", "origin", tag],
        )
    except ReleaseError:
        console.print(
            Panel.fit(
                f"PyPI publication succeeded, but pushing {tag} failed.\n"
                f"Run manually: git push origin {tag}",
                title="Tag recovery",
                border_style="yellow",
            )
        )
        raise


def _prepare_context(
    pipeline: Pipeline,
    *,
    dry_run: bool,
    validate_only: bool,
) -> ReleaseContext:
    tools = Toolchain(
        git=_require_command("git"),
        uv=_require_command("uv"),
        docker=_require_command("docker"),
    )
    version, commit = _validate_repository(
        pipeline,
        tools,
        allow_existing_tag=validate_only,
    )
    token = _load_publish_token()
    if not dry_run and not validate_only:
        token = _validate_publish_token(token)
    return ReleaseContext(tools, version, commit, token)


def _abort(message: str, *, code: int = 1) -> NoReturn:
    console.print(Panel.fit(message, title="Release stopped", border_style="red"))
    raise typer.Exit(code=code)


def main(
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help=("Run every release check and uv publish --dry-run without uploading or tagging."),
        ),
    ] = False,
    validate_only: Annotated[
        bool,
        typer.Option(
            "--validate-only",
            help=(
                "Run quality, PostgreSQL, coverage, build and artifact checks "
                "without contacting PyPI."
            ),
        ),
    ] = False,
    tag: Annotated[
        bool,
        typer.Option(
            "--tag/--no-tag",
            help="Create and push an annotated Git tag after publication.",
        ),
    ] = True,
) -> None:
    """Validate, build, publish, verify and tag epok-auth from main."""

    os.umask(0o077)
    os.chdir(ROOT)
    if dry_run and validate_only:
        _abort("--dry-run and --validate-only are mutually exclusive.", code=2)

    pipeline = Pipeline()
    try:
        context = _prepare_context(
            pipeline,
            dry_run=dry_run,
            validate_only=validate_only,
        )
        mode = "validate-only" if validate_only else "dry-run" if dry_run else "publish"
        console.print(
            Panel.fit(
                f"[bold]{PROJECT_NAME} {context.version}[/bold]\n"
                f"commit {context.commit[:12]}\n"
                f"mode: {mode}",
                title="Release pipeline",
                border_style="cyan",
            )
        )

        _run_quality_and_tests(pipeline, context)
        _build_and_smoke_test(pipeline, context)

        if validate_only:
            pipeline.summary(context, mode="validation only", tagged=False)
            return

        publish_env = {}
        if context.publish_token:
            publish_env[TOKEN_NAME] = context.publish_token

        pipeline.run(
            "Validate artifacts against PyPI",
            _publish_arguments(context, dry_run=True),
            env=publish_env,
        )
        if dry_run:
            pipeline.summary(context, mode="dry-run", tagged=False)
            return

        confirmation = Prompt.ask(
            f"Type [bold]{context.version}[/bold] to publish this immutable release"
        )
        if confirmation != context.version:
            _abort("Publication cancelled; confirmation did not match the version.")

        pipeline.run(
            "Publish artifacts to PyPI",
            _publish_arguments(context, dry_run=False),
            env=publish_env,
        )

        tagged = False
        if tag:
            _create_and_push_tag(pipeline, context)
            tagged = True
        _verify_public_install(pipeline, context)
        pipeline.summary(context, mode="published", tagged=tagged)
    except ReleaseError as error:
        _abort(str(error))
    except KeyboardInterrupt:
        _abort("Interrupted by the user.", code=130)


if __name__ == "__main__":
    typer.run(main)
