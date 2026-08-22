import os
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
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

console = Console()


class ReleaseError(RuntimeError):
    """A release invariant was not satisfied."""


@dataclass(frozen=True, slots=True)
class Toolchain:
    git: str
    uv: str
    docker: str
    node: str
    npm: str


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
        completed = subprocess.run(  # noqa: S603
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
