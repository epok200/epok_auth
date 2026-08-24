import os
import shutil
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path, PurePosixPath

from release_support import (
    CHECK_URL,
    DIST_DIR,
    PROJECT_NAME,
    PUBLISH_URL,
    Pipeline,
    ReleaseContext,
    ReleaseError,
    console,
)
from rich.panel import Panel


class ArtifactValidator:
    """Enforce the public distribution allowlist."""

    SDIST_ROOTS = (
        ".gitignore",
        "LICENSE",
        "PKG-INFO",
        "README.md",
        "pyproject.toml",
        "src",
    )
    PRIVATE_PARTS = (
        ".github",
        ".pytest_cache",
        ".pyright",
        ".ruff_cache",
        "__pycache__",
        "docs",
        "examples",
        "node_modules",
        "scripts",
        "tests",
    )
    PRIVATE_NAMES = (
        ".env",
        ".env.secret",
        ".gitignore",
        "AGENTS.md",
        "DEVELOPMENT.md",
        "ROADMAP.md",
        "uv.lock",
    )

    @classmethod
    def validate(cls, wheel: Path, sdist: Path) -> None:
        cls._validate_wheel(wheel)
        cls._validate_sdist(sdist)

    @classmethod
    def _validate_wheel(cls, wheel: Path) -> None:
        with zipfile.ZipFile(wheel) as archive:
            unexpected = [name for name in archive.namelist() if not cls._wheel_path_allowed(name)]
        cls._require_clean(wheel, unexpected)

    @classmethod
    def _validate_sdist(cls, sdist: Path) -> None:
        expected_root = sdist.name.removesuffix(".tar.gz")
        with tarfile.open(sdist, "r:gz") as archive:
            unexpected = [
                member.name
                for member in archive.getmembers()
                if not cls._sdist_path_allowed(member.name, expected_root)
            ]
        cls._require_clean(sdist, unexpected)

    @staticmethod
    def _wheel_path_allowed(name: str) -> bool:
        parts = ArtifactValidator._safe_parts(name)
        if parts is None:
            return False
        if not parts:
            return True
        if ArtifactValidator._contains_private_path(parts):
            return False
        root = parts[0]
        package_metadata = root.startswith("epok_auth-") and root.endswith(".dist-info")
        return root == "epok_auth" or package_metadata

    @classmethod
    def _sdist_path_allowed(cls, name: str, expected_root: str) -> bool:
        parts = cls._safe_parts(name)
        if parts is None or not parts or parts[0] != expected_root:
            return False
        if len(parts) == 1:
            return True
        if parts[1] == ".gitignore":
            return len(parts) == 2
        if cls._contains_private_path(parts[1:]):
            return False
        if parts[1] not in cls.SDIST_ROOTS:
            return False
        return parts[1] != "src" or len(parts) == 2 or parts[2] == "epok_auth"

    @staticmethod
    def _safe_parts(name: str) -> tuple[str, ...] | None:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            return None
        return tuple(part for part in path.parts if part != ".")

    @classmethod
    def _contains_private_path(cls, parts: tuple[str, ...]) -> bool:
        if any(part in cls.PRIVATE_PARTS for part in parts):
            return True
        return any(part in cls.PRIVATE_NAMES or part.startswith(".env.") for part in parts)

    @staticmethod
    def _require_clean(artifact: Path, unexpected: list[str]) -> None:
        if not unexpected:
            return
        entries = "\n".join(f"- {name}" for name in unexpected[:20])
        raise ReleaseError(
            f"{artifact.name} contains files outside the public allowlist:\n{entries}"
        )


def build_and_smoke_test(
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
    ArtifactValidator.validate(wheel, sdist)

    with tempfile.TemporaryDirectory(prefix="epok-auth-release-") as temporary:
        temporary_path = Path(temporary)
        _smoke_test_artifact(pipeline, context, wheel, temporary_path / "wheel")
        _smoke_test_artifact(pipeline, context, sdist, temporary_path / "sdist")

    status = pipeline.capture([context.tools.git, "status", "--porcelain", "--untracked-files=no"])
    if status:
        raise ReleaseError(
            f"Release checks modified tracked files. Review the working tree:\n{status}"
        )
    return wheel, sdist


def publish_arguments(context: ReleaseContext, *, dry_run: bool) -> list[str]:
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


def verify_public_install(
    pipeline: Pipeline,
    context: ReleaseContext,
    *,
    attempts: int = 6,
) -> None:
    requirement = f"{PROJECT_NAME}[google,postgres,passkeys]=={context.version}"
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
        (
            "import epok_auth\n"
            "import google.auth\n"
            "import webauthn\n"
            "from epok_auth.google.google_auth import GoogleAuthVerifier\n"
            "from epok_auth.passkeys.webauthn import WebAuthnAdapter\n"
            "assert GoogleAuthVerifier is not None\n"
            "print(epok_auth.__version__)"
        ),
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


def create_and_push_tag(
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
    _create_environment(pipeline, context, artifact, environment)
    python = _venv_python(environment)
    pipeline.run(
        f"Verify base install from {artifact.name}",
        [str(python), "-c", _base_check_code()],
        env={"EPOK_AUTH_EXPECTED_VERSION": context.version},
    )
    pipeline.run(
        f"Verify CLI from {artifact.name}",
        [str(_venv_cli(environment)), "--help"],
        capture=True,
        quiet=True,
    )

    passkey_environment = environment.with_name(f"{environment.name}-passkeys")
    _create_environment(
        pipeline,
        context,
        artifact,
        passkey_environment,
        extra="google,postgres,passkeys",
    )
    pipeline.run(
        f"Verify documented extras from {artifact.name}",
        [str(_venv_python(passkey_environment)), "-c", _passkey_check_code()],
    )


def _create_environment(
    pipeline: Pipeline,
    context: ReleaseContext,
    artifact: Path,
    environment: Path,
    *,
    extra: str | None = None,
) -> None:
    title = artifact.name if extra is None else f"{artifact.name}[{extra}]"
    pipeline.run(
        f"Create environment for {title}",
        [context.tools.uv, "venv", str(environment), "--python", "3.12"],
    )
    requirement = str(artifact) if extra is None else f"{artifact}[{extra}]"
    pipeline.run(
        f"Install {title}",
        [
            context.tools.uv,
            "pip",
            "install",
            "--python",
            str(_venv_python(environment)),
            requirement,
        ],
    )


def _base_check_code() -> str:
    return "\n".join(
        (
            "import os",
            "from importlib.metadata import version",
            "from importlib.resources import files",
            "from importlib.util import find_spec",
            "import epok_auth",
            "from fastapi import FastAPI",
            "from epok_auth import AuthSettings, EpokAuth",
            "from epok_auth.email_links import AuthEmail, PendingEmailLink",
            "from epok_auth.testing import MemoryAuthStore",
            "expected = os.environ['EPOK_AUTH_EXPECTED_VERSION']",
            "assert version('epok-auth') == expected == epok_auth.__version__",
            "assert find_spec('webauthn') is None",
            "assert find_spec('google') is None",
            (
                "assert files('epok_auth.migrations').joinpath('versions', "
                "'0004_email_links.py').is_file()"
            ),
            "auth = EpokAuth(settings=AuthSettings.development(), store=MemoryAuthStore())",
            "try:",
            "    auth.install(FastAPI(), include_passkeys=True)",
            "except RuntimeError as error:",
            "    assert 'epok-auth[passkeys]' in str(error)",
            "else:",
            "    raise AssertionError('passkeys enabled without optional dependency')",
            (
                "google_settings = AuthSettings.development(google_client_id="
                "'123456789-test.apps.googleusercontent.com')"
            ),
            "google_auth = EpokAuth(settings=google_settings, store=MemoryAuthStore())",
            "try:",
            "    google_auth.install(FastAPI(), include_google=True)",
            "except RuntimeError as error:",
            "    assert 'epok-auth[google]' in str(error)",
            "else:",
            "    raise AssertionError('Google enabled without optional dependency')",
            "class EmailQueue:",
            "    async def dispatch(self, message: AuthEmail | PendingEmailLink) -> None:",
            "        del message",
            "email_settings = AuthSettings.development(",
            "    email_link_login_url='http://localhost:3000/login',",
            "    email_link_password_reset_url='http://localhost:3000/reset-password',",
            "    email_link_invitation_url='http://localhost:3000/invitation',",
            ")",
            "email_auth = EpokAuth(",
            "    settings=email_settings,",
            "    store=MemoryAuthStore(),",
            "    email_link_dispatcher=EmailQueue(),",
            ")",
            "email_app = FastAPI()",
            "email_auth.install(email_app, include_email_links=True)",
            "assert '/auth/email-links/login' in email_app.openapi()['paths']",
        )
    )


def _passkey_check_code() -> str:
    return "\n".join(
        (
            "from epok_auth import PasskeyService",
            "from epok_auth.google.google_auth import GoogleAuthVerifier",
            "from epok_auth.passkeys.webauthn import WebAuthnAdapter",
            "from epok_auth.postgres import PostgresAuthStore",
            "adapter = WebAuthnAdapter(rp_id='localhost', rp_name='EPOK', timeout_ms=60000)",
            "assert adapter.authentication_options(b'a' * 32)['challenge']",
            "assert PasskeyService is not None",
            "assert GoogleAuthVerifier is not None",
            "assert PostgresAuthStore is not None",
        )
    )
