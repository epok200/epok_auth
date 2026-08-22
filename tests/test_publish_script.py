import importlib.util
import sys
import tarfile
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "publish.py"
SPEC = importlib.util.spec_from_file_location("epok_auth_publish", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
publish = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = publish
SPEC.loader.exec_module(publish)
release_artifacts = importlib.import_module("release_artifacts")


def write_artifacts(tmp_path: Path, sdist_extra: str | None = None) -> tuple[Path, Path]:
    wheel = tmp_path / "epok_auth-0.2.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("epok_auth/__init__.py", "")
        archive.writestr("epok_auth-0.2.0.dist-info/METADATA", "")

    sdist = tmp_path / "epok_auth-0.2.0.tar.gz"
    names = [
        "epok_auth-0.2.0/.gitignore",
        "epok_auth-0.2.0/pyproject.toml",
        "epok_auth-0.2.0/README.md",
        "epok_auth-0.2.0/src/epok_auth/__init__.py",
    ]
    if sdist_extra:
        names.append(f"epok_auth-0.2.0/{sdist_extra}")
    with tarfile.open(sdist, "w:gz") as archive:
        for name in names:
            archive.addfile(tarfile.TarInfo(name))
    return wheel, sdist


def write_wheel_file(wheel: Path, name: str) -> None:
    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr(name, "")


def test_parse_secret_text_accepts_comments_and_quotes() -> None:
    token = publish.parse_secret_text('# local token\nUV_PUBLISH_TOKEN="pypi-example_token-123"\n')
    assert token == "pypi-example_token-123"


def test_parse_secret_text_rejects_unknown_keys() -> None:
    with pytest.raises(publish.ReleaseError, match="only UV_PUBLISH_TOKEN"):
        publish.parse_secret_text("OTHER_SECRET=nope")


def test_parse_secret_text_rejects_duplicates() -> None:
    with pytest.raises(publish.ReleaseError, match="only once"):
        publish.parse_secret_text("UV_PUBLISH_TOKEN=pypi-first\nUV_PUBLISH_TOKEN=pypi-second\n")


def test_load_publish_token_removes_it_from_process_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(publish, "SECRET_FILE", tmp_path / ".env.secret")
    monkeypatch.setenv(publish.TOKEN_NAME, "pypi-environment-token")

    assert publish._load_publish_token() == "pypi-environment-token"
    assert publish.TOKEN_NAME not in publish.os.environ


def test_load_publish_token_rejects_broad_file_permissions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    secret = tmp_path / ".env.secret"
    secret.write_text("UV_PUBLISH_TOKEN=pypi-private-token", encoding="utf-8")
    secret.chmod(0o644)
    monkeypatch.setattr(publish, "SECRET_FILE", secret)

    with pytest.raises(publish.ReleaseError, match="chmod 600"):
        publish._load_publish_token()


def test_load_publish_token_rejects_symbolic_links(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = tmp_path / "token.txt"
    target.write_text("UV_PUBLISH_TOKEN=pypi-private-token", encoding="utf-8")
    secret = tmp_path / ".env.secret"
    secret.symlink_to(target)
    monkeypatch.setattr(publish, "SECRET_FILE", secret)

    with pytest.raises(publish.ReleaseError, match="symbolic link"):
        publish._load_publish_token()


def test_prepare_context_removes_token_before_repository_commands(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(publish, "SECRET_FILE", tmp_path / ".env.secret")
    monkeypatch.setenv(publish.TOKEN_NAME, "pypi-environment-token")
    monkeypatch.setattr(publish, "_require_command", lambda name: name)

    def validate_repository(*args: object, **kwargs: object) -> tuple[str, str]:
        assert publish.TOKEN_NAME not in publish.os.environ
        return "0.2.0", "abcdef"

    monkeypatch.setattr(publish, "_validate_repository", validate_repository)

    context = publish._prepare_context(publish.Pipeline(), dry_run=True, validate_only=False)

    assert context.publish_token == "pypi-environment-token"


@pytest.mark.parametrize(
    ("mapping", "expected"),
    [
        ("127.0.0.1:49153\n", 49153),
        ("0.0.0.0:32768\n[::]:32768\n", 32768),
        ("[::1]:55000\n", 55000),
    ],
)
def test_parse_docker_port(mapping: str, expected: int) -> None:
    assert publish.parse_docker_port(mapping) == expected


def test_parse_docker_port_rejects_invalid_output() -> None:
    with pytest.raises(publish.ReleaseError, match="Could not parse"):
        publish.parse_docker_port("not-a-port")


def test_artifact_smoke_contract_covers_base_and_passkey_installs() -> None:
    base_code = release_artifacts._base_check_code()
    passkey_code = release_artifacts._passkey_check_code()

    compile(base_code, "<base-smoke>", "exec")
    compile(passkey_code, "<passkey-smoke>", "exec")
    assert "find_spec('webauthn') is None" in base_code
    assert "0002_passkeys.py" in base_code
    assert "WebAuthnAdapter" in passkey_code
    assert "PostgresAuthStore" in passkey_code


def test_artifact_validator_accepts_only_public_package_files(tmp_path: Path) -> None:
    wheel, sdist = write_artifacts(tmp_path)

    release_artifacts.ArtifactValidator.validate(wheel, sdist)


@pytest.mark.parametrize(
    "private_path",
    [
        "tests/test_private.py",
        "src/epok_auth/tests/test_private.py",
        "src/epok_auth/.env.secret",
        "../outside.py",
    ],
)
def test_artifact_validator_rejects_private_sdist_paths(
    tmp_path: Path,
    private_path: str,
) -> None:
    wheel, sdist = write_artifacts(tmp_path, private_path)

    with pytest.raises(publish.ReleaseError, match="outside the public allowlist"):
        release_artifacts.ArtifactValidator.validate(wheel, sdist)


@pytest.mark.parametrize(
    "private_path",
    [
        "epok_auth/tests/test_private.py",
        "epok_auth/.env.secret",
        "../outside.py",
    ],
)
def test_artifact_validator_rejects_private_wheel_paths(
    tmp_path: Path,
    private_path: str,
) -> None:
    wheel, sdist = write_artifacts(tmp_path)
    write_wheel_file(wheel, private_path)

    with pytest.raises(publish.ReleaseError, match="outside the public allowlist"):
        release_artifacts.ArtifactValidator.validate(wheel, sdist)


def test_public_verification_installs_postgres_and_passkeys() -> None:
    pipeline = Mock()
    pipeline.run.return_value = SimpleNamespace(returncode=0, stdout="0.2.0\n")
    context = publish.ReleaseContext(
        publish.Toolchain(git="git", uv="uv", docker="docker", node="node", npm="npm"),
        version="0.2.0",
        commit="abcdef",
        publish_token=None,
    )

    release_artifacts.verify_public_install(pipeline, context, attempts=1)

    command = pipeline.run.call_args.args[1]
    assert "epok-auth[postgres,passkeys]==0.2.0" in command


def test_publish_arguments_never_contain_the_token() -> None:
    token = "pypi-never-in-command-arguments"
    context = publish.ReleaseContext(
        publish.Toolchain(git="git", uv="uv", docker="docker", node="node", npm="npm"),
        version="0.2.0",
        commit="abcdef",
        publish_token=token,
    )

    command = release_artifacts.publish_arguments(context, dry_run=False)

    assert token not in command
    assert token not in " ".join(command)
