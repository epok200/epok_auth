#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MODE="${1:-publish}"
if [[ "$MODE" != "publish" && "$MODE" != "--dry-run" ]]; then
  echo "Usage: bash scripts/publish.sh [--dry-run]" >&2
  exit 2
fi

command -v git >/dev/null 2>&1 || { echo "git is required." >&2; exit 1; }
command -v uv >/dev/null 2>&1 || { echo "uv is required." >&2; exit 1; }

CURRENT_BRANCH="$(git branch --show-current)"
if [[ "$CURRENT_BRANCH" != "main" ]]; then
  echo "Publishing is allowed only from main; current branch: ${CURRENT_BRANCH:-detached}." >&2
  exit 1
fi

if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
  echo "The working tree must be clean before publishing." >&2
  git status --short >&2
  exit 1
fi

if git ls-files --error-unmatch .env.secret >/dev/null 2>&1; then
  echo ".env.secret is tracked. Remove it from Git before publishing." >&2
  exit 1
fi

if ! git check-ignore -q .env.secret; then
  echo ".env.secret is not ignored by Git. Refusing to continue." >&2
  exit 1
fi

if [[ -f .env.secret ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env.secret
  set +a
fi

if [[ "$MODE" == "publish" && -z "${UV_PUBLISH_TOKEN:-}" ]]; then
  echo "UV_PUBLISH_TOKEN is required. Put it in .env.secret or export it." >&2
  exit 1
fi

VERSION="$(uv version --short)"
if [[ -z "$VERSION" || "$VERSION" == *"+"* ]]; then
  echo "Invalid PyPI release version: $VERSION" >&2
  exit 1
fi

printf 'Preparing epok-auth %s from commit %s\n' "$VERSION" "$(git rev-parse --short HEAD)"

uv lock --check
uv sync --locked --all-extras --group dev --python 3.12
uv run ruff format --check .
uv run ruff check .
uv run pyright
uv run pytest -m "not integration" -q

rm -rf dist
uv build --no-sources

WHEEL="$(find dist -maxdepth 1 -name '*.whl' -print -quit)"
SDIST="$(find dist -maxdepth 1 -name '*.tar.gz' -print -quit)"
if [[ -z "$WHEEL" || -z "$SDIST" ]]; then
  echo "Both wheel and source distribution are required." >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
uv venv "$TMP_DIR/venv" --python 3.12
uv pip install --python "$TMP_DIR/venv/bin/python" "$WHEEL"
EPOK_AUTH_EXPECTED_VERSION="$VERSION" "$TMP_DIR/venv/bin/python" - <<'PY'
import os
from importlib.metadata import version

import epok_auth

expected = os.environ["EPOK_AUTH_EXPECTED_VERSION"]
assert version("epok-auth") == expected
assert epok_auth.__version__ == expected
PY
"$TMP_DIR/venv/bin/epok-auth" --help >/dev/null

PUBLISH_ARGS=(
  --publish-url https://upload.pypi.org/legacy/
  --check-url https://pypi.org/simple/
)

uv publish --dry-run "${PUBLISH_ARGS[@]}"

if [[ "$MODE" == "--dry-run" ]]; then
  echo "Release validation completed. Nothing was uploaded."
  exit 0
fi

printf 'Type %s to publish this immutable release to PyPI: ' "$VERSION"
read -r CONFIRMATION
if [[ "$CONFIRMATION" != "$VERSION" ]]; then
  echo "Publication cancelled."
  exit 1
fi

uv publish "${PUBLISH_ARGS[@]}"
echo "Published epok-auth $VERSION to PyPI."
