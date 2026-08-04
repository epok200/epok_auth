#!/usr/bin/env bash
set -euo pipefail
umask 077

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

if ! git remote get-url origin >/dev/null 2>&1; then
  echo "An origin remote is required to verify the release commit." >&2
  exit 1
fi

git fetch --quiet origin refs/heads/main
REMOTE_MAIN="$(git rev-parse FETCH_HEAD)"
LOCAL_HEAD="$(git rev-parse HEAD)"
if [[ "$LOCAL_HEAD" != "$REMOTE_MAIN" ]]; then
  echo "Local main must exactly match origin/main before publishing." >&2
  echo "local:  $LOCAL_HEAD" >&2
  echo "remote: $REMOTE_MAIN" >&2
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

load_publish_token() {
  local line raw token=""

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ "$line" =~ ^[[:space:]]*$ ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue

    if [[ "$line" =~ ^[[:space:]]*UV_PUBLISH_TOKEN[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      if [[ -n "$token" ]]; then
        echo ".env.secret must define UV_PUBLISH_TOKEN only once." >&2
        exit 1
      fi
      raw="${BASH_REMATCH[1]}"
      raw="${raw#"${raw%%[![:space:]]*}"}"
      raw="${raw%"${raw##*[![:space:]]}"}"
      if [[ "$raw" == \"*\" && "$raw" == *\" ]] || \
         [[ "$raw" == \'*\' && "$raw" == *\' ]]; then
        raw="${raw:1:${#raw}-2}"
      fi
      token="$raw"
      continue
    fi

    echo ".env.secret accepts only UV_PUBLISH_TOKEN and comments." >&2
    exit 1
  done < .env.secret

  if [[ -n "$token" ]]; then
    export UV_PUBLISH_TOKEN="$token"
  fi
}

if [[ -f .env.secret ]]; then
  load_publish_token
fi

if [[ "$MODE" == "publish" ]]; then
  if [[ -z "${UV_PUBLISH_TOKEN:-}" ]]; then
    echo "UV_PUBLISH_TOKEN is required. Put it in .env.secret or export it." >&2
    exit 1
  fi
  if [[ "$UV_PUBLISH_TOKEN" != pypi-* ]] || \
     [[ "$UV_PUBLISH_TOKEN" == *"REPLACE_WITH_YOUR_TOKEN"* ]]; then
    echo "UV_PUBLISH_TOKEN does not look like a real PyPI API token." >&2
    exit 1
  fi
fi

VERSION="$(uv version --short)"
if [[ -z "$VERSION" || "$VERSION" == *"+"* ]]; then
  echo "Invalid PyPI release version: $VERSION" >&2
  exit 1
fi

if git rev-parse --verify --quiet "refs/tags/v$VERSION" >/dev/null || \
   git ls-remote --exit-code --tags origin "refs/tags/v$VERSION" >/dev/null 2>&1; then
  echo "Tag v$VERSION already exists. PyPI releases are immutable; bump the version." >&2
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

WHEEL_COUNT="$(find dist -maxdepth 1 -name '*.whl' -print | wc -l | tr -d ' ')"
SDIST_COUNT="$(find dist -maxdepth 1 -name '*.tar.gz' -print | wc -l | tr -d ' ')"
if [[ "$WHEEL_COUNT" != "1" || "$SDIST_COUNT" != "1" ]]; then
  echo "Exactly one wheel and one source distribution are required." >&2
  find dist -maxdepth 1 -type f -print >&2
  exit 1
fi

WHEEL="$(find dist -maxdepth 1 -name '*.whl' -print -quit)"
SDIST="$(find dist -maxdepth 1 -name '*.tar.gz' -print -quit)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

smoke_test_artifact() {
  local artifact="$1"
  local environment="$2"

  uv venv "$environment" --python 3.12
  uv pip install --python "$environment/bin/python" "$artifact"
  EPOK_AUTH_EXPECTED_VERSION="$VERSION" "$environment/bin/python" - <<'PY'
import os
from importlib.metadata import version

import epok_auth
from epok_auth import AuthSettings, EpokAuth

expected = os.environ["EPOK_AUTH_EXPECTED_VERSION"]
assert version("epok-auth") == expected
assert epok_auth.__version__ == expected
assert AuthSettings is not None
assert EpokAuth is not None
PY
  "$environment/bin/epok-auth" --help >/dev/null
}

smoke_test_artifact "$WHEEL" "$TMP_DIR/wheel-venv"
smoke_test_artifact "$SDIST" "$TMP_DIR/sdist-venv"

git diff --exit-code -- . ':!dist'

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
