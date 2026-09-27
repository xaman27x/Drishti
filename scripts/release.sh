#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/release.sh VERSION [--push] [--unsigned-tag] [--skip-container]

Runs every release gate locally. With --push, creates vVERSION at the current
commit and pushes that tag to origin; the tag triggers GitHub's release workflow.

Options:
  --push            Push the release tag after every local gate passes.
  --unsigned-tag    Create an annotated tag instead of requiring a GPG signature.
  --skip-container  Skip the local Docker build and health check.
EOF
}

fail() {
  printf 'release failed: %s\n' "$*" >&2
  exit 1
}

[[ $# -ge 1 ]] || { usage; exit 2; }

version="$1"
shift
push_release=false
sign_tag=true
test_container=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --push) push_release=true ;;
    --unsigned-tag) sign_tag=false ;;
    --skip-container) test_container=false ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
  shift
done

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
cd "$repo_root"

python_bin="${PYTHON_BIN:-python3}"
release_branch="${RELEASE_BRANCH:-main}"
tag="v${version}"

command -v git >/dev/null || fail "git is required"
command -v "$python_bin" >/dev/null || fail "${python_bin} is required"
python_executable="$(command -v "$python_bin")"
export PATH="$(dirname -- "$python_executable"):${PATH}"
git rev-parse --verify HEAD >/dev/null 2>&1 || fail "the repository has no commit to release"
[[ "$(git branch --show-current)" == "$release_branch" ]] \
  || fail "releases must be cut from ${release_branch}; set RELEASE_BRANCH only if intentional"
[[ -z "$(git status --porcelain --untracked-files=normal)" ]] \
  || fail "the working tree must be clean before a release"

"$python_bin" scripts/check_release.py --version "$version" --tag "$tag"
"$python_bin" -m build --version >/dev/null 2>&1 \
  || fail "install release tools first: ${python_bin} -m pip install -e '.[dev,release]'"
"$python_bin" -m twine --version >/dev/null 2>&1 \
  || fail "install release tools first: ${python_bin} -m pip install -e '.[dev,release]'"

make PYTHON="$python_bin" release-check

release_tmp="$(mktemp -d "${TMPDIR:-${repo_root}}/drishti-release.XXXXXX")"
container_name="drishti-release-check-$$"
cleanup() {
  if command -v docker >/dev/null 2>&1; then
    docker rm --force "$container_name" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$release_tmp"
}
trap cleanup EXIT INT TERM

export SOURCE_DATE_EPOCH
SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
"$python_bin" -m build --outdir "${release_tmp}/dist"
"$python_bin" -m twine check "${release_tmp}"/dist/*

if [[ "$test_container" == true ]]; then
  command -v docker >/dev/null || fail "docker is required unless --skip-container is used"
  revision="$(git rev-parse HEAD)"
  created="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  image="drishti:${version}-release-check"
  docker build \
    --build-arg "VERSION=${version}" \
    --build-arg "REVISION=${revision}" \
    --build-arg "CREATED=${created}" \
    --tag "$image" .
  docker run --detach --name "$container_name" \
    --env DRISHTI_ADAPTER_MODE=memory "$image" >/dev/null

  for _ in $(seq 1 30); do
    status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container_name")"
    [[ "$status" == healthy ]] && break
    [[ "$status" == unhealthy ]] && {
      docker logs "$container_name" >&2
      fail "container became unhealthy"
    }
    sleep 1
  done
  [[ "$(docker inspect --format '{{.State.Health.Status}}' "$container_name")" == healthy ]] \
    || fail "container did not become healthy within 30 seconds"
fi

if [[ "$push_release" != true ]]; then
  printf '\nAll release gates passed for %s.\n' "$tag"
  printf 'Publish with: scripts/release.sh %s --push\n' "$version"
  exit 0
fi

git fetch --quiet origin "$release_branch" --tags
[[ "$(git rev-parse HEAD)" == "$(git rev-parse "origin/${release_branch}")" ]] \
  || fail "HEAD must exactly match origin/${release_branch} before publishing"
if git rev-parse --verify "refs/tags/${tag}" >/dev/null 2>&1; then
  [[ "$(git rev-list --max-count=1 "$tag")" == "$(git rev-parse HEAD)" ]] \
    || fail "existing tag ${tag} points to a different commit"
  printf 'Reusing existing local tag %s after verifying its target.\n' "$tag"
else
  if [[ "$sign_tag" == true ]]; then
    git tag --sign --message "Drishti ${version}" "$tag"
  else
    git tag --annotate --message "Drishti ${version}" "$tag"
  fi
fi
git push origin "refs/tags/${tag}"

printf '\nPublished %s. GitHub Actions will now create the package, GHCR image, attestations, SBOM and GitHub Release.\n' "$tag"
