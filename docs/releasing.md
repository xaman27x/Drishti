# Releasing Drishti

Drishti releases are tag-driven and fail closed. The only publishing credential is GitHub's
short-lived workflow token; a developer workstation never needs a GHCR password or a long-lived
release token.

## One-time repository settings

1. Protect `main`: require the `quality` and `distribution` CI jobs, require reviewed pull
   requests, block force pushes, and require signed commits if the team has signing configured.
2. Add a tag protection rule for `v*` so only release maintainers can create release tags.
3. After the first GHCR publication, set the `drishti` package visibility deliberately. Public
   repositories do not automatically guarantee that a new package is public.

No repository secret is required. `GITHUB_TOKEN` authenticates GHCR and GitHub Releases, while
GitHub OIDC issues short-lived signing identities for attestations.

## Version update

Drishti currently uses stable semantic versions only: `MAJOR.MINOR.PATCH`.

Update both locations in the same pull request:

- `project.version` in `pyproject.toml`;
- `__version__` in `src/drishti/__init__.py`.

`scripts/check_release.py` prevents a release when they differ or the tag is not exactly
`vMAJOR.MINOR.PATCH`. The API reads the package version instead of keeping a third copy.

## Local preflight

Install the development and release tools, commit the version update, and push `main`:

```bash
python -m pip install -e ".[dev,release]"
scripts/release.sh 0.4.0
git push origin main
```

The preflight requires a clean worktree and runs:

1. Ruff and strict mypy checks;
2. vendored and compiled OCSF integrity verification;
3. the complete pytest suite;
4. wheel and source-distribution creation plus Twine validation; and
5. a release-shaped container build and health check.

`--skip-container` is intended only for a workstation without Docker. It never weakens the
GitHub release workflow, which always builds and tests the image.

## Publish

By default the script requires a GPG-signed Git tag:

```bash
scripts/release.sh 0.4.0 --push
```

Use `--unsigned-tag` only when the repository policy explicitly accepts annotated tags. Before
creating the tag, the script fetches `origin/main` and proves that the local commit is exactly the
published head. Pushing the tag triggers the Release workflow.

The workflow publishes:

| Artifact | Location | Integrity evidence |
| --- | --- | --- |
| Wheel and source archive | GitHub Release | SHA-256 + GitHub build attestation |
| Python dependency SBOM | GitHub Release | CycloneDX JSON + SBOM attestation |
| Container image | `ghcr.io/xaman27x/drishti` | Immutable digest + BuildKit SBOM/provenance + GitHub attestation |
| Release notes | GitHub Release | Generated from merged pull requests |

The container receives version, commit and build-time OCI labels. It is built for AMD64 and
ARM64 from the same source tag and published under the full version, `MAJOR.MINOR`, and `latest`.
The release also includes `container-image.txt`, which records the immutable digest consumers
should pin in production.

## Consumer verification

Verify downloaded release assets before installation:

```bash
sha256sum --check SHA256SUMS
gh attestation verify ./drishti_ulpf-0.4.0-py3-none-any.whl \
  --repo xaman27x/Drishti
```

Pull by immutable digest rather than by a moving tag:

```bash
docker pull ghcr.io/xaman27x/drishti@sha256:<digest-from-container-image.txt>
```

GitHub's release page and `gh attestation verify` expose the workflow identity, source repository,
commit and signing certificate behind each attestation.

## Failure and recovery

- Never move or replace a published version tag.
- If any job fails, fix the cause, increment the patch version, and create a new tag.
- Never edit or rebuild assets under an existing release version.
- If a release is compromised, mark it clearly as withdrawn, revoke deployment access to its
  digest, publish an incident note, and issue a new version.
- Keep parser-registry signing keys outside the container release pipeline. Package provenance
  proves how Drishti was built; it does not replace Drishti's runtime parser-governance keys.
