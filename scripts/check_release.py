#!/usr/bin/env python3
"""Fail closed when Drishti release metadata is incomplete or inconsistent."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STABLE_VERSION = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
REQUIRED_FILES = (
    "Dockerfile",
    "LICENSE",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "compose.yaml",
    "src/drishti/ocsf/assets/bundle-manifest.json",
)


class ReleaseCheckError(RuntimeError):
    """Raised when a release invariant is not satisfied."""


def project_version() -> str:
    with (ROOT / "pyproject.toml").open("rb") as stream:
        document = tomllib.load(stream)
    value = document.get("project", {}).get("version")
    if not isinstance(value, str):
        raise ReleaseCheckError("pyproject.toml must declare project.version")
    return value


def package_version() -> str:
    module = ast.parse((ROOT / "src/drishti/__init__.py").read_text(encoding="utf-8"))
    for statement in module.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        declares_version = any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in targets
        )
        if not declares_version:
            continue
        value = statement.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            return value.value
    raise ReleaseCheckError("src/drishti/__init__.py must assign a literal __version__")


def verify(expected_version: str | None = None, tag: str | None = None) -> dict[str, str]:
    declared = project_version()
    package = package_version()
    errors: list[str] = []

    if not STABLE_VERSION.fullmatch(declared):
        errors.append(f"project version {declared!r} is not stable SemVer (MAJOR.MINOR.PATCH)")
    if package != declared:
        errors.append(f"package version {package!r} does not match project version {declared!r}")
    if expected_version is not None and expected_version != declared:
        errors.append(f"requested version {expected_version!r} does not match {declared!r}")
    if tag is not None and tag != f"v{declared}":
        errors.append(f"release tag {tag!r} must be exactly 'v{declared}'")

    missing = [name for name in REQUIRED_FILES if not (ROOT / name).is_file()]
    if missing:
        errors.append("required release files are missing: " + ", ".join(missing))

    if errors:
        raise ReleaseCheckError("\n".join(f"- {error}" for error in errors))
    return {"version": declared, "tag": f"v{declared}"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", help="version requested by a release operator")
    parser.add_argument("--tag", help="Git tag that triggered the release")
    parser.add_argument("--print-version", action="store_true", help="print only the version")
    parser.add_argument("--json", action="store_true", help="print machine-readable metadata")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = verify(expected_version=args.version, tag=args.tag)
    except ReleaseCheckError as exc:
        print(f"release check failed:\n{exc}", file=sys.stderr)
        return 1

    if args.print_version:
        print(result["version"])
    elif args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"release metadata is consistent: {result['tag']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
