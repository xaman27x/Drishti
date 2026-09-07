#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "third_party" / "ocsf-schema"
EXTENSION_ROOT = ROOT / "schemas" / "drishti-extension"
ASSET_ROOT = ROOT / "src" / "drishti" / "ocsf" / "assets"
BUNDLE_PATH = ASSET_ROOT / "ocsf-1.9.0-drishti-0.1.0.json.gz"
MANIFEST_PATH = ASSET_ROOT / "bundle-manifest.json"


def canonicalize(value: object) -> object:
    """Remove compiler ordering noise without changing schema meaning."""
    if isinstance(value, dict):
        return {key: canonicalize(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        normalized = [canonicalize(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True))
    return value


def compile_bundle() -> tuple[bytes, str]:
    command = [
        sys.executable,
        "-m",
        "ocsf.compile",
        str(SCHEMA_ROOT),
        "--extension-path",
        str(EXTENSION_ROOT),
        "--extension",
        "drishti",
        "--prefix-extensions",
    ]
    compiled = subprocess.run(command, check=True, capture_output=True).stdout
    parsed = json.loads(compiled)
    if parsed["version"] != "1.9.0":
        raise SystemExit(f"refusing to package unexpected OCSF version: {parsed['version']}")
    if "drishti" not in parsed["extensions"]:
        raise SystemExit("compiled schema does not contain the Drishti extension")

    canonical = json.dumps(canonicalize(parsed), sort_keys=True, separators=(",", ":")).encode()
    return canonical, hashlib.sha256(canonical).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the pinned Drishti OCSF contract bundle")
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify that sources reproduce the committed bundle without writing files",
    )
    args = parser.parse_args()
    canonical, bundle_sha256 = compile_bundle()
    if args.check:
        manifest = json.loads(MANIFEST_PATH.read_text())
        if bundle_sha256 != manifest["bundle_sha256"]:
            raise SystemExit(
                "OCSF sources do not reproduce the committed bundle: "
                f"expected {manifest['bundle_sha256']}, got {bundle_sha256}"
            )
        print(f"reproduced compiled OCSF bundle ({bundle_sha256})")
        return

    ASSET_ROOT.mkdir(parents=True, exist_ok=True)
    with BUNDLE_PATH.open("wb") as output:
        with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
            compressed.write(canonical)
    manifest = {
        "asset": BUNDLE_PATH.name,
        "bundle_sha256": bundle_sha256,
        "compiler": "ocsf-lib",
        "compiler_version": "0.10.4",
        "drishti_extension_version": "0.1.0",
        "ocsf_git_commit": "856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba",
        "ocsf_version": "1.9.0",
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"built {BUNDLE_PATH.relative_to(ROOT)} ({bundle_sha256})")


if __name__ == "__main__":
    main()
