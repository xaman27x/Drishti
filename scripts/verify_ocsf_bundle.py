#!/usr/bin/env python3
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSET_ROOT = ROOT / "src" / "drishti" / "ocsf" / "assets"
MANIFEST_PATH = ASSET_ROOT / "bundle-manifest.json"


def main() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text())
    bundle_path = ASSET_ROOT / manifest["asset"]
    with gzip.open(bundle_path, "rb") as compressed:
        bundle = compressed.read()
    actual_sha256 = hashlib.sha256(bundle).hexdigest()
    schema = json.loads(bundle)
    if actual_sha256 != manifest["bundle_sha256"]:
        raise SystemExit(
            f"bundle digest mismatch: expected {manifest['bundle_sha256']}, got {actual_sha256}"
        )
    if schema["version"] != manifest["ocsf_version"]:
        raise SystemExit("compiled schema version does not match its manifest")
    if "drishti" not in schema["extensions"]:
        raise SystemExit("compiled schema is missing the Drishti extension")
    print(f"verified compiled OCSF bundle ({actual_sha256})")


if __name__ == "__main__":
    main()
