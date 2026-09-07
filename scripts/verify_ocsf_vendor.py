#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR_ROOT = ROOT / "third_party" / "ocsf-schema"
MANIFEST_PATH = ROOT / "third_party" / "ocsf-schema.DRISHTI_VENDOR.json"


def tree_digest(root: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and not path.relative_to(root).as_posix().startswith((".github/", ".vscode/"))
    )
    for path in files:
        relative = path.relative_to(root).as_posix()
        file_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(file_sha256.encode())
        digest.update(b"\n")
    return digest.hexdigest(), len(files)


def main() -> None:
    manifest = json.loads(MANIFEST_PATH.read_text())
    version = json.loads((VENDOR_ROOT / "version.json").read_text())["version"]
    actual_digest, actual_count = tree_digest(VENDOR_ROOT)
    if version != manifest["version"]:
        raise SystemExit(f"OCSF version mismatch: expected {manifest['version']}, got {version}")
    if actual_count != manifest["tree_file_count"]:
        raise SystemExit(
            f"OCSF file-count mismatch: expected {manifest['tree_file_count']}, got {actual_count}"
        )
    if actual_digest != manifest["tree_sha256"]:
        raise SystemExit(
            f"OCSF tree digest mismatch: expected {manifest['tree_sha256']}, got {actual_digest}"
        )
    print(f"verified OCSF {version} vendor tree ({actual_count} files, {actual_digest})")


if __name__ == "__main__":
    main()
