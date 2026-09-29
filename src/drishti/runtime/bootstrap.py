from __future__ import annotations

import argparse
import asyncio
import os

from drishti.config import get_settings
from drishti.runtime.service import Runtime


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Explicit local operator approval of built-in packs"
    )
    parser.add_argument("--approve-builtins", action="store_true", required=True)
    parser.parse_args()
    settings = get_settings()
    if settings.environment not in {"local", "test"}:
        raise ValueError("Demo bootstrap cannot run in production")
    runtime = Runtime(settings)
    await runtime.initialize_storage()
    missing = any(
        runtime.governance.registry.active_release(key) is None
        for key in ("generic.rfc5424-firewall", "generic.cef-firewall")
    )
    if missing and os.environ.get("DRISHTI_APPROVE_BUILTINS", "false").lower() != "true":
        raise ValueError(
            "First run requires run-local.sh --approve-builtins after reviewing built-in packs"
        )
    await runtime.governance.approve_builtins()
    print("Approved, qualified and persisted RFC5424 and CEF releases.")


if __name__ == "__main__":
    asyncio.run(main())
