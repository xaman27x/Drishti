from datetime import UTC, datetime

from drishti.config import get_settings
from drishti.runtime.state import State

settings = get_settings()
heartbeat = State(settings.state_dir / "runtime.sqlite3").get("worker", {})
fresh = (
    bool(heartbeat.get("at"))
    and (datetime.now(UTC) - datetime.fromisoformat(heartbeat["at"])).total_seconds()
    < settings.worker_stale_seconds
)
raise SystemExit(0 if fresh and heartbeat.get("status") in {"running", "paused"} else 1)
