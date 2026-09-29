from __future__ import annotations

import base64
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from uuid import UUID

from drishti.domain.events import RawEvent
from drishti.pipeline.ingestion import IdempotencyConflictError


def encode_event(event: RawEvent) -> str:
    document = event.model_dump(mode="json", exclude={"raw_bytes"})
    document["payload_base64"] = base64.b64encode(event.raw_bytes).decode()
    return json.dumps(document)


def decode_event(document: str) -> RawEvent:
    value = json.loads(document)
    value["raw_bytes"] = base64.b64decode(value.pop("payload_base64"), validate=True)
    return RawEvent.model_validate(value)


class State:
    """Local WAL database. One API and one worker; do not put this on NFS.

    Intent is committed before object archival. This closes the crash window
    between writing raw evidence and registering its publication for recovery.
    The retained intent payload is a local recovery spool, not the evidence API.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY, document TEXT NOT NULL,
                    archived INTEGER NOT NULL DEFAULT 0,
                    published INTEGER NOT NULL DEFAULT 0,
                    error TEXT, received_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS results (
                    event_id TEXT NOT NULL, revision INTEGER NOT NULL,
                    document TEXT NOT NULL, PRIMARY KEY(event_id, revision)
                );
                CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, document TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS replays (
                    id TEXT PRIMARY KEY, document TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS deadletters (
                    id TEXT PRIMARY KEY, document TEXT NOT NULL
                );
            """)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        try:
            with db:
                yield db
        finally:
            db.close()

    def stage(self, event: RawEvent) -> tuple[RawEvent, bool]:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT document FROM events WHERE id=?", (str(event.event_id),)
            ).fetchone()
            if existing:
                old = decode_event(existing[0])
                if old.raw_sha256 != event.raw_sha256 or old.source != event.source:
                    raise IdempotencyConflictError(
                        "idempotency key already identifies different bytes or source metadata"
                    )
                return old, False
            db.execute(
                "INSERT INTO events(id,document,received_at) VALUES(?,?,?)",
                (str(event.event_id), encode_event(event), event.received_at.isoformat()),
            )
        return event, True

    def mark_archived(self, event_id: UUID) -> None:
        with self.connect() as db:
            db.execute("UPDATE events SET archived=1,error=NULL WHERE id=?", (str(event_id),))

    def mark_published(self, event_id: UUID) -> None:
        with self.connect() as db:
            db.execute("UPDATE events SET published=1,error=NULL WHERE id=?", (str(event_id),))

    def publication_error(self, event_id: UUID, error: str) -> None:
        with self.connect() as db:
            db.execute("UPDATE events SET error=? WHERE id=?", (error, str(event_id)))

    def pending(self, limit: int = 100) -> list[RawEvent]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT document FROM events WHERE published=0 ORDER BY received_at LIMIT ?",
                (limit,),
            ).fetchall()
        return [decode_event(row[0]) for row in rows]

    def event(self, event_id: UUID) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM events WHERE id=?", (str(event_id),)).fetchone()
        return dict(row) if row else None

    def events(self, limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM events ORDER BY received_at DESC LIMIT ? OFFSET ?", (limit, offset)
            ).fetchall()
        return [dict(row) for row in rows]

    def result(self, event_id: UUID, revision: int = 1) -> dict[str, Any] | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT document FROM results WHERE event_id=? AND revision=?",
                (str(event_id), revision),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def save_result(
        self,
        event_id: UUID,
        revision: int,
        document: dict[str, Any],
        *,
        drift_key: str | None = None,
        drift: dict[str, Any] | None = None,
    ) -> None:
        with self.connect() as db:
            cursor = db.execute(
                "INSERT OR IGNORE INTO results VALUES(?,?,?)",
                (str(event_id), revision, json.dumps(document)),
            )
            if cursor.rowcount and drift_key and drift:
                db.execute("INSERT OR REPLACE INTO kv VALUES(?,?)", (drift_key, json.dumps(drift)))

    def get(self, key: str, default: Any = None) -> Any:
        with self.connect() as db:
            row = db.execute("SELECT document FROM kv WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set(self, key: str, document: Any) -> None:
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO kv VALUES(?,?)", (key, json.dumps(document)))

    def replays(self) -> list[dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT document FROM replays ORDER BY rowid DESC").fetchall()
        return [json.loads(row[0]) for row in rows]

    def save_replay(self, replay_id: str, document: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO replays VALUES(?,?)", (replay_id, json.dumps(document))
            )

    def deadletter(self, key: str, document: dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute("INSERT OR IGNORE INTO deadletters VALUES(?,?)", (key, json.dumps(document)))

    def counts(self) -> dict[str, int]:
        with self.connect() as db:
            total, archived, published = db.execute(
                "SELECT COUNT(*),COALESCE(SUM(archived),0),COALESCE(SUM(published),0) FROM events"
            ).fetchone()
            statuses = db.execute(
                "SELECT json_extract(document,'$.status'),COUNT(*) "
                "FROM results WHERE revision=1 GROUP BY 1"
            ).fetchall()
            dead = db.execute("SELECT COUNT(*) FROM deadletters").fetchone()[0]
        return {
            "total": total,
            "archived": archived,
            "published": published,
            "pending_publication": total - published,
            "deadletters": dead,
            "normalized": 0,
            "quarantined": 0,
            **dict(statuses),
        }
