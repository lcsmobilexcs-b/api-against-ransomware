"""SQLite persistence: processed alerts (idempotency) and optional failed events."""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class StateStore:
    """Idempotent processing keyed by SecuritySnares alert entity_id."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS processed_alerts (
                    entity_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    detail TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS failed_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id TEXT,
                    payload TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def is_processed(self, entity_id: str) -> bool:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM processed_alerts WHERE entity_id = ?",
                (entity_id,),
            ).fetchone()
            return row is not None

    def mark_processed(
        self,
        entity_id: str,
        status: str,
        detail: str | None = None,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO processed_alerts (entity_id, status, detail, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (entity_id, status, detail or "", now),
            )
            conn.commit()

    def record_failed_event(
        self,
        entity_id: str | None,
        payload: str,
        error: str,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO failed_events (entity_id, payload, error, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (entity_id or "", payload, error, now),
            )
            conn.commit()

    def stats(self) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            processed = conn.execute(
                "SELECT COUNT(*) FROM processed_alerts"
            ).fetchone()[0]
            failed = conn.execute("SELECT COUNT(*) FROM failed_events").fetchone()[0]
        return {"processed_alerts": processed, "failed_events": failed}
