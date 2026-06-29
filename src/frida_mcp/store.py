from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path


class ProjectStore:
    def __init__(self, path: str | os.PathLike) -> None:
        self.root = Path(path)
        (self.root / "traces").mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.root / "db.sqlite")
        self.db.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self) -> None:
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                mode TEXT NOT NULL,
                exe_path TEXT,
                args TEXT,
                fingerprint TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'alive',
                created_at REAL NOT NULL
            );
            """
        )
        self.db.commit()

    def create_session(
        self,
        target: str,
        mode: str,
        exe_path: str | None,
        args: list[str] | None,
        fingerprint: str,
    ) -> int:
        cur = self.db.execute(
            "INSERT INTO sessions (target, mode, exe_path, args, fingerprint,"
            " state, created_at) VALUES (?,?,?,?,?, 'alive', ?)",
            (target, mode, exe_path, json.dumps(args or []), fingerprint, time.time()),
        )
        self.db.commit()
        return int(cur.lastrowid)

    def get_session(self, session_id: int) -> dict | None:
        row = self.db.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
        return self._session_row(row) if row else None

    def list_sessions(self) -> list[dict]:
        rows = self.db.execute(
            "SELECT * FROM sessions ORDER BY id DESC"
        ).fetchall()
        return [self._session_row(r) for r in rows]

    def set_session_state(self, session_id: int, state: str) -> None:
        if state not in {"alive", "dead"}:
            raise ValueError(f"invalid state: {state!r}")
        self.db.execute(
            "UPDATE sessions SET state = ? WHERE id = ?", (state, session_id)
        )
        self.db.commit()

    @staticmethod
    def _session_row(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["args"] = json.loads(d["args"]) if d["args"] else []
        return d

    def close(self) -> None:
        self.db.close()
