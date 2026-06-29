from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path


class ProjectStore:
    def __init__(self, path: str | os.PathLike) -> None:
        self.root = Path(path)
        (self.root / "traces").mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: Frida message callbacks arrive on a background
        # thread; _write_lock serialises all mutations so this is safe.
        self.db = sqlite3.connect(
            self.root / "db.sqlite", check_same_thread=False
        )
        self.db.row_factory = sqlite3.Row
        self._line_counts: dict[int, int] = {}
        self._db_lock = threading.RLock()
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
                pid INTEGER,
                state TEXT NOT NULL DEFAULT 'alive',
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events_index (
                session_id INTEGER NOT NULL,
                line INTEGER NOT NULL,
                type TEXT NOT NULL,
                PRIMARY KEY (session_id, line)
            );
            CREATE TABLE IF NOT EXISTS instruments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                target_expr TEXT NOT NULL,
                source TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS repl_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                code TEXT NOT NULL,
                preview TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                text TEXT NOT NULL,
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
        pid: int | None = None,
    ) -> int:
        with self._db_lock:
            cur = self.db.execute(
                "INSERT INTO sessions (target, mode, exe_path, args, fingerprint,"
                " pid, state, created_at) VALUES (?,?,?,?,?,?, 'alive', ?)",
                (target, mode, exe_path, json.dumps(args or []), fingerprint, pid, time.time()),
            )
            self.db.commit()
            return int(cur.lastrowid)

    def get_session(self, session_id: int) -> dict | None:
        with self._db_lock:
            row = self.db.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            ).fetchone()
            return self._session_row(row) if row else None

    def list_sessions(self) -> list[dict]:
        with self._db_lock:
            rows = self.db.execute(
                "SELECT * FROM sessions ORDER BY id DESC"
            ).fetchall()
            return [self._session_row(r) for r in rows]

    def set_session_state(self, session_id: int, state: str) -> None:
        if state not in {"alive", "dead"}:
            raise ValueError(f"invalid state: {state!r}")
        with self._db_lock:
            self.db.execute(
                "UPDATE sessions SET state = ? WHERE id = ?", (state, session_id)
            )
            self.db.commit()

    @staticmethod
    def _session_row(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["args"] = json.loads(d["args"]) if d["args"] else []
        return d

    def _trace_path(self, session_id: int) -> Path:
        return self.root / "traces" / f"{session_id}.jsonl"

    def _next_line(self, session_id: int) -> int:
        if session_id not in self._line_counts:
            path = self._trace_path(session_id)
            if path.exists():
                with path.open("r", encoding="utf-8") as fh:
                    self._line_counts[session_id] = sum(1 for _ in fh)
            else:
                self._line_counts[session_id] = 0
        return self._line_counts[session_id]

    def append_event(self, session_id: int, event: dict) -> int:
        with self._db_lock:
            line = self._next_line(session_id)
            with self._trace_path(session_id).open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, ensure_ascii=False) + "\n")
            self.db.execute(
                "INSERT INTO events_index (session_id, line, type) VALUES (?,?,?)",
                (session_id, line, str(event.get("type", ""))),
            )
            self.db.commit()
            self._line_counts[session_id] = line + 1
            return line

    def count_events(self, session_id: int, type_filter: str | None = None) -> int:
        with self._db_lock:
            if type_filter is None:
                row = self.db.execute(
                    "SELECT COUNT(*) AS c FROM events_index WHERE session_id = ?",
                    (session_id,),
                ).fetchone()
            else:
                row = self.db.execute(
                    "SELECT COUNT(*) AS c FROM events_index"
                    " WHERE session_id = ? AND type = ?",
                    (session_id, type_filter),
                ).fetchone()
            return int(row["c"])

    def read_events(
        self,
        session_id: int,
        offset: int = 0,
        limit: int = 100,
        type_filter: str | None = None,
    ) -> list[dict]:
        with self._db_lock:
            if type_filter is None:
                rows = self.db.execute(
                    "SELECT line FROM events_index WHERE session_id = ?"
                    " ORDER BY line LIMIT ? OFFSET ?",
                    (session_id, limit, offset),
                ).fetchall()
            else:
                rows = self.db.execute(
                    "SELECT line FROM events_index WHERE session_id = ? AND type = ?"
                    " ORDER BY line LIMIT ? OFFSET ?",
                    (session_id, type_filter, limit, offset),
                ).fetchall()
            wanted = {int(r["line"]) for r in rows}
            if not wanted:
                return []
            out: list[dict] = []
            path = self._trace_path(session_id)
            with path.open("r", encoding="utf-8") as fh:
                for line_no, raw in enumerate(fh):
                    if line_no in wanted:
                        event = json.loads(raw)
                        out.append({"line": line_no, "type": event.get("type", ""),
                                    "event": event})
            return out

    def add_instrument(self, session_id, kind, target_expr, source) -> int:
        with self._db_lock:
            cur = self.db.execute(
                "INSERT INTO instruments (session_id, kind, target_expr, source)"
                " VALUES (?,?,?,?)",
                (session_id, kind, target_expr, source),
            )
            self.db.commit()
            return int(cur.lastrowid)

    def list_instruments(self, session_id, active_only: bool = True) -> list[dict]:
        with self._db_lock:
            sql = "SELECT * FROM instruments WHERE session_id = ?"
            if active_only:
                sql += " AND active = 1"
            sql += " ORDER BY id"
            return [dict(r) for r in self.db.execute(sql, (session_id,)).fetchall()]

    def remove_instrument(self, instrument_id: int) -> None:
        with self._db_lock:
            self.db.execute(
                "UPDATE instruments SET active = 0 WHERE id = ?", (instrument_id,)
            )
            self.db.commit()

    def add_repl(self, session_id, code, preview) -> int:
        with self._db_lock:
            cur = self.db.execute(
                "INSERT INTO repl_history (session_id, code, preview, created_at)"
                " VALUES (?,?,?,?)",
                (session_id, code, preview, time.time()),
            )
            self.db.commit()
            return int(cur.lastrowid)

    def list_repl(self, session_id) -> list[dict]:
        with self._db_lock:
            return [dict(r) for r in self.db.execute(
                "SELECT id, code, preview, created_at FROM repl_history"
                " WHERE session_id = ? ORDER BY id", (session_id,)).fetchall()]

    def add_note(self, session_id, text) -> int:
        with self._db_lock:
            cur = self.db.execute(
                "INSERT INTO notes (session_id, text, created_at) VALUES (?,?,?)",
                (session_id, text, time.time()),
            )
            self.db.commit()
            return int(cur.lastrowid)

    def list_notes(self, session_id) -> list[dict]:
        with self._db_lock:
            return [dict(r) for r in self.db.execute(
                "SELECT id, text, created_at FROM notes"
                " WHERE session_id = ? ORDER BY id", (session_id,)).fetchall()]

    def close(self) -> None:
        self.db.close()
