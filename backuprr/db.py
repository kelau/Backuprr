import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional


SCHEMA_VERSION = 1


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT OR REPLACE INTO app_meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )

    def log(self, level: str, event_type: str, message: str, file_id: Optional[int] = None, data: str = "") -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO events(ts, level, event_type, message, file_id, data) VALUES(?,?,?,?,?,?)",
                (utcnow(), level, event_type, message, file_id, data),
            )

    def add_endpoint(self, path: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO endpoints(path, created_at) VALUES(?,?)",
                (str(Path(path).resolve()), utcnow()),
            )

    def endpoints(self) -> List[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute("SELECT * FROM endpoints ORDER BY path").fetchall()

    def upsert_file(self, record: Dict[str, Any]) -> int:
        now = utcnow()
        with self.connect() as conn:
            row = conn.execute("SELECT id, size, mtime_ns, sha256 FROM files WHERE path = ?", (record["path"],)).fetchone()
            if row:
                changed = row["size"] != record["size"] or row["mtime_ns"] != record["mtime_ns"] or row["sha256"] != record["sha256"]
                state = "changed" if changed else record.get("state", "discovered")
                conn.execute(
                    """
                    UPDATE files
                    SET endpoint_id=?, relative_path=?, size=?, mtime_ns=?, sha256=?,
                        state=CASE WHEN ? THEN ? ELSE state END, updated_at=?
                    WHERE id=?
                    """,
                    (
                        record["endpoint_id"],
                        record["relative_path"],
                        record["size"],
                        record["mtime_ns"],
                        record["sha256"],
                        1 if changed else 0,
                        state,
                        now,
                        row["id"],
                    ),
                )
                file_id = int(row["id"])
            else:
                cur = conn.execute(
                    """
                    INSERT INTO files(endpoint_id, path, relative_path, size, mtime_ns, sha256, state, created_at, updated_at)
                    VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["endpoint_id"],
                        record["path"],
                        record["relative_path"],
                        record["size"],
                        record["mtime_ns"],
                        record["sha256"],
                        record.get("state", "discovered"),
                        now,
                        now,
                    ),
                )
                file_id = int(cur.lastrowid)
            return file_id

    def mark_missing_files(self, seen_paths: Iterable[str], endpoint_id: int) -> int:
        seen = set(seen_paths)
        with self.connect() as conn:
            rows = conn.execute("SELECT id, path FROM files WHERE endpoint_id=? AND state != 'deleted'", (endpoint_id,)).fetchall()
            missing = [row["id"] for row in rows if row["path"] not in seen]
            if missing:
                conn.executemany("UPDATE files SET state='deleted', updated_at=? WHERE id=?", [(utcnow(), item) for item in missing])
            return len(missing)

    def queue_file(self, file_id: int, priority: int = 100, reason: str = "manual") -> None:
        now = utcnow()
        with self.connect() as conn:
            row = conn.execute("SELECT COALESCE(MAX(position), 0) + 1 AS next_pos FROM queue").fetchone()
            conn.execute(
                """
                INSERT INTO queue(file_id, priority, position, status, reason, created_at, updated_at)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(file_id) DO UPDATE SET
                  priority=excluded.priority, status='queued', reason=excluded.reason, updated_at=excluded.updated_at
                """,
                (file_id, priority, row["next_pos"], "queued", reason, now, now),
            )
            conn.execute("UPDATE files SET state='queued', updated_at=? WHERE id=?", (now, file_id))

    def next_queue_item(self) -> Optional[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(
                """
                SELECT q.*, f.path, f.size, f.sha256 FROM queue q
                JOIN files f ON f.id = q.file_id
                WHERE q.status='queued'
                ORDER BY q.priority ASC, q.position ASC
                LIMIT 1
                """
            ).fetchone()

    def set_queue_status(self, file_id: int, status: str) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE queue SET status=?, updated_at=? WHERE file_id=?", (status, utcnow(), file_id))

    def add_chunk(self, file_id: int, chunk_index: int, message_id: str, size: int, sha256: str, subject: str) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO chunks(file_id, chunk_index, message_id, size, sha256, subject, status, posted_at)
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (file_id, chunk_index, message_id, size, sha256, subject, "posted", utcnow()),
            )

    def update_file_state(self, file_id: int, state: str) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE files SET state=?, updated_at=? WHERE id=?", (state, utcnow(), file_id))

    def chunks_due_for_verification(self, older_than: str) -> List[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(
                """
                SELECT c.*, f.path FROM chunks c
                JOIN files f ON f.id = c.file_id
                WHERE c.status != 'missing'
                  AND (c.verified_at IS NULL OR c.verified_at <= ?)
                ORDER BY c.verified_at IS NULL DESC, c.verified_at ASC
                """,
                (older_than,),
            ).fetchall()

    def mark_chunk_verified(self, chunk_id: int, exists: bool) -> None:
        status = "verified" if exists else "missing"
        missing_file_id: Optional[int] = None
        with self.connect() as conn:
            row = conn.execute("SELECT file_id FROM chunks WHERE id=?", (chunk_id,)).fetchone()
            conn.execute("UPDATE chunks SET status=?, verified_at=? WHERE id=?", (status, utcnow(), chunk_id))
            if row and not exists:
                conn.execute("UPDATE files SET state='missing_chunks', updated_at=? WHERE id=?", (utcnow(), row["file_id"]))
                missing_file_id = int(row["file_id"])
        if missing_file_id is not None:
            self.queue_file(missing_file_id, priority=10, reason="missing-chunks")

    def list_rows(self, table: str, limit: int = 200) -> List[sqlite3.Row]:
        allowed = {"files", "events", "queue", "chunks", "endpoints"}
        if table not in allowed:
            raise ValueError(f"Unsupported table: {table}")
        with self.connect() as conn:
            return conn.execute(f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def list_events(self, levels: Optional[List[str]] = None, limit: int = 300) -> List[sqlite3.Row]:
        allowed_levels = {"error", "warning", "info", "verbose"}
        selected = [level for level in (levels or []) if level in allowed_levels]
        with self.connect() as conn:
            if not selected:
                return conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            placeholders = ",".join("?" for _ in selected)
            return conn.execute(
                f"SELECT * FROM events WHERE level IN ({placeholders}) ORDER BY id DESC LIMIT ?",
                (*selected, limit),
            ).fetchall()

    def search_files(self, term: str, limit: int = 200) -> List[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM files WHERE path LIKE ? OR relative_path LIKE ? ORDER BY path LIMIT ?",
                (f"%{term}%", f"%{term}%", limit),
            ).fetchall()

    def stats(self) -> Dict[str, int]:
        with self.connect() as conn:
            states = conn.execute("SELECT state, COUNT(*) AS count FROM files GROUP BY state").fetchall()
            queue = conn.execute("SELECT status, COUNT(*) AS count FROM queue GROUP BY status").fetchall()
            return {
                **{f"files_{row['state']}": row["count"] for row in states},
                **{f"queue_{row['status']}": row["count"] for row in queue},
                "files_total": conn.execute("SELECT COUNT(*) FROM files").fetchone()[0],
                "chunks_total": conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0],
            }


SCHEMA = """
CREATE TABLE IF NOT EXISTS app_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  path TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  endpoint_id INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  path TEXT NOT NULL UNIQUE,
  relative_path TEXT NOT NULL,
  size INTEGER NOT NULL,
  mtime_ns INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_backup_at TEXT,
  last_verify_at TEXT
);

CREATE TABLE IF NOT EXISTS queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER NOT NULL UNIQUE REFERENCES files(id) ON DELETE CASCADE,
  priority INTEGER NOT NULL DEFAULT 100,
  position INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chunks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  chunk_index INTEGER NOT NULL,
  message_id TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  subject TEXT NOT NULL,
  status TEXT NOT NULL,
  posted_at TEXT NOT NULL,
  verified_at TEXT,
  UNIQUE(file_id, chunk_index)
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  level TEXT NOT NULL,
  event_type TEXT NOT NULL,
  message TEXT NOT NULL,
  file_id INTEGER REFERENCES files(id) ON DELETE SET NULL,
  data TEXT NOT NULL DEFAULT ''
);
"""
