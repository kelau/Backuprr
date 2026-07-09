import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
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
                move_row = self._find_move_candidate(conn, record)
                if move_row:
                    conn.execute(
                        """
                        UPDATE files
                        SET path=?, relative_path=?, mtime_ns=?, state=CASE WHEN state='deleted' THEN ? ELSE state END,
                            updated_at=?
                        WHERE id=?
                        """,
                        (
                            record["path"],
                            record["relative_path"],
                            record["mtime_ns"],
                            record.get("state", "discovered"),
                            now,
                            move_row["id"],
                        ),
                    )
                    file_id = int(move_row["id"])
                    conn.execute(
                        "INSERT INTO events(ts, level, event_type, message, file_id, data) VALUES(?,?,?,?,?,?)",
                        (
                            now,
                            "info",
                            "scan.move",
                            f"Updated moved file path: {move_row['path']} -> {record['path']}",
                            file_id,
                            "",
                        ),
                    )
                    return file_id
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

    def _find_move_candidate(self, conn: sqlite3.Connection, record: Dict[str, Any]) -> Optional[sqlite3.Row]:
        rows = conn.execute(
            """
            SELECT id, path FROM files
            WHERE endpoint_id=? AND size=? AND sha256=? AND path != ?
            """,
            (record["endpoint_id"], record["size"], record["sha256"], record["path"]),
        ).fetchall()
        missing_rows = [row for row in rows if not Path(row["path"]).exists()]
        if len(missing_rows) == 1:
            return missing_rows[0]
        return None

    def mark_missing_files(self, seen_paths: Iterable[str], endpoint_id: int) -> int:
        seen = set(seen_paths)
        with self.connect() as conn:
            rows = conn.execute("SELECT id, path FROM files WHERE endpoint_id=? AND state != 'deleted'", (endpoint_id,)).fetchall()
            missing = [row["id"] for row in rows if row["path"] not in seen]
            if missing:
                conn.executemany("UPDATE files SET state='deleted', updated_at=? WHERE id=?", [(utcnow(), item) for item in missing])
            return len(missing)

    def reconcile_moved_duplicates(self, endpoint_id: int) -> int:
        now = utcnow()
        reconciled = 0
        with self.connect() as conn:
            pairs = conn.execute(
                """
                SELECT
                  deleted.id AS deleted_id,
                  deleted.path AS deleted_path,
                  active.id AS active_id,
                  active.path AS active_path,
                  active.relative_path AS active_relative_path,
                  active.mtime_ns AS active_mtime_ns,
                  active.state AS active_state
                FROM files deleted
                JOIN files active
                  ON active.endpoint_id = deleted.endpoint_id
                 AND active.size = deleted.size
                 AND active.sha256 = deleted.sha256
                 AND active.id != deleted.id
                WHERE deleted.endpoint_id = ?
                  AND deleted.state = 'deleted'
                  AND active.state != 'deleted'
                """,
                (endpoint_id,),
            ).fetchall()
            for pair in pairs:
                if Path(pair["deleted_path"]).exists() or not Path(pair["active_path"]).exists():
                    continue
                active_chunks = conn.execute("SELECT COUNT(*) FROM chunks WHERE file_id=?", (pair["active_id"],)).fetchone()[0]
                active_queue = conn.execute("SELECT COUNT(*) FROM queue WHERE file_id=?", (pair["active_id"],)).fetchone()[0]
                if active_chunks or active_queue:
                    continue
                duplicate_count = conn.execute(
                    """
                    SELECT COUNT(*) FROM files
                    WHERE endpoint_id=? AND size=(SELECT size FROM files WHERE id=?)
                      AND sha256=(SELECT sha256 FROM files WHERE id=?)
                      AND state != 'deleted'
                    """,
                    (endpoint_id, pair["deleted_id"], pair["deleted_id"]),
                ).fetchone()[0]
                if duplicate_count != 1:
                    continue
                conn.execute("DELETE FROM files WHERE id=?", (pair["active_id"],))
                conn.execute(
                    """
                    UPDATE files
                    SET path=?, relative_path=?, mtime_ns=?, state=?, updated_at=?
                    WHERE id=?
                    """,
                    (
                        pair["active_path"],
                        pair["active_relative_path"],
                        pair["active_mtime_ns"],
                        pair["active_state"],
                        now,
                        pair["deleted_id"],
                    ),
                )
                conn.execute(
                    "INSERT INTO events(ts, level, event_type, message, file_id, data) VALUES(?,?,?,?,?,?)",
                    (
                        now,
                        "info",
                        "scan.move",
                        f"Reconciled moved file path: {pair['deleted_path']} -> {pair['active_path']}",
                        pair["deleted_id"],
                        "",
                    ),
                )
                reconciled += 1
        return reconciled

    def queue_file(self, file_id: int, priority: int = 100, reason: str = "manual") -> None:
        now = utcnow()
        with self.connect() as conn:
            file_row = conn.execute("SELECT state FROM files WHERE id=?", (file_id,)).fetchone()
            if not file_row or file_row["state"] in {"backed_up", "deleted", "posting"}:
                return
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
                  AND f.state NOT IN ('backed_up', 'deleted', 'posting')
                ORDER BY q.priority ASC, q.position ASC
                LIMIT 1
                """
            ).fetchone()

    def list_queue(self, include_done: bool = False) -> List[sqlite3.Row]:
        where = "" if include_done else "WHERE q.status != 'done' AND f.state != 'backed_up'"
        with self.connect() as conn:
            return conn.execute(
                f"""
                SELECT q.*, f.path, f.size, f.state FROM queue q
                JOIN files f ON f.id = q.file_id
                {where}
                ORDER BY q.priority ASC, q.position ASC
                """
            ).fetchall()

    def cleanup_completed_queue(self) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                """
                UPDATE queue
                SET status='done', updated_at=?
                WHERE file_id IN (SELECT id FROM files WHERE state='backed_up')
                  AND status != 'done'
                """,
                (utcnow(),),
            )
            return cur.rowcount

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

    def clear_chunks(self, file_id: int) -> int:
        with self.connect() as conn:
            cur = conn.execute("DELETE FROM chunks WHERE file_id=?", (file_id,))
            return cur.rowcount

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

    def speed_samples(self, minutes: int = 30, bucket_seconds: int = 60) -> List[Dict[str, Any]]:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        start = now - timedelta(minutes=minutes)
        buckets: Dict[str, Dict[str, Any]] = {}
        cursor = start
        while cursor <= now:
            bucket_start = cursor - timedelta(seconds=cursor.timestamp() % bucket_seconds)
            key = bucket_start.isoformat()
            buckets[key] = {"ts": key, "upload_bps": 0.0, "download_bps": 0.0}
            cursor += timedelta(seconds=bucket_seconds)
        with self.connect() as conn:
            posted = conn.execute(
                "SELECT posted_at, size FROM chunks WHERE posted_at >= ?",
                (start.isoformat(),),
            ).fetchall()
            verified = conn.execute(
                "SELECT verified_at, size FROM chunks WHERE verified_at IS NOT NULL AND verified_at >= ?",
                (start.isoformat(),),
            ).fetchall()
        for row in posted:
            key = self._bucket_key(row["posted_at"], bucket_seconds)
            buckets.setdefault(key, {"ts": key, "upload_bps": 0.0, "download_bps": 0.0})
            buckets[key]["upload_bps"] += row["size"] / bucket_seconds
        for row in verified:
            key = self._bucket_key(row["verified_at"], bucket_seconds)
            buckets.setdefault(key, {"ts": key, "upload_bps": 0.0, "download_bps": 0.0})
            buckets[key]["download_bps"] += row["size"] / bucket_seconds
        return [buckets[key] for key in sorted(buckets)]

    def _bucket_key(self, timestamp: str, bucket_seconds: int) -> str:
        dt = datetime.fromisoformat(timestamp)
        bucket_start = dt - timedelta(seconds=dt.timestamp() % bucket_seconds)
        return bucket_start.replace(microsecond=0).isoformat()

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
