import json
import sqlite3
import gzip
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional


SCHEMA_VERSION = 10
STALE_POSTING_SECONDS = 15 * 60
SQLITE_TIMEOUT_SECONDS = 30
SQLITE_BUSY_TIMEOUT_MS = SQLITE_TIMEOUT_SECONDS * 1000


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class Database:
    def __init__(self, path: Path, event_forwarder: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.path = Path(path)
        self.event_forwarder = event_forwarder

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=SQLITE_TIMEOUT_SECONDS)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init(self) -> None:
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.executescript(SCHEMA)
            self._migrate(conn)
            conn.execute(
                "INSERT OR REPLACE INTO app_meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            conn.execute(
                """
                INSERT OR IGNORE INTO schema_migrations(version, name, applied_at)
                VALUES(?,?,?)
                """,
                (SCHEMA_VERSION, f"schema-{SCHEMA_VERSION}", utcnow()),
            )

    def _migrate(self, conn: sqlite3.Connection) -> None:
        queue_columns = {row["name"] for row in conn.execute("PRAGMA table_info(queue)").fetchall()}
        if "progress_chunks" not in queue_columns:
            conn.execute("ALTER TABLE queue ADD COLUMN progress_chunks INTEGER NOT NULL DEFAULT 0")
        if "progress_bytes" not in queue_columns:
            conn.execute("ALTER TABLE queue ADD COLUMN progress_bytes INTEGER NOT NULL DEFAULT 0")
        chunk_columns = {row["name"] for row in conn.execute("PRAGMA table_info(chunks)").fetchall()}
        if "article_size" not in chunk_columns:
            conn.execute("ALTER TABLE chunks ADD COLUMN article_size INTEGER")
        manifest_columns = {row["name"] for row in conn.execute("PRAGMA table_info(chunk_manifests)").fetchall()}
        if manifest_columns and "missing_count" not in manifest_columns:
            conn.execute("ALTER TABLE chunk_manifests ADD COLUMN missing_count INTEGER NOT NULL DEFAULT 0")
        host_stats_columns = {row["name"] for row in conn.execute("PRAGMA table_info(host_stats)").fetchall()}
        if host_stats_columns and "article_size_bytes" not in host_stats_columns:
            conn.execute("ALTER TABLE host_stats ADD COLUMN article_size_bytes INTEGER")
        file_columns = {row["name"] for row in conn.execute("PRAGMA table_info(files)").fetchall()}
        if "backup_uncompressed_size" not in file_columns:
            conn.execute("ALTER TABLE files ADD COLUMN backup_uncompressed_size INTEGER NOT NULL DEFAULT 0")
        if "backup_compressed_size" not in file_columns:
            conn.execute("ALTER TABLE files ADD COLUMN backup_compressed_size INTEGER NOT NULL DEFAULT 0")
        if "backup_compressed" not in file_columns:
            conn.execute("ALTER TABLE files ADD COLUMN backup_compressed INTEGER NOT NULL DEFAULT 0")
        if "backup_par2" not in file_columns:
            conn.execute("ALTER TABLE files ADD COLUMN backup_par2 INTEGER NOT NULL DEFAULT 0")
        self._create_operational_tables(conn)

    def _create_operational_tables(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS transfer_samples (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts TEXT NOT NULL,
              direction TEXT NOT NULL,
              size INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS backup_runs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              file_id INTEGER REFERENCES files(id) ON DELETE SET NULL,
              path TEXT NOT NULL,
              status TEXT NOT NULL,
              reason TEXT NOT NULL DEFAULT '',
              host TEXT NOT NULL DEFAULT '',
              started_at TEXT NOT NULL,
              finished_at TEXT,
              chunks_total INTEGER NOT NULL DEFAULT 0,
              chunks_done INTEGER NOT NULL DEFAULT 0,
              bytes_total INTEGER NOT NULL DEFAULT 0,
              bytes_done INTEGER NOT NULL DEFAULT 0,
              error TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS host_stats (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              host_name TEXT NOT NULL,
              mode TEXT NOT NULL,
              status TEXT NOT NULL,
              message TEXT NOT NULL DEFAULT '',
              latency_ms INTEGER,
              article_size_bytes INTEGER,
              checked_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS maintenance_runs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              kind TEXT NOT NULL,
              started_at TEXT NOT NULL,
              finished_at TEXT NOT NULL,
              result TEXT NOT NULL,
              details TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS restore_drills (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              file_id INTEGER REFERENCES files(id) ON DELETE SET NULL,
              path TEXT NOT NULL,
              status TEXT NOT NULL,
              checked_at TEXT NOT NULL,
              bytes_checked INTEGER NOT NULL DEFAULT 0,
              message TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS backup_manifests (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              file_id INTEGER REFERENCES files(id) ON DELETE SET NULL,
              backup_run_id INTEGER REFERENCES backup_runs(id) ON DELETE SET NULL,
              path TEXT NOT NULL,
              file_sha256 TEXT NOT NULL DEFAULT '',
              app_version TEXT NOT NULL DEFAULT '',
              article_size INTEGER NOT NULL DEFAULT 0,
              chunk_count INTEGER NOT NULL DEFAULT 0,
              bytes_total INTEGER NOT NULL DEFAULT 0,
              flags TEXT NOT NULL DEFAULT '',
              manifest_json TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS worker_state (
              kind TEXT PRIMARY KEY,
              name TEXT NOT NULL DEFAULT '',
              next_run_at TEXT NOT NULL DEFAULT '',
              last_started_at TEXT NOT NULL DEFAULT '',
              last_finished_at TEXT NOT NULL DEFAULT '',
              last_duration_seconds REAL,
              last_result TEXT NOT NULL DEFAULT '',
              last_error TEXT NOT NULL DEFAULT '',
              runs INTEGER NOT NULL DEFAULT 0,
              revision INTEGER NOT NULL DEFAULT 0,
              updated_at TEXT NOT NULL
            )
            """
        )

    def get_meta(self, key: str) -> Optional[str]:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM app_meta WHERE key=?", (key,)).fetchone()
            return None if row is None else str(row["value"])

    def set_meta(self, key: str, value: str) -> None:
        with self.connect() as conn:
            conn.execute("INSERT OR REPLACE INTO app_meta(key, value) VALUES(?,?)", (key, value))

    def paused_kinds(self) -> List[str]:
        with self.connect() as conn:
            rows = conn.execute("SELECT key FROM app_meta WHERE key LIKE 'pause.%' AND value='1'").fetchall()
            return [str(row["key"]).removeprefix("pause.") for row in rows]

    def set_paused(self, kind: str, paused: bool) -> None:
        self.set_meta(f"pause.{kind}", "1" if paused else "0")
        self.log("info", "worker.pause", f"{'Paused' if paused else 'Resumed'} {kind} worker")

    def is_paused(self, kind: str) -> bool:
        return self.get_meta(f"pause.{kind}") == "1"

    def worker_state(self, kind: str) -> Optional[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute("SELECT * FROM worker_state WHERE kind=?", (kind,)).fetchone()

    def worker_state_rows(self) -> List[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute("SELECT * FROM worker_state ORDER BY kind").fetchall()

    def clear_worker_error(self, kind: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE worker_state SET last_error='', revision=revision+1, updated_at=? WHERE kind=?",
                (utcnow(), kind),
            )

    def save_worker_state(
        self,
        kind: str,
        name: str,
        next_run_at: str,
        last_started_at: str,
        last_finished_at: str,
        last_duration_seconds: Optional[float],
        last_result: str,
        last_error: str,
        runs: int,
        revision: int,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO worker_state(
                  kind, name, next_run_at, last_started_at, last_finished_at,
                  last_duration_seconds, last_result, last_error, runs, revision, updated_at
                )
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(kind) DO UPDATE SET
                  name=excluded.name,
                  next_run_at=excluded.next_run_at,
                  last_started_at=excluded.last_started_at,
                  last_finished_at=excluded.last_finished_at,
                  last_duration_seconds=excluded.last_duration_seconds,
                  last_result=excluded.last_result,
                  last_error=excluded.last_error,
                  runs=excluded.runs,
                  revision=excluded.revision,
                  updated_at=excluded.updated_at
                """,
                (
                    kind,
                    name,
                    next_run_at,
                    last_started_at,
                    last_finished_at,
                    last_duration_seconds,
                    last_result,
                    last_error,
                    int(runs),
                    int(revision),
                    utcnow(),
                ),
            )

    def log(self, level: str, event_type: str, message: str, file_id: Optional[int] = None, data: str = "") -> None:
        event = {"ts": utcnow(), "level": level, "event_type": event_type, "message": message, "file_id": file_id, "data": data}
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO events(ts, level, event_type, message, file_id, data) VALUES(?,?,?,?,?,?)",
                (event["ts"], level, event_type, message, file_id, data),
            )
        if self.event_forwarder:
            self.event_forwarder(event)

    def add_endpoint(self, path: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO endpoints(path, created_at) VALUES(?,?)",
                (str(Path(path).resolve()), utcnow()),
            )

    def endpoints(self) -> List[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute("SELECT * FROM endpoints ORDER BY path").fetchall()

    def endpoint_file_snapshot(self, endpoint_id: int) -> Dict[str, Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, path, relative_path, size, mtime_ns, sha256, state FROM files WHERE endpoint_id=?",
                (endpoint_id,),
            ).fetchall()
            return {str(row["path"]): dict(row) for row in rows}

    def upsert_file(self, record: Dict[str, Any]) -> int:
        now = utcnow()
        incoming_sha = str(record.get("sha256") or "")
        with self.connect() as conn:
            row = conn.execute("SELECT id, size, mtime_ns, sha256, state FROM files WHERE path = ?", (record["path"],)).fetchone()
            if row:
                metadata_changed = row["mtime_ns"] != record["mtime_ns"]
                if incoming_sha:
                    content_changed = row["size"] != record["size"] or row["sha256"] != incoming_sha
                elif row["state"] == "backed_up" and row["size"] == record["size"]:
                    content_changed = False
                else:
                    content_changed = row["size"] != record["size"] or metadata_changed
                revived = row["state"] in {"deleted", "unreadable"}
                state = "changed" if content_changed else record.get("state", "discovered")
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
                        incoming_sha if content_changed or revived or incoming_sha else row["sha256"],
                        1 if content_changed or revived else 0,
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
                        incoming_sha,
                        record.get("state", "discovered"),
                        now,
                        now,
                    ),
                )
                file_id = int(cur.lastrowid)
            return file_id

    def update_moved_file(self, file_id: int, path: str, relative_path: str, mtime_ns: int, state: str = "discovered") -> None:
        now = utcnow()
        with self.connect() as conn:
            row = conn.execute("SELECT path, state FROM files WHERE id=?", (file_id,)).fetchone()
            if not row:
                return
            conn.execute(
                """
                UPDATE files
                SET path=?, relative_path=?, mtime_ns=?, state=CASE WHEN state='deleted' THEN ? ELSE state END,
                    updated_at=?
                WHERE id=?
                """,
                (path, relative_path, mtime_ns, state, now, file_id),
            )
            conn.execute(
                "INSERT INTO events(ts, level, event_type, message, file_id, data) VALUES(?,?,?,?,?,?)",
                (now, "info", "scan.move", f"Updated moved file path: {row['path']} -> {path}", file_id, ""),
            )

    def _find_move_candidate(self, conn: sqlite3.Connection, record: Dict[str, Any]) -> Optional[sqlite3.Row]:
        if not str(record.get("sha256") or ""):
            return None
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
                 AND active.sha256 != ''
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
            if not file_row or file_row["state"] in {"backed_up", "deleted", "posting", "unreadable"}:
                return
            row = conn.execute("SELECT COALESCE(MAX(position), 0) + 1 AS next_pos FROM queue").fetchone()
            conn.execute(
                """
                INSERT INTO queue(file_id, priority, position, status, reason, created_at, updated_at)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(file_id) DO UPDATE SET
                  priority=excluded.priority, status='queued', reason=excluded.reason,
                  progress_chunks=0, progress_bytes=0, updated_at=excluded.updated_at
                """,
                (file_id, priority, row["next_pos"], "queued", reason, now, now),
            )
            conn.execute("UPDATE files SET state='queued', updated_at=? WHERE id=?", (now, file_id))

    def next_queue_item(self) -> Optional[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(
                """
                SELECT q.*, f.path, f.size, f.mtime_ns, f.sha256, f.state FROM queue q
                JOIN files f ON f.id = q.file_id
                WHERE q.status='queued'
                  AND f.state NOT IN ('backed_up', 'deleted', 'posting', 'unreadable')
                ORDER BY q.priority ASC, q.position ASC
                LIMIT 1
                """
            ).fetchone()

    def list_queue(self, include_done: bool = False, status: Optional[str] = None, limit: int = 200, offset: int = 0) -> List[sqlite3.Row]:
        return self.list_queue_sorted(include_done, status, limit, offset)

    def list_queue_sorted(
        self,
        include_done: bool = False,
        status: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
        sort_by: str = "",
        sort_dir: str = "asc",
    ) -> List[sqlite3.Row]:
        where_parts = []
        params: List[Any] = []
        if status == "attention":
            where_parts.append(
                """
                (q.status='failed'
                 OR (q.status!='done' AND q.reason IN ('network-blocked', 'missing-chunks', 'file-changing')))
                """
            )
        elif status:
            where_parts.append("q.status = ?")
            params.append(status)
        elif not include_done:
            where_parts.append("q.status NOT IN ('done', 'failed')")
            where_parts.append("f.state NOT IN ('backed_up', 'failed', 'unreadable')")
        where = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""
        sort_columns = {
            "file_id": "q.file_id",
            "position": "q.position",
            "priority": "q.priority",
            "status": "q.status",
            "reason": "q.reason",
            "path": "f.path",
            "relative_path": "f.relative_path",
            "size": "f.size",
            "progress": "posted_chunks",
            "chunk_count": "posted_chunks",
            "state": "f.state",
            "updated_at": "q.updated_at",
            "created_at": "q.created_at",
        }
        direction = "DESC" if str(sort_dir).lower() == "desc" else "ASC"
        if sort_by in sort_columns:
            order_by = f"{sort_columns[sort_by]} {direction}, q.id ASC"
        else:
            order_by = "q.updated_at ASC, q.id ASC" if status == "done" else "q.priority ASC, q.position ASC"
        with self.connect() as conn:
            return conn.execute(
                f"""
                SELECT q.*, f.path, f.relative_path, f.size, f.state,
                       CASE WHEN q.status='posting' THEN q.progress_chunks ELSE COUNT(c.id) + COALESCE(cm.chunk_count, 0) END AS posted_chunks,
                       CASE WHEN q.status='posting' THEN q.progress_bytes ELSE COALESCE(SUM(c.size), 0) + COALESCE(cm.bytes_total, 0) END AS posted_bytes
                FROM queue q
                JOIN files f ON f.id = q.file_id
                LEFT JOIN chunks c ON c.file_id = f.id
                LEFT JOIN chunk_manifests cm ON cm.file_id = f.id
                {where}
                GROUP BY q.id
                ORDER BY {order_by}
                LIMIT ? OFFSET ?
                """
                ,
                (*params, limit, offset),
            ).fetchall()

    def queue_count(self, include_done: bool = False, status: Optional[str] = None) -> int:
        where_parts = []
        params: List[Any] = []
        if status == "attention":
            where_parts.append(
                """
                (q.status='failed'
                 OR (q.status!='done' AND q.reason IN ('network-blocked', 'missing-chunks', 'file-changing')))
                """
            )
        elif status:
            where_parts.append("q.status = ?")
            params.append(status)
        elif not include_done:
            where_parts.append("q.status NOT IN ('done', 'failed')")
            where_parts.append("f.state NOT IN ('backed_up', 'failed', 'unreadable')")
        where = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""
        with self.connect() as conn:
            return int(
                conn.execute(
                    f"""
                    SELECT COUNT(*) FROM queue q
                    JOIN files f ON f.id = q.file_id
                    {where}
                    """,
                    params,
                ).fetchone()[0]
            )

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

    def recover_stale_posting(self, stale_after_seconds: int = STALE_POSTING_SECONDS) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=stale_after_seconds)).replace(microsecond=0).isoformat()
        return self._recover_posting_rows(
            "q.status='posting' AND q.updated_at <= ?",
            (cutoff,),
            "stale-posting-retry",
            "Recovered stale posting queue item",
        )

    def recover_interrupted_posting(self) -> int:
        return self._recover_posting_rows(
            "q.status='posting'",
            (),
            "startup-posting-retry",
            "Recovered interrupted posting queue item after startup",
        )

    def _recover_posting_rows(self, where_clause: str, params: Iterable[Any], reason: str, message_prefix: str) -> int:
        now = utcnow()
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT q.file_id, f.path FROM queue q
                JOIN files f ON f.id = q.file_id
                WHERE {where_clause}
                """,
                tuple(params),
            ).fetchall()
            for row in rows:
                conn.execute(
                    """
                    UPDATE queue
                    SET status='queued', reason=?, progress_chunks=0, progress_bytes=0, updated_at=?
                    WHERE file_id=?
                    """,
                    (reason, now, row["file_id"]),
                )
                conn.execute("UPDATE files SET state='queued', updated_at=? WHERE id=?", (now, row["file_id"]))
                conn.execute(
                    "INSERT INTO events(ts, level, event_type, message, file_id, data) VALUES(?,?,?,?,?,?)",
                    (now, "warning", "queue.recover", f"{message_prefix}: {row['path']}", row["file_id"], ""),
                )
            return len(rows)

    def recover_queued_failed_mismatches(self) -> int:
        now = utcnow()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT q.file_id, f.path FROM queue q
                JOIN files f ON f.id = q.file_id
                WHERE q.status='failed' AND f.state='queued'
                """
            ).fetchall()
            for row in rows:
                conn.execute(
                    """
                    UPDATE queue
                    SET status='queued', reason='queued-state-recovery',
                        progress_chunks=0, progress_bytes=0, updated_at=?
                    WHERE file_id=?
                    """,
                    (now, row["file_id"]),
                )
                conn.execute(
                    "INSERT INTO events(ts, level, event_type, message, file_id, data) VALUES(?,?,?,?,?,?)",
                    (now, "warning", "queue.recover", f"Recovered failed queue row for queued file: {row['path']}", row["file_id"], ""),
                )
            return len(rows)

    def recover_retryable_failed(self) -> int:
        now = utcnow()
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT q.file_id, f.path FROM queue q
                JOIN files f ON f.id = q.file_id
                WHERE q.status='failed'
                  AND f.state='failed'
                  AND f.id NOT IN (SELECT DISTINCT file_id FROM chunks)
                """
            ).fetchall()
            for row in rows:
                conn.execute(
                    """
                    UPDATE queue
                    SET status='queued', reason='failed-retry',
                        progress_chunks=0, progress_bytes=0, updated_at=?
                    WHERE file_id=?
                    """,
                    (now, row["file_id"]),
                )
                conn.execute("UPDATE files SET state='queued', updated_at=? WHERE id=?", (now, row["file_id"]))
                conn.execute(
                    "INSERT INTO events(ts, level, event_type, message, file_id, data) VALUES(?,?,?,?,?,?)",
                    (now, "warning", "queue.recover", f"Recovered failed queue item for retry: {row['path']}", row["file_id"], ""),
                )
            return len(rows)

    def set_queue_status(self, file_id: int, status: str) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE queue SET status=?, updated_at=? WHERE file_id=?", (status, utcnow(), file_id))

    def requeue_file(self, file_id: int, reason: str) -> None:
        now = utcnow()
        with self.connect() as conn:
            conn.execute(
                "UPDATE queue SET status='queued', reason=?, updated_at=? WHERE file_id=?",
                (reason, now, file_id),
            )
            conn.execute("UPDATE files SET state='queued', updated_at=? WHERE id=?", (now, file_id))

    def set_queue_progress(self, file_id: int, chunks: int, bytes_posted: int) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE queue SET progress_chunks=?, progress_bytes=?, updated_at=? WHERE file_id=?",
                (max(0, int(chunks)), max(0, int(bytes_posted)), utcnow(), file_id),
            )

    def record_transfer_sample(self, direction: str, size: int) -> None:
        if size <= 0:
            return
        now = datetime.now(timezone.utc).replace(second=0, microsecond=0).isoformat()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT id FROM transfer_samples WHERE ts=? AND direction=? LIMIT 1",
                (now, direction),
            ).fetchone()
            if row:
                conn.execute("UPDATE transfer_samples SET size=size+? WHERE id=?", (int(size), row["id"]))
            else:
                conn.execute(
                    "INSERT INTO transfer_samples(ts, direction, size) VALUES(?,?,?)",
                    (now, direction, int(size)),
                )

    def start_backup_run(self, file_id: int, path: str, chunks_total: int, bytes_total: int, reason: str) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO backup_runs(file_id, path, status, reason, started_at, chunks_total, bytes_total)
                VALUES(?,?,?,?,?,?,?)
                """,
                (file_id, path, "running", reason, utcnow(), chunks_total, bytes_total),
            )
            return int(cur.lastrowid)

    def update_backup_run(self, run_id: int, chunks_done: int, bytes_done: int, host: str = "") -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE backup_runs SET chunks_done=?, bytes_done=?, host=COALESCE(NULLIF(?, ''), host) WHERE id=?",
                (chunks_done, bytes_done, host, run_id),
            )

    def update_backup_run_totals(self, run_id: int, chunks_total: int, bytes_total: int) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE backup_runs SET chunks_total=?, bytes_total=? WHERE id=?",
                (chunks_total, bytes_total, run_id),
            )

    def finish_backup_run(self, run_id: int, status: str, error: str = "") -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE backup_runs SET status=?, error=?, finished_at=? WHERE id=?",
                (status, error, utcnow(), run_id),
            )

    def backup_run_rows(self, limit: int = 50) -> List[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute("SELECT * FROM backup_runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def set_file_backup_features(
        self,
        file_id: int,
        uncompressed_size: int,
        compressed_size: int,
        compressed: bool,
        par2: bool,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE files
                SET backup_uncompressed_size=?, backup_compressed_size=?, backup_compressed=?, backup_par2=?, updated_at=?
                WHERE id=?
                """,
                (int(uncompressed_size), int(compressed_size), int(bool(compressed)), int(bool(par2)), utcnow(), file_id),
            )

    def record_backup_manifest(self, file_id: int, backup_run_id: Optional[int], manifest: Dict[str, Any]) -> None:
        flags = ",".join(str(item) for item in manifest.get("flags", []))
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO backup_manifests(
                  file_id, backup_run_id, path, file_sha256, app_version, article_size,
                  chunk_count, bytes_total, flags, manifest_json, created_at
                )
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    file_id,
                    backup_run_id,
                    str(manifest.get("path", "")),
                    str(manifest.get("file_sha256", "")),
                    str(manifest.get("app_version", "")),
                    int(manifest.get("article_size", 0) or 0),
                    int(manifest.get("chunk_count", 0) or 0),
                    int(manifest.get("bytes_total", 0) or 0),
                    flags,
                    json.dumps(manifest, sort_keys=True),
                    utcnow(),
                ),
            )

    def backup_manifest_rows(self, limit: int = 50) -> List[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute("SELECT * FROM backup_manifests ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def record_host_check(
        self,
        host_name: str,
        mode: str,
        status: str,
        message: str = "",
        latency_ms: Optional[int] = None,
        article_size_bytes: Optional[int] = None,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO host_stats(host_name, mode, status, message, latency_ms, article_size_bytes, checked_at) VALUES(?,?,?,?,?,?,?)",
                (host_name, mode, status, message, latency_ms, article_size_bytes, utcnow()),
            )

    def host_health_rows(self, limit: int = 50) -> List[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute("SELECT * FROM host_stats ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def recent_host_failure_count(self, host_name: str, mode: str = "post", limit: int = 10, message_like: str = "") -> int:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT status, message FROM host_stats
                WHERE host_name=? AND mode=?
                ORDER BY id DESC
                LIMIT ?
                """,
                (host_name, mode, max(1, int(limit))),
            ).fetchall()
        failures = 0
        for row in rows:
            if row["status"] != "failed":
                break
            if message_like and message_like not in str(row["message"]):
                break
            failures += 1
        return failures

    def provider_profiles(self) -> List[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(
                """
                SELECT host_name, mode,
                       COUNT(*) AS checks,
                       SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) AS failures,
                       MAX(article_size_bytes) AS max_article_size_bytes,
                       ROUND(AVG(latency_ms), 1) AS avg_latency_ms,
                       MAX(checked_at) AS last_checked_at
                FROM host_stats
                GROUP BY host_name, mode
                ORDER BY host_name, mode
                """
            ).fetchall()

    def record_maintenance(self, kind: str, started_at: str, result: str, details: str = "") -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO maintenance_runs(kind, started_at, finished_at, result, details) VALUES(?,?,?,?,?)",
                (kind, started_at, utcnow(), result, details),
            )

    def maintenance_rows(self, limit: int = 50) -> List[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute("SELECT * FROM maintenance_runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def prune_events(self, log_retention_days: int, verbose_retention_days: int) -> int:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        general_cutoff = (now - timedelta(days=log_retention_days)).isoformat()
        verbose_cutoff = (now - timedelta(days=verbose_retention_days)).isoformat()
        with self.connect() as conn:
            cur = conn.execute(
                """
                DELETE FROM events
                WHERE ts < ?
                   OR (level IN ('debug', 'verbose') AND ts < ?)
                """,
                (general_cutoff, verbose_cutoff),
            )
            return int(cur.rowcount)

    def compact_transfer_samples(self) -> int:
        with self.connect() as conn:
            before = int(conn.execute("SELECT COUNT(*) FROM transfer_samples").fetchone()[0])
            rows = conn.execute(
                """
                SELECT substr(ts, 1, 16) || ':00+00:00' AS bucket, direction, SUM(size) AS size
                FROM transfer_samples
                GROUP BY bucket, direction
                """
            ).fetchall()
            conn.execute("DELETE FROM transfer_samples")
            conn.executemany(
                "INSERT INTO transfer_samples(ts, direction, size) VALUES(?,?,?)",
                [(row["bucket"], row["direction"], int(row["size"] or 0)) for row in rows],
            )
            return max(0, before - len(rows))

    def vacuum_analyze(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            conn.execute("ANALYZE")
            conn.execute("VACUUM")
        finally:
            conn.close()

    def restore_drill_candidate(self) -> Optional[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(
                """
                SELECT f.*
                FROM files f
                LEFT JOIN chunks c ON c.file_id = f.id
                LEFT JOIN chunk_manifests cm ON cm.file_id = f.id
                LEFT JOIN restore_drills rd ON rd.file_id = f.id
                WHERE f.state='backed_up'
                  AND (c.file_id IS NOT NULL OR cm.file_id IS NOT NULL)
                GROUP BY f.id
                ORDER BY MAX(rd.checked_at) IS NOT NULL ASC,
                         COALESCE(MAX(rd.checked_at), f.last_verify_at, f.last_backup_at, f.updated_at) ASC,
                         f.backup_compressed DESC,
                         f.backup_par2 DESC,
                         f.size DESC
                LIMIT 1
                """
            ).fetchone()

    def record_restore_drill(self, file_id: Optional[int], path: str, status: str, bytes_checked: int, message: str = "") -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO restore_drills(file_id, path, status, checked_at, bytes_checked, message) VALUES(?,?,?,?,?,?)",
                (file_id, path, status, utcnow(), bytes_checked, message),
            )

    def restore_drill_rows(self, limit: int = 50) -> List[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute("SELECT * FROM restore_drills ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def transfer_bytes_since(self, direction: str, since: str) -> int:
        with self.connect() as conn:
            return int(
                conn.execute(
                    "SELECT COALESCE(SUM(size), 0) FROM transfer_samples WHERE direction=? AND ts >= ?",
                    (direction, since),
                ).fetchone()[0]
            )

    def boost_queue_priority(self, file_id: int, amount: int = 10, reason: str = "manual-priority") -> None:
        should_queue = False
        with self.connect() as conn:
            file_row = conn.execute("SELECT state FROM files WHERE id=?", (file_id,)).fetchone()
            if not file_row or file_row["state"] in {"backed_up", "deleted", "unreadable"}:
                return
            queue_row = conn.execute("SELECT priority FROM queue WHERE file_id=?", (file_id,)).fetchone()
            if not queue_row:
                should_queue = True
            else:
                conn.execute(
                    "UPDATE queue SET priority=?, status=CASE WHEN status='done' THEN 'queued' ELSE status END, updated_at=? WHERE file_id=?",
                    (max(0, int(queue_row["priority"]) - amount), utcnow(), file_id),
                )
                conn.execute(
                    "UPDATE files SET state=CASE WHEN state IN ('posting', 'backed_up') THEN state ELSE 'queued' END, updated_at=? WHERE id=?",
                    (utcnow(), file_id),
                )
        if should_queue:
            self.queue_file(file_id, priority=90, reason=reason)

    def boost_folder_priority(self, folder_path: str, amount: int = 10) -> int:
        raw = folder_path.rstrip("\\/")
        alt = raw.replace("/", "\\")
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT id FROM files
                WHERE state NOT IN ('backed_up', 'deleted', 'unreadable')
                  AND (path LIKE ? OR relative_path = ? OR relative_path LIKE ? OR relative_path = ? OR relative_path LIKE ?)
                ORDER BY relative_path
                """,
                (raw + "%", raw, raw + "/%", alt, alt + "\\%"),
            ).fetchall()
        for row in rows:
            self.boost_queue_priority(int(row["id"]), amount=amount, reason="folder-priority")
        if rows:
            self.log("info", "queue.priority", f"Boosted queue priority for {len(rows)} files under {folder_path}")
        return len(rows)

    def add_chunk(
        self,
        file_id: int,
        chunk_index: int,
        message_id: str,
        size: int,
        sha256: str,
        subject: str,
        article_size: Optional[int] = None,
    ) -> None:
        now = utcnow()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO chunks(file_id, chunk_index, message_id, size, sha256, subject, status, posted_at, article_size)
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(file_id, chunk_index) DO UPDATE SET
                  message_id=excluded.message_id, size=excluded.size, sha256=excluded.sha256,
                  subject=excluded.subject, status=excluded.status, posted_at=excluded.posted_at,
                  article_size=excluded.article_size, verified_at=NULL
                """,
                (file_id, chunk_index, message_id, size, sha256, subject, "posted", now, article_size),
            )
            conn.execute("UPDATE queue SET updated_at=? WHERE file_id=?", (now, file_id))
            conn.execute("UPDATE files SET updated_at=? WHERE id=?", (now, file_id))
            row = conn.execute(
                "SELECT id FROM transfer_samples WHERE ts=? AND direction='upload' LIMIT 1",
                (now[:16] + ":00+00:00",),
            ).fetchone()
            if row:
                conn.execute("UPDATE transfer_samples SET size=size+? WHERE id=?", (int(size), row["id"]))
            else:
                conn.execute(
                    "INSERT INTO transfer_samples(ts, direction, size) VALUES(?,?,?)",
                    (now[:16] + ":00+00:00", "upload", int(size)),
                )

    def _manifest_blob(self, chunks: Iterable[Dict[str, Any]]) -> bytes:
        persisted = []
        for chunk in chunks:
            persisted.append(
                {
                    "chunk_index": int(chunk["chunk_index"]),
                    "message_id": chunk["message_id"],
                    "size": int(chunk["size"]),
                    "sha256": chunk.get("sha256", ""),
                    "subject": chunk.get("subject", ""),
                    "status": chunk.get("status", "posted"),
                    "posted_at": chunk.get("posted_at"),
                    "article_size": chunk.get("article_size"),
                    "verified_at": chunk.get("verified_at"),
                }
            )
        payload = json.dumps(persisted, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return gzip.compress(payload, compresslevel=6)

    def _manifest_entries(self, row: sqlite3.Row) -> List[Dict[str, Any]]:
        entries = json.loads(gzip.decompress(row["manifest_blob"]).decode("utf-8"))
        file_id = int(row["file_id"])
        for entry in entries:
            entry["file_id"] = file_id
            entry["id"] = f"manifest:{file_id}:{int(entry['chunk_index'])}"
        return entries

    def compact_chunks_to_manifest(self, file_id: int) -> int:
        now = utcnow()
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM chunks WHERE file_id=? ORDER BY chunk_index", (file_id,)).fetchall()
            if not rows:
                return 0
            entries = [
                {
                    "chunk_index": int(row["chunk_index"]),
                    "message_id": row["message_id"],
                    "size": int(row["size"]),
                    "sha256": row["sha256"],
                    "subject": row["subject"],
                    "status": row["status"],
                    "posted_at": row["posted_at"],
                    "article_size": row["article_size"],
                    "verified_at": row["verified_at"],
                }
                for row in rows
            ]
            chunk_count = len(entries)
            bytes_total = sum(int(entry["size"]) for entry in entries)
            verified_count = sum(1 for entry in entries if entry["status"] == "verified")
            missing_count = sum(1 for entry in entries if entry["status"] == "missing")
            article_size = next((entry["article_size"] for entry in entries if entry.get("article_size")), None)
            conn.execute(
                """
                INSERT INTO chunk_manifests(file_id, chunk_count, bytes_total, article_size, verified_count, missing_count, manifest_blob, created_at, updated_at)
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(file_id) DO UPDATE SET
                  chunk_count=excluded.chunk_count,
                  bytes_total=excluded.bytes_total,
                  article_size=excluded.article_size,
                  verified_count=excluded.verified_count,
                  missing_count=excluded.missing_count,
                  manifest_blob=excluded.manifest_blob,
                  updated_at=excluded.updated_at
                """,
                (file_id, chunk_count, bytes_total, article_size, verified_count, missing_count, self._manifest_blob(entries), now, now),
            )
            conn.execute("DELETE FROM chunks WHERE file_id=?", (file_id,))
            conn.execute("UPDATE files SET updated_at=? WHERE id=?", (now, file_id))
            return chunk_count

    def chunk_manifest_entries_for_file(self, file_id: int) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM chunk_manifests WHERE file_id=?", (file_id,)).fetchone()
            return [] if row is None else self._manifest_entries(row)

    def reusable_chunk_indexes(self, file_id: int, article_size: int) -> Dict[int, int]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT chunk_index, size
                FROM chunks
                WHERE file_id=? AND status != 'missing' AND article_size=?
                """,
                (file_id, int(article_size)),
            ).fetchall()
            return {int(row["chunk_index"]): int(row["size"]) for row in rows}

    def chunk_count_for_file(self, file_id: int) -> int:
        with self.connect() as conn:
            live = int(conn.execute("SELECT COUNT(*) FROM chunks WHERE file_id=?", (file_id,)).fetchone()[0])
            if live:
                return live
            row = conn.execute("SELECT chunk_count FROM chunk_manifests WHERE file_id=?", (file_id,)).fetchone()
            return 0 if row is None else int(row["chunk_count"])

    def replace_chunks(self, file_id: int, chunks: Iterable[Dict[str, Any]]) -> int:
        now = utcnow()
        chunk_rows = list(chunks)
        with self.connect() as conn:
            conn.execute("DELETE FROM chunks WHERE file_id=?", (file_id,))
            conn.execute("DELETE FROM chunk_manifests WHERE file_id=?", (file_id,))
            conn.executemany(
                """
                INSERT INTO chunks(file_id, chunk_index, message_id, size, sha256, subject, status, posted_at, article_size)
                VALUES(?,?,?,?,?,?,?,?,?)
                """,
                [
                    (
                        file_id,
                        int(chunk["chunk_index"]),
                        str(chunk["message_id"]),
                        int(chunk["size"]),
                        str(chunk["sha256"]),
                        str(chunk["subject"]),
                        "posted",
                        now,
                        chunk.get("article_size"),
                    )
                    for chunk in chunk_rows
                ],
            )
            conn.execute("UPDATE queue SET updated_at=? WHERE file_id=?", (now, file_id))
            conn.execute("UPDATE files SET updated_at=? WHERE id=?", (now, file_id))
        return len(chunk_rows)

    def clear_chunks(self, file_id: int) -> int:
        with self.connect() as conn:
            cur = conn.execute("DELETE FROM chunks WHERE file_id=?", (file_id,))
            manifest = conn.execute("DELETE FROM chunk_manifests WHERE file_id=?", (file_id,))
            return cur.rowcount + manifest.rowcount

    def trim_chunks(self, file_id: int, expected_chunks: int) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                "DELETE FROM chunks WHERE file_id=? AND chunk_index >= ?",
                (file_id, max(0, int(expected_chunks))),
            )
            return cur.rowcount

    def update_file_state(self, file_id: int, state: str) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE files SET state=?, updated_at=? WHERE id=?", (state, utcnow(), file_id))

    def mark_file_unreadable(self, path: str, reason: str) -> Optional[int]:
        now = utcnow()
        with self.connect() as conn:
            row = conn.execute("SELECT id, state FROM files WHERE path=?", (path,)).fetchone()
            if not row:
                return None
            file_id = int(row["id"])
            if row["state"] != "backed_up":
                conn.execute("UPDATE files SET state='unreadable', updated_at=? WHERE id=?", (now, file_id))
                conn.execute(
                    """
                    UPDATE queue
                    SET status='failed', reason='file-unreadable',
                        progress_chunks=0, progress_bytes=0, updated_at=?
                    WHERE file_id=? AND status IN ('queued', 'posting')
                    """,
                    (now, file_id),
                )
            conn.execute(
                "INSERT INTO events(ts, level, event_type, message, file_id, data) VALUES(?,?,?,?,?,?)",
                (now, "warning", "scan.file_error", f"Marked unreadable file on hold: {path}: {reason}", file_id, ""),
            )
            return file_id

    def update_file_hash(self, file_id: int, size: int, mtime_ns: int, sha256: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE files SET size=?, mtime_ns=?, sha256=?, updated_at=? WHERE id=?",
                (size, mtime_ns, sha256, utcnow(), file_id),
            )

    def mark_restored_backed_up(self, file_id: int, size: int, mtime_ns: int, sha256: str) -> None:
        now = utcnow()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE files
                SET size=?, mtime_ns=?, sha256=?, state='backed_up', updated_at=?
                WHERE id=?
                """,
                (size, mtime_ns, sha256, now, file_id),
            )
            conn.execute(
                "UPDATE queue SET status='done', updated_at=? WHERE file_id=? AND status != 'done'",
                (now, file_id),
            )

    def chunks_due_for_verification(self, older_than: str, include_missing: bool = False) -> List[sqlite3.Row]:
        status_clause = "1=1" if include_missing else "c.status != 'missing'"
        manifest_clause = "1=1" if include_missing else "cm.missing_count = 0"
        with self.connect() as conn:
            live = conn.execute(
                f"""
                SELECT c.*, f.path FROM chunks c
                JOIN files f ON f.id = c.file_id
                WHERE {status_clause}
                  AND (c.verified_at IS NULL OR c.verified_at <= ?)
                ORDER BY c.verified_at IS NULL DESC, c.verified_at ASC
                """,
                (older_than,),
            ).fetchall()
            compact_files = conn.execute(
                f"""
                SELECT cm.*, f.path FROM chunk_manifests cm
                JOIN files f ON f.id = cm.file_id
                WHERE {manifest_clause}
                  AND EXISTS (
                    SELECT 1 FROM files ff
                    WHERE ff.id=cm.file_id AND (ff.last_verify_at IS NULL OR ff.last_verify_at <= ?)
                  )
                ORDER BY f.last_verify_at IS NULL DESC, f.last_verify_at ASC
                """,
                (older_than,),
            ).fetchall()
        manifest_chunks: List[Dict[str, Any]] = []
        for row in compact_files:
            for entry in self._manifest_entries(row):
                if include_missing or entry.get("status") != "missing":
                    entry["path"] = row["path"]
                    manifest_chunks.append(entry)
        return list(live) + manifest_chunks

    def chunks_due_for_file_verification(self, older_than: str, file_limit: int) -> List[sqlite3.Row]:
        with self.connect() as conn:
            due_files = conn.execute(
                """
                SELECT id
                FROM (
                    SELECT f.id,
                           f.relative_path,
                           COALESCE(f.last_verify_at, f.last_backup_at, MIN(c.posted_at), f.updated_at, f.created_at) AS due_basis
                    FROM files f
                    LEFT JOIN chunks c ON c.file_id = f.id
                    LEFT JOIN chunk_manifests cm ON cm.file_id = f.id
                    WHERE f.state != 'deleted'
                      AND (c.status != 'missing' OR (cm.file_id IS NOT NULL AND cm.missing_count=0))
                    GROUP BY f.id
                )
                WHERE due_basis IS NOT NULL
                  AND due_basis <= ?
                ORDER BY due_basis ASC, relative_path ASC
                LIMIT ?
                """,
                (older_than, max(1, int(file_limit))),
            ).fetchall()
        return self.chunks_for_file_ids(row["id"] for row in due_files)

    def chunks_for_file_ids(self, file_ids: Iterable[int], include_missing: bool = False) -> List[sqlite3.Row]:
        ids = [int(file_id) for file_id in file_ids]
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        status_clause = "1=1" if include_missing else "c.status != 'missing'"
        manifest_clause = "1=1" if include_missing else "cm.missing_count=0"
        with self.connect() as conn:
            live = conn.execute(
                f"""
                SELECT c.*, f.path FROM chunks c
                JOIN files f ON f.id = c.file_id
                WHERE c.file_id IN ({placeholders})
                  AND {status_clause}
                ORDER BY c.file_id, c.chunk_index
                """,
                ids,
            ).fetchall()
            compact_rows = conn.execute(
                f"""
                SELECT cm.*, f.path FROM chunk_manifests cm
                JOIN files f ON f.id = cm.file_id
                WHERE cm.file_id IN ({placeholders})
                  AND {manifest_clause}
                ORDER BY cm.file_id
                """,
                ids,
            ).fetchall()
        manifest_chunks: List[Dict[str, Any]] = []
        for row in compact_rows:
            for entry in self._manifest_entries(row):
                if include_missing or entry.get("status") != "missing":
                    entry["path"] = row["path"]
                    manifest_chunks.append(entry)
        return list(live) + manifest_chunks

    def mark_chunk_verified(self, chunk_id: Any, exists: bool) -> None:
        status = "verified" if exists else "missing"
        missing_file_id: Optional[int] = None
        if isinstance(chunk_id, str) and chunk_id.startswith("manifest:"):
            _, file_text, index_text = chunk_id.split(":", 2)
            file_id = int(file_text)
            chunk_index = int(index_text)
            now = utcnow()
            with self.connect() as conn:
                row = conn.execute("SELECT * FROM chunk_manifests WHERE file_id=?", (file_id,)).fetchone()
                if row is None:
                    return
                entries = self._manifest_entries(row)
                for entry in entries:
                    if int(entry["chunk_index"]) == chunk_index:
                        entry["status"] = status
                        entry["verified_at"] = now
                verified_count = sum(1 for entry in entries if entry["status"] == "verified")
                missing_count = sum(1 for entry in entries if entry["status"] == "missing")
                conn.execute(
                    """
                    UPDATE chunk_manifests
                    SET verified_count=?, missing_count=?, manifest_blob=?, updated_at=?
                    WHERE file_id=?
                    """,
                    (verified_count, missing_count, self._manifest_blob(entries), now, file_id),
                )
                if not exists:
                    conn.execute("UPDATE files SET state='missing_chunks', updated_at=? WHERE id=?", (now, file_id))
                    missing_file_id = file_id
                elif missing_count == 0 and verified_count == len(entries):
                    conn.execute(
                        """
                        UPDATE files
                        SET state=CASE WHEN state IN ('missing_chunks','failed','queued') THEN 'backed_up' ELSE state END,
                            last_verify_at=?, updated_at=?
                        WHERE id=?
                        """,
                        (now, now, file_id),
                    )
                    conn.execute(
                        "UPDATE queue SET status='done', reason='verified-recovered', updated_at=? WHERE file_id=? AND reason='missing-chunks'",
                        (now, file_id),
                    )
            if missing_file_id is not None:
                self.queue_file(missing_file_id, priority=10, reason="missing-chunks")
            return
        with self.connect() as conn:
            now = utcnow()
            row = conn.execute("SELECT file_id FROM chunks WHERE id=?", (chunk_id,)).fetchone()
            conn.execute("UPDATE chunks SET status=?, verified_at=? WHERE id=?", (status, now, chunk_id))
            if row and not exists:
                conn.execute("UPDATE files SET state='missing_chunks', updated_at=? WHERE id=?", (now, row["file_id"]))
                missing_file_id = int(row["file_id"])
            elif row and exists:
                incomplete = conn.execute(
                    "SELECT COUNT(*) FROM chunks WHERE file_id=? AND status != 'verified'",
                    (row["file_id"],),
                ).fetchone()[0]
                if incomplete == 0:
                    conn.execute(
                        """
                        UPDATE files
                        SET state=CASE WHEN state IN ('missing_chunks','failed','queued') THEN 'backed_up' ELSE state END,
                            last_verify_at=?, updated_at=?
                        WHERE id=?
                        """,
                        (now, now, row["file_id"]),
                    )
                    conn.execute(
                        "UPDATE queue SET status='done', reason='verified-recovered', updated_at=? WHERE file_id=? AND reason='missing-chunks'",
                        (now, row["file_id"]),
                    )
        if missing_file_id is not None:
            self.queue_file(missing_file_id, priority=10, reason="missing-chunks")

    def list_rows(self, table: str, limit: int = 200) -> List[sqlite3.Row]:
        allowed = {"files", "events", "queue", "chunks", "chunk_manifests", "endpoints", "backup_runs", "backup_manifests", "host_stats", "maintenance_runs", "restore_drills"}
        if table not in allowed:
            raise ValueError(f"Unsupported table: {table}")
        with self.connect() as conn:
            return conn.execute(f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def table_stats(self) -> List[Dict[str, Any]]:
        tables = ["files", "chunks", "chunk_manifests", "queue", "events", "backup_runs", "backup_manifests", "host_stats", "maintenance_runs", "restore_drills", "transfer_samples"]
        with self.connect() as conn:
            page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
            page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
            rows: List[Dict[str, Any]] = []
            for table in tables:
                count = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                rows.append({"table": table, "rows": count, "estimated_bytes": 0})
            if rows:
                rows[0]["estimated_bytes"] = page_size * page_count
            return rows

    def verification_backlog_summary(self, interval_days: int) -> Dict[str, Any]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=interval_days)).replace(microsecond=0).isoformat()
        with self.connect() as conn:
            due = conn.execute(
                """
                SELECT COUNT(*) FROM files
                WHERE state='backed_up'
                  AND (
                    id IN (SELECT DISTINCT file_id FROM chunks WHERE status != 'missing')
                    OR id IN (SELECT file_id FROM chunk_manifests WHERE missing_count=0)
                  )
                  AND (last_verify_at IS NULL OR last_verify_at <= ?)
                """,
                (cutoff,),
            ).fetchone()[0]
            oldest = conn.execute(
                """
                SELECT MIN(COALESCE(last_verify_at, last_backup_at, updated_at)) FROM files
                WHERE state='backed_up'
                """
            ).fetchone()[0]
        return {"due_files": int(due or 0), "oldest_verification_basis": oldest or "", "interval_days": int(interval_days)}

    def list_files(
        self,
        limit: int = 200,
        offset: int = 0,
        search: str = "",
        include_deleted: bool = False,
        unbacked_only: bool = False,
        sort_by: str = "relative_path",
        sort_dir: str = "asc",
    ) -> List[sqlite3.Row]:
        clauses = []
        params: List[Any] = []
        if not include_deleted:
            clauses.append("f.state != 'deleted'")
        if unbacked_only:
            clauses.append("f.state != 'backed_up'")
        if search:
            clauses.append("(f.path LIKE ? OR f.relative_path LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sort_columns = {
            "id": "f.id",
            "path": "f.path",
            "relative_path": "f.relative_path",
            "name": "f.relative_path",
            "size": "f.size",
            "state": "f.state",
            "verification": "f.last_verify_at",
            "last_verify_at": "f.last_verify_at",
            "last_backup_at": "f.last_backup_at",
            "updated_at": "f.updated_at",
            "chunk_count": "chunk_count",
            "progress": "q.progress_chunks",
        }
        direction = "DESC" if str(sort_dir).lower() == "desc" else "ASC"
        order_expr = sort_columns.get(sort_by, "f.relative_path")
        with self.connect() as conn:
            return conn.execute(
                f"""
                SELECT f.*,
                       COUNT(c.id) + COALESCE(cm.chunk_count, 0) AS chunk_count,
                       COALESCE(SUM(CASE WHEN c.status='verified' THEN 1 ELSE 0 END), 0) + COALESCE(cm.verified_count, 0) AS verified_chunks,
                       COALESCE(SUM(CASE WHEN c.status='missing' THEN 1 ELSE 0 END), 0) + COALESCE(cm.missing_count, 0) AS missing_chunks,
                       COALESCE(SUM(c.size), 0) + COALESCE(cm.bytes_total, 0) AS chunk_bytes,
                       q.status AS queue_status,
                       q.progress_chunks AS progress_chunks,
                       q.progress_bytes AS progress_bytes
                FROM files f
                LEFT JOIN chunks c ON c.file_id = f.id
                LEFT JOIN chunk_manifests cm ON cm.file_id = f.id
                LEFT JOIN queue q ON q.file_id = f.id
                {where}
                GROUP BY f.id
                ORDER BY {order_expr} {direction}, f.relative_path ASC
                LIMIT ? OFFSET ?
                """,
                (*params, limit, offset),
            ).fetchall()

    def file_by_id(self, file_id: int) -> sqlite3.Row:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
            if row is None:
                raise FileNotFoundError(f"No file with id {file_id}")
            return row

    def file_count(self, search: str = "", include_deleted: bool = False, unbacked_only: bool = False) -> int:
        clauses = []
        params: List[Any] = []
        if not include_deleted:
            clauses.append("state != 'deleted'")
        if unbacked_only:
            clauses.append("state != 'backed_up'")
        if search:
            clauses.append("(path LIKE ? OR relative_path LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as conn:
            return int(conn.execute(f"SELECT COUNT(*) FROM files {where}", params).fetchone()[0])

    def folder_rollups(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Aggregate file safety metadata by top-level folder for large-library triage."""
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT
                  CASE
                    WHEN instr(replace(relative_path, '\\', '/'), '/') > 0
                    THEN substr(replace(relative_path, '\\', '/'), 1, instr(replace(relative_path, '\\', '/'), '/') - 1)
                    ELSE ''
                  END AS folder,
                  COUNT(*) AS files,
                  COALESCE(SUM(size), 0) AS bytes_total,
                  SUM(CASE WHEN state='backed_up' THEN 1 ELSE 0 END) AS backed_up_files,
                  COALESCE(SUM(CASE WHEN state='backed_up' THEN size ELSE 0 END), 0) AS backed_up_bytes,
                  SUM(CASE WHEN backup_compressed=1 THEN 1 ELSE 0 END) AS compressed_files,
                  SUM(CASE WHEN backup_par2=1 THEN 1 ELSE 0 END) AS par2_files,
                  SUM(CASE WHEN last_verify_at IS NOT NULL THEN 1 ELSE 0 END) AS verified_files,
                  SUM(CASE WHEN state IN ('failed','missing_chunks','unreadable') THEN 1 ELSE 0 END) AS attention_files
                FROM files
                WHERE state != 'deleted'
                GROUP BY folder
                ORDER BY attention_files DESC, bytes_total DESC, folder ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def verification_rows(
        self,
        limit: int = 200,
        offset: int = 0,
        verification_state: str = "",
        search: str = "",
        sort_by: str = "",
        sort_dir: str = "asc",
    ) -> List[sqlite3.Row]:
        where, params = self._verification_state_clause(verification_state, search)
        sort_columns = {
            "relative_path": "relative_path",
            "path": "path",
            "progress": "last_chunk_verify_at",
            "state": "state",
            "chunk_count": "chunk_count",
            "missing_chunks": "missing_chunks",
            "last_verify_at": "last_verify_at",
            "last_chunk_verify_at": "last_chunk_verify_at",
            "verification_state": "verification_state",
        }
        direction = "DESC" if str(sort_dir).lower() == "desc" else "ASC"
        if sort_by in sort_columns:
            order_by = f"{sort_columns[sort_by]} {direction}, relative_path ASC"
        else:
            order_by = "last_verify_at IS NULL DESC, last_verify_at ASC, relative_path"
        with self.connect() as conn:
            return conn.execute(
                f"""
                WITH verification AS (
                SELECT f.id, f.path, f.relative_path, f.state, f.last_verify_at,
                       COUNT(c.id) + COALESCE(cm.chunk_count, 0) AS chunk_count,
                       COALESCE(SUM(CASE WHEN c.status='verified' THEN 1 ELSE 0 END), 0) + COALESCE(cm.verified_count, 0) AS verified_chunks,
                       COALESCE(SUM(CASE WHEN c.status='missing' THEN 1 ELSE 0 END), 0) + COALESCE(cm.missing_count, 0) AS missing_chunks,
                       MAX(COALESCE(c.verified_at, cm.updated_at)) AS last_chunk_verify_at,
                       CASE
                         WHEN COALESCE(SUM(CASE WHEN c.status='missing' THEN 1 ELSE 0 END), 0) + COALESCE(cm.missing_count, 0) > 0 THEN 'missing'
                         WHEN COUNT(c.id) + COALESCE(cm.chunk_count, 0) = 0 THEN 'no_chunks'
                         WHEN f.last_verify_at IS NULL AND COALESCE(SUM(CASE WHEN c.status='verified' THEN 1 ELSE 0 END), 0) + COALESCE(cm.verified_count, 0) = 0 THEN 'unverified'
                         ELSE 'verified'
                       END AS verification_state
                FROM files f
                LEFT JOIN chunks c ON c.file_id = f.id
                LEFT JOIN chunk_manifests cm ON cm.file_id = f.id
                WHERE f.state != 'deleted'
                GROUP BY f.id
                )
                SELECT * FROM verification
                {where}
                ORDER BY {order_by}
                LIMIT ? OFFSET ?
                """,
                (*params, limit, offset),
            ).fetchall()

    def verification_count(self, verification_state: str = "", search: str = "") -> int:
        where, params = self._verification_state_clause(verification_state, search)
        with self.connect() as conn:
            row = conn.execute(
                f"""
                WITH verification AS (
                SELECT f.id, f.path, f.relative_path,
                       CASE
                         WHEN COALESCE(SUM(CASE WHEN c.status='missing' THEN 1 ELSE 0 END), 0) + COALESCE(cm.missing_count, 0) > 0 THEN 'missing'
                         WHEN COUNT(c.id) + COALESCE(cm.chunk_count, 0) = 0 THEN 'no_chunks'
                         WHEN f.last_verify_at IS NULL AND COALESCE(SUM(CASE WHEN c.status='verified' THEN 1 ELSE 0 END), 0) + COALESCE(cm.verified_count, 0) = 0 THEN 'unverified'
                         ELSE 'verified'
                       END AS verification_state
                FROM files f
                LEFT JOIN chunks c ON c.file_id = f.id
                LEFT JOIN chunk_manifests cm ON cm.file_id = f.id
                WHERE f.state != 'deleted'
                GROUP BY f.id
                )
                SELECT COUNT(*) AS total FROM verification {where}
                """,
                params,
            ).fetchone()
            return int(row["total"] or 0)

    def _verification_state_clause(self, verification_state: str, search: str = "") -> tuple[str, List[Any]]:
        clauses = []
        params: List[Any] = []
        if verification_state in {"missing", "unverified", "verified", "no_chunks"}:
            clauses.append("verification_state = ?")
            params.append(verification_state)
        if search:
            clauses.append("(path LIKE ? OR relative_path LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def list_events(
        self,
        levels: Optional[List[str]] = None,
        limit: int = 300,
        event_types: Optional[List[str]] = None,
        exclude_event_types: Optional[List[str]] = None,
        offset: int = 0,
        search: str = "",
        sort_by: str = "id",
        sort_dir: str = "desc",
    ) -> List[sqlite3.Row]:
        where, params = self._event_filters(levels, event_types, exclude_event_types, search)
        sort_columns = {
            "id": "id",
            "ts": "ts",
            "level": "level",
            "event_type": "event_type",
            "message": "message",
            "file_id": "file_id",
        }
        direction = "DESC" if str(sort_dir).lower() == "desc" else "ASC"
        order_expr = sort_columns.get(sort_by, "id")
        with self.connect() as conn:
            return conn.execute(
                f"SELECT * FROM events {where} ORDER BY {order_expr} {direction}, id DESC LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()

    def list_events_after_id(
        self,
        after_id: int,
        levels: Optional[List[str]] = None,
        limit: int = 100,
        event_types: Optional[List[str]] = None,
        exclude_event_types: Optional[List[str]] = None,
        search: str = "",
    ) -> List[sqlite3.Row]:
        where, params = self._event_filters(levels, event_types, exclude_event_types, search)
        prefix = "WHERE" if not where else f"{where} AND"
        with self.connect() as conn:
            return conn.execute(
                f"SELECT * FROM events {prefix} id > ? ORDER BY id DESC LIMIT ?",
                (*params, int(after_id), int(limit)),
            ).fetchall()

    def event_count(
        self,
        levels: Optional[List[str]] = None,
        event_types: Optional[List[str]] = None,
        exclude_event_types: Optional[List[str]] = None,
        search: str = "",
    ) -> int:
        where, params = self._event_filters(levels, event_types, exclude_event_types, search)
        with self.connect() as conn:
            row = conn.execute(f"SELECT COUNT(*) AS total FROM events {where}", params).fetchone()
            return int(row["total"] or 0)

    def _event_filters(
        self,
        levels: Optional[List[str]] = None,
        event_types: Optional[List[str]] = None,
        exclude_event_types: Optional[List[str]] = None,
        search: str = "",
    ) -> tuple[str, List[Any]]:
        allowed_levels = {"error", "warning", "info", "debug", "verbose"}
        selected = [level for level in (levels or []) if level in allowed_levels]
        clauses = []
        params: List[Any] = []
        if selected:
            placeholders = ",".join("?" for _ in selected)
            clauses.append(f"level IN ({placeholders})")
            params.extend(selected)
        if event_types:
            placeholders = ",".join("?" for _ in event_types)
            clauses.append(f"event_type IN ({placeholders})")
            params.extend(event_types)
        if exclude_event_types:
            placeholders = ",".join("?" for _ in exclude_event_types)
            clauses.append(f"event_type NOT IN ({placeholders})")
            params.extend(exclude_event_types)
        if search:
            clauses.append("(message LIKE ? OR event_type LIKE ? OR data LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def event_types(self) -> List[str]:
        with self.connect() as conn:
            rows = conn.execute("SELECT DISTINCT event_type FROM events ORDER BY event_type").fetchall()
            return [str(row["event_type"]) for row in rows]

    def change_token(self) -> Dict[str, Any]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT
                  (SELECT COALESCE(MAX(updated_at), '') FROM files) AS files_updated,
                  (SELECT COALESCE(MAX(updated_at), '') FROM queue) AS queue_updated,
                  (SELECT COALESCE(MAX(id), 0) FROM events WHERE event_type != 'web.access') AS event_id,
                  (SELECT COALESCE(MAX(id), 0) FROM transfer_samples) AS transfer_id,
                  ((SELECT COUNT(*) FROM chunks) + (SELECT COALESCE(SUM(chunk_count), 0) FROM chunk_manifests)) AS chunks_total,
                  (SELECT COUNT(*) FROM files WHERE state != 'deleted') AS files_total,
                  (SELECT COUNT(*) FROM queue) AS queue_total
                """
            ).fetchone()
            return dict(row)

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
            transfers = conn.execute(
                "SELECT ts, direction, size FROM transfer_samples WHERE ts >= ?",
                (start.isoformat(),),
            ).fetchall()
            verified = conn.execute("SELECT verified_at, size FROM chunks WHERE verified_at IS NOT NULL AND verified_at >= ?", (start.isoformat(),)).fetchall()
        for row in transfers:
            key = self._bucket_key(row["ts"], bucket_seconds)
            buckets.setdefault(key, {"ts": key, "upload_bps": 0.0, "download_bps": 0.0})
            metric = "download_bps" if row["direction"] == "download" else "upload_bps"
            buckets[key][metric] += row["size"] / bucket_seconds
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
                "files_total": conn.execute("SELECT COUNT(*) FROM files WHERE state != 'deleted'").fetchone()[0],
                "files_all_total": conn.execute("SELECT COUNT(*) FROM files").fetchone()[0],
                "files_bytes_total": conn.execute("SELECT COALESCE(SUM(size), 0) FROM files WHERE state != 'deleted'").fetchone()[0],
                "files_bytes_backed_up": conn.execute("SELECT COALESCE(SUM(size), 0) FROM files WHERE state='backed_up'").fetchone()[0],
                "files_bytes_queued": conn.execute("SELECT COALESCE(SUM(size), 0) FROM files WHERE state='queued'").fetchone()[0],
                "files_bytes_posting": conn.execute("SELECT COALESCE(SUM(size), 0) FROM files WHERE state='posting'").fetchone()[0],
                "files_compressed": conn.execute("SELECT COUNT(*) FROM files WHERE state != 'deleted' AND backup_compressed=1").fetchone()[0],
                "files_par2": conn.execute("SELECT COUNT(*) FROM files WHERE state != 'deleted' AND backup_par2=1").fetchone()[0],
                "files_compressible_backed_up": conn.execute(
                    "SELECT COUNT(*) FROM files WHERE state='backed_up' AND backup_uncompressed_size > 0"
                ).fetchone()[0],
                "backup_uncompressed_bytes_total": conn.execute(
                    "SELECT COALESCE(SUM(backup_uncompressed_size), 0) FROM files WHERE state != 'deleted' AND backup_uncompressed_size > 0"
                ).fetchone()[0],
                "backup_compressed_bytes_total": conn.execute(
                    "SELECT COALESCE(SUM(backup_compressed_size), 0) FROM files WHERE state != 'deleted' AND backup_compressed_size > 0"
                ).fetchone()[0],
                "backup_par2_bytes_total": conn.execute(
                    "SELECT COALESCE(SUM(backup_compressed_size), 0) FROM files WHERE state != 'deleted' AND backup_par2=1"
                ).fetchone()[0],
                "queue_attention_count": conn.execute(
                    """
                    SELECT COUNT(*) FROM queue
                    WHERE status='failed'
                       OR (status!='done' AND reason IN ('network-blocked', 'missing-chunks', 'file-changing'))
                    """
                ).fetchone()[0],
                "queue_attention_failed": conn.execute("SELECT COUNT(*) FROM queue WHERE status='failed'").fetchone()[0],
                "queue_attention_network_blocked": conn.execute("SELECT COUNT(*) FROM queue WHERE status!='done' AND reason='network-blocked'").fetchone()[0],
                "chunks_total": conn.execute("SELECT (SELECT COUNT(*) FROM chunks) + (SELECT COALESCE(SUM(chunk_count), 0) FROM chunk_manifests)").fetchone()[0],
                "chunks_verified": conn.execute("SELECT (SELECT COUNT(*) FROM chunks WHERE status='verified') + (SELECT COALESCE(SUM(verified_count), 0) FROM chunk_manifests)").fetchone()[0],
                "chunks_missing": conn.execute("SELECT (SELECT COUNT(*) FROM chunks WHERE status='missing') + (SELECT COALESCE(SUM(missing_count), 0) FROM chunk_manifests)").fetchone()[0],
                "chunks_bytes_total": conn.execute("SELECT (SELECT COALESCE(SUM(size), 0) FROM chunks) + (SELECT COALESCE(SUM(bytes_total), 0) FROM chunk_manifests)").fetchone()[0],
                "backup_runs_total": conn.execute("SELECT COUNT(*) FROM backup_runs").fetchone()[0],
                "backup_runs_failed": conn.execute("SELECT COUNT(*) FROM backup_runs WHERE status='failed'").fetchone()[0],
                "restore_drills_total": conn.execute("SELECT COUNT(*) FROM restore_drills").fetchone()[0],
                "restore_drills_failed": conn.execute("SELECT COUNT(*) FROM restore_drills WHERE status!='ok'").fetchone()[0],
            }


SCHEMA = """
CREATE TABLE IF NOT EXISTS app_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at TEXT NOT NULL
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
  last_verify_at TEXT,
  backup_uncompressed_size INTEGER NOT NULL DEFAULT 0,
  backup_compressed_size INTEGER NOT NULL DEFAULT 0,
  backup_compressed INTEGER NOT NULL DEFAULT 0,
  backup_par2 INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER NOT NULL UNIQUE REFERENCES files(id) ON DELETE CASCADE,
  priority INTEGER NOT NULL DEFAULT 100,
  position INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  reason TEXT NOT NULL,
  progress_chunks INTEGER NOT NULL DEFAULT 0,
  progress_bytes INTEGER NOT NULL DEFAULT 0,
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
  article_size INTEGER,
  verified_at TEXT,
  UNIQUE(file_id, chunk_index)
);

CREATE TABLE IF NOT EXISTS chunk_manifests (
  file_id INTEGER PRIMARY KEY REFERENCES files(id) ON DELETE CASCADE,
  chunk_count INTEGER NOT NULL,
  bytes_total INTEGER NOT NULL,
  article_size INTEGER,
  verified_count INTEGER NOT NULL DEFAULT 0,
  missing_count INTEGER NOT NULL DEFAULT 0,
  manifest_blob BLOB NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
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

CREATE TABLE IF NOT EXISTS transfer_samples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  direction TEXT NOT NULL,
  size INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS backup_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER REFERENCES files(id) ON DELETE SET NULL,
  path TEXT NOT NULL,
  status TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  host TEXT NOT NULL DEFAULT '',
  started_at TEXT NOT NULL,
  finished_at TEXT,
  chunks_total INTEGER NOT NULL DEFAULT 0,
  chunks_done INTEGER NOT NULL DEFAULT 0,
  bytes_total INTEGER NOT NULL DEFAULT 0,
  bytes_done INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS backup_manifests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER REFERENCES files(id) ON DELETE SET NULL,
  backup_run_id INTEGER REFERENCES backup_runs(id) ON DELETE SET NULL,
  path TEXT NOT NULL,
  file_sha256 TEXT NOT NULL DEFAULT '',
  app_version TEXT NOT NULL DEFAULT '',
  article_size INTEGER NOT NULL DEFAULT 0,
  chunk_count INTEGER NOT NULL DEFAULT 0,
  bytes_total INTEGER NOT NULL DEFAULT 0,
  flags TEXT NOT NULL DEFAULT '',
  manifest_json TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS host_stats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_name TEXT NOT NULL,
  mode TEXT NOT NULL,
  status TEXT NOT NULL,
  message TEXT NOT NULL DEFAULT '',
  latency_ms INTEGER,
  article_size_bytes INTEGER,
  checked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS maintenance_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  result TEXT NOT NULL,
  details TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS restore_drills (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_id INTEGER REFERENCES files(id) ON DELETE SET NULL,
  path TEXT NOT NULL,
  status TEXT NOT NULL,
  checked_at TEXT NOT NULL,
  bytes_checked INTEGER NOT NULL DEFAULT 0,
  message TEXT NOT NULL DEFAULT ''
);
"""
