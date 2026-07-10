import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional


SCHEMA_VERSION = 4
STALE_POSTING_SECONDS = 15 * 60


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
            self._migrate(conn)
            conn.execute(
                "INSERT OR REPLACE INTO app_meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
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

    def get_meta(self, key: str) -> Optional[str]:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM app_meta WHERE key=?", (key,)).fetchone()
            return None if row is None else str(row["value"])

    def set_meta(self, key: str, value: str) -> None:
        with self.connect() as conn:
            conn.execute("INSERT OR REPLACE INTO app_meta(key, value) VALUES(?,?)", (key, value))

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

    def endpoint_file_snapshot(self, endpoint_id: int) -> Dict[str, Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id, path, relative_path, size, mtime_ns, sha256, state FROM files WHERE endpoint_id=?",
                (endpoint_id,),
            ).fetchall()
            return {str(row["path"]): dict(row) for row in rows}

    def upsert_file(self, record: Dict[str, Any]) -> int:
        now = utcnow()
        with self.connect() as conn:
            row = conn.execute("SELECT id, size, mtime_ns, sha256, state FROM files WHERE path = ?", (record["path"],)).fetchone()
            if row:
                changed = row["size"] != record["size"] or row["mtime_ns"] != record["mtime_ns"] or row["sha256"] != record["sha256"]
                revived = row["state"] == "deleted"
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
                        1 if changed or revived else 0,
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
                SELECT q.*, f.path, f.size, f.sha256, f.state FROM queue q
                JOIN files f ON f.id = q.file_id
                WHERE q.status='queued'
                  AND f.state NOT IN ('backed_up', 'deleted', 'posting')
                ORDER BY q.priority ASC, q.position ASC
                LIMIT 1
                """
            ).fetchone()

    def list_queue(self, include_done: bool = False, status: Optional[str] = None, limit: int = 200, offset: int = 0) -> List[sqlite3.Row]:
        where_parts = []
        params: List[Any] = []
        if status:
            where_parts.append("q.status = ?")
            params.append(status)
        elif not include_done:
            where_parts.append("q.status NOT IN ('done', 'failed')")
            where_parts.append("f.state NOT IN ('backed_up', 'failed')")
        where = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""
        with self.connect() as conn:
            return conn.execute(
                f"""
                SELECT q.*, f.path, f.size, f.state,
                       CASE WHEN q.status='posting' THEN q.progress_chunks ELSE COUNT(c.id) END AS posted_chunks,
                       CASE WHEN q.status='posting' THEN q.progress_bytes ELSE COALESCE(SUM(c.size), 0) END AS posted_bytes
                FROM queue q
                JOIN files f ON f.id = q.file_id
                LEFT JOIN chunks c ON c.file_id = f.id
                {where}
                GROUP BY q.id
                ORDER BY q.priority ASC, q.position ASC
                LIMIT ? OFFSET ?
                """
                ,
                (*params, limit, offset),
            ).fetchall()

    def queue_count(self, include_done: bool = False, status: Optional[str] = None) -> int:
        where_parts = []
        params: List[Any] = []
        if status:
            where_parts.append("q.status = ?")
            params.append(status)
        elif not include_done:
            where_parts.append("q.status NOT IN ('done', 'failed')")
            where_parts.append("f.state NOT IN ('backed_up', 'failed')")
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

    def set_queue_status(self, file_id: int, status: str) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE queue SET status=?, updated_at=? WHERE file_id=?", (status, utcnow(), file_id))

    def set_queue_progress(self, file_id: int, chunks: int, bytes_posted: int) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE queue SET progress_chunks=?, progress_bytes=?, updated_at=? WHERE file_id=?",
                (max(0, int(chunks)), max(0, int(bytes_posted)), utcnow(), file_id),
            )

    def record_transfer_sample(self, direction: str, size: int) -> None:
        if size <= 0:
            return
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO transfer_samples(ts, direction, size) VALUES(?,?,?)",
                (utcnow(), direction, int(size)),
            )

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
            if not file_row or file_row["state"] in {"backed_up", "deleted"}:
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
                WHERE state NOT IN ('backed_up', 'deleted')
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
            conn.execute(
                "INSERT INTO transfer_samples(ts, direction, size) VALUES(?,?,?)",
                (now, "upload", int(size)),
            )

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
            return int(conn.execute("SELECT COUNT(*) FROM chunks WHERE file_id=?", (file_id,)).fetchone()[0])

    def replace_chunks(self, file_id: int, chunks: Iterable[Dict[str, Any]]) -> int:
        now = utcnow()
        chunk_rows = list(chunks)
        with self.connect() as conn:
            conn.execute("DELETE FROM chunks WHERE file_id=?", (file_id,))
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
            return cur.rowcount

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
                    JOIN chunks c ON c.file_id = f.id
                    WHERE f.state != 'deleted'
                      AND c.status != 'missing'
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

    def chunks_for_file_ids(self, file_ids: Iterable[int]) -> List[sqlite3.Row]:
        ids = [int(file_id) for file_id in file_ids]
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        with self.connect() as conn:
            return conn.execute(
                f"""
                SELECT c.*, f.path FROM chunks c
                JOIN files f ON f.id = c.file_id
                WHERE c.file_id IN ({placeholders})
                  AND c.status != 'missing'
                ORDER BY c.file_id, c.chunk_index
                """,
                ids,
            ).fetchall()

    def mark_chunk_verified(self, chunk_id: int, exists: bool) -> None:
        status = "verified" if exists else "missing"
        missing_file_id: Optional[int] = None
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
                    conn.execute("UPDATE files SET last_verify_at=?, updated_at=? WHERE id=?", (now, now, row["file_id"]))
        if missing_file_id is not None:
            self.queue_file(missing_file_id, priority=10, reason="missing-chunks")

    def list_rows(self, table: str, limit: int = 200) -> List[sqlite3.Row]:
        allowed = {"files", "events", "queue", "chunks", "endpoints"}
        if table not in allowed:
            raise ValueError(f"Unsupported table: {table}")
        with self.connect() as conn:
            return conn.execute(f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def list_files(
        self,
        limit: int = 200,
        offset: int = 0,
        search: str = "",
        include_deleted: bool = False,
        unbacked_only: bool = False,
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
        with self.connect() as conn:
            return conn.execute(
                f"""
                SELECT f.*,
                       COUNT(c.id) AS chunk_count,
                       SUM(CASE WHEN c.status='verified' THEN 1 ELSE 0 END) AS verified_chunks,
                       SUM(CASE WHEN c.status='missing' THEN 1 ELSE 0 END) AS missing_chunks,
                       COALESCE(SUM(c.size), 0) AS chunk_bytes,
                       q.status AS queue_status,
                       q.progress_chunks AS progress_chunks,
                       q.progress_bytes AS progress_bytes
                FROM files f
                LEFT JOIN chunks c ON c.file_id = f.id
                LEFT JOIN queue q ON q.file_id = f.id
                {where}
                GROUP BY f.id
                ORDER BY f.relative_path
                LIMIT ? OFFSET ?
                """,
                (*params, limit, offset),
            ).fetchall()

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

    def verification_rows(self, limit: int = 200, offset: int = 0) -> List[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(
                """
                SELECT f.id, f.path, f.relative_path, f.state, f.last_verify_at,
                       COUNT(c.id) AS chunk_count,
                       SUM(CASE WHEN c.status='verified' THEN 1 ELSE 0 END) AS verified_chunks,
                       SUM(CASE WHEN c.status='missing' THEN 1 ELSE 0 END) AS missing_chunks,
                       MAX(c.verified_at) AS last_chunk_verify_at
                FROM files f
                LEFT JOIN chunks c ON c.file_id = f.id
                WHERE f.state != 'deleted'
                GROUP BY f.id
                ORDER BY f.last_verify_at IS NULL DESC, f.last_verify_at ASC, f.relative_path
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()

    def list_events(
        self,
        levels: Optional[List[str]] = None,
        limit: int = 300,
        event_types: Optional[List[str]] = None,
        exclude_event_types: Optional[List[str]] = None,
    ) -> List[sqlite3.Row]:
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
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as conn:
            return conn.execute(
                f"SELECT * FROM events {where} ORDER BY id DESC LIMIT ?",
                (*params, limit),
            ).fetchall()

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
                  (SELECT COUNT(*) FROM chunks) AS chunks_total,
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
            verified = conn.execute(
                "SELECT verified_at, size FROM chunks WHERE verified_at IS NOT NULL AND verified_at >= ?",
                (start.isoformat(),),
            ).fetchall()
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
                "chunks_total": conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0],
                "chunks_verified": conn.execute("SELECT COUNT(*) FROM chunks WHERE status='verified'").fetchone()[0],
                "chunks_missing": conn.execute("SELECT COUNT(*) FROM chunks WHERE status='missing'").fetchone()[0],
                "chunks_bytes_total": conn.execute("SELECT COALESCE(SUM(size), 0) FROM chunks").fetchone()[0],
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
"""
