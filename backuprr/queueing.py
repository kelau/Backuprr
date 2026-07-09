from .db import Database


def enqueue_unbacked(db: Database) -> int:
    count = 0
    with db.connect() as conn:
        rows = conn.execute(
            """
            SELECT id FROM files
            WHERE state IN ('discovered', 'changed', 'missing_chunks')
              AND id NOT IN (SELECT file_id FROM queue WHERE status IN ('queued', 'posting'))
            ORDER BY created_at ASC
            """
        ).fetchall()
    for row in rows:
        db.queue_file(int(row["id"]), priority=100, reason="unbacked")
        count += 1
    db.log("info" if count else "debug", "queue", f"Queued {count} unbacked files")
    return count


def prioritize(db: Database, filter_name: str) -> int:
    if filter_name not in {"older-first", "larger-first", "smaller-first"}:
        raise ValueError("filter_name must be older-first, larger-first, or smaller-first")
    order = {
        "older-first": "f.mtime_ns ASC",
        "larger-first": "f.size DESC",
        "smaller-first": "f.size ASC",
    }[filter_name]
    with db.connect() as conn:
        rows = conn.execute(
            f"""
            SELECT q.file_id FROM queue q
            JOIN files f ON f.id = q.file_id
            WHERE q.status='queued'
              AND f.state NOT IN ('backed_up', 'deleted', 'posting')
            ORDER BY {order}
            """
        ).fetchall()
        for position, row in enumerate(rows, start=1):
            conn.execute("UPDATE queue SET position=?, updated_at=datetime('now') WHERE file_id=?", (position, row["file_id"]))
    db.log("debug", "queue.prioritize", f"Applied queue filter {filter_name}")
    return len(rows)


def move(db: Database, file_id: int, position: int) -> None:
    with db.connect() as conn:
        conn.execute("UPDATE queue SET position=?, updated_at=datetime('now') WHERE file_id=?", (position, file_id))
    db.log("info", "queue.move", f"Moved file {file_id} to queue position {position}", file_id)
