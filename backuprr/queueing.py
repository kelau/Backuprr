from fnmatch import fnmatch
import time
from pathlib import Path
from typing import Optional

from .config import Config
from .db import Database


def excluded_by_auto_queue_filter(path: str, relative_path: str, patterns: list[str]) -> bool:
    names = {Path(path).name.lower(), str(relative_path or "").lower(), str(path or "").lower()}
    for raw_pattern in patterns:
        pattern = raw_pattern.strip().lower()
        if not pattern:
            continue
        extension_pattern = f"*{pattern}" if pattern.startswith(".") else pattern
        if any(fnmatch(name, extension_pattern) for name in names):
            return True
    return False


def file_is_stable(path: str, size: int, mtime_ns: int, stability_seconds: int) -> bool:
    if stability_seconds <= 0:
        return True
    try:
        stat = Path(path).stat()
    except OSError:
        return False
    if stat.st_size != int(size) or stat.st_mtime_ns != int(mtime_ns):
        return False
    age_seconds = max(0.0, time.time() - (stat.st_mtime_ns / 1_000_000_000))
    return age_seconds >= stability_seconds


def enqueue_unbacked(db: Database, config: Optional[Config] = None) -> int:
    count = 0
    skipped = 0
    unstable = 0
    patterns = list(getattr(config, "auto_queue_exclude_patterns", []) or [])
    stability_seconds = int(getattr(config, "file_stability_seconds", 0) or 0)
    with db.connect() as conn:
        rows = conn.execute(
            """
            SELECT id, path, relative_path, size, mtime_ns FROM files
            WHERE state IN ('discovered', 'changed', 'missing_chunks')
              AND id NOT IN (SELECT file_id FROM queue WHERE status IN ('queued', 'posting'))
            ORDER BY created_at ASC
            """
        ).fetchall()
    for row in rows:
        if patterns and excluded_by_auto_queue_filter(str(row["path"]), str(row["relative_path"]), patterns):
            skipped += 1
            continue
        if stability_seconds and not file_is_stable(str(row["path"]), int(row["size"]), int(row["mtime_ns"]), stability_seconds):
            unstable += 1
            continue
        db.queue_file(int(row["id"]), priority=100, reason="unbacked")
        count += 1
    suffix = f", skipped {skipped} by auto-queue filter" if skipped else ""
    suffix += f", waiting for {unstable} unstable file(s)" if unstable else ""
    db.log("info" if count else "debug", "queue", f"Queued {count} unbacked files{suffix}")
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
