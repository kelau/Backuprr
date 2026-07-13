from fnmatch import fnmatch
import re
import time
from pathlib import Path
from typing import Optional

from .config import Config
from .db import Database


def excluded_by_auto_queue_filter(path: str, relative_path: str, patterns: list[str]) -> bool:
    names = {Path(path).name, str(relative_path or ""), str(path or "")}
    lowered_names = {name.lower() for name in names}
    for raw_pattern in patterns:
        pattern = raw_pattern.strip()
        if not pattern:
            continue
        regex = regex_from_filter(pattern)
        if regex and any(regex.search(name) for name in names):
            return True
        glob_patterns = glob_patterns_from_filter(pattern)
        if any(fnmatch(name, glob_pattern) for name in lowered_names for glob_pattern in glob_patterns):
            return True
    return False


def regex_from_filter(pattern: str) -> Optional[re.Pattern[str]]:
    if pattern.lower().startswith(("regex:", "re:")):
        expression = pattern.split(":", 1)[1].strip()
    elif len(pattern) >= 2 and pattern.startswith("/") and pattern.endswith("/"):
        expression = pattern[1:-1]
    else:
        return None
    if not expression:
        return None
    try:
        return re.compile(expression, re.IGNORECASE)
    except re.error:
        return None


def glob_patterns_from_filter(pattern: str) -> list[str]:
    lowered = pattern.lower()
    if any(char in lowered for char in "*?[]"):
        return [lowered]
    if lowered.startswith("."):
        return [f"*{lowered}"]
    if re.fullmatch(r"[a-z0-9]+", lowered):
        return [f"*.{lowered}", lowered]
    return [lowered]


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
    paused = 0
    unstable = 0
    patterns = list(getattr(config, "auto_queue_exclude_patterns", []) or [])
    pause_patterns = list(getattr(config, "queue_pause_patterns", []) or [])
    stability_seconds = int(getattr(config, "file_stability_seconds", 0) or 0)
    strategy = str(getattr(config, "queue_strategy", "older-first") or "older-first")
    order = {
        "older-first": "mtime_ns ASC",
        "larger-first": "size DESC",
        "smaller-first": "size ASC",
        "folder-first": "relative_path ASC",
    }.get(strategy, "mtime_ns ASC")
    with db.connect() as conn:
        rows = conn.execute(
            f"""
            SELECT id, path, relative_path, size, mtime_ns FROM files
            WHERE state IN ('discovered', 'changed', 'missing_chunks')
              AND id NOT IN (SELECT file_id FROM queue WHERE status IN ('queued', 'posting'))
            ORDER BY {order}, created_at ASC
            """
        ).fetchall()
    for row in rows:
        if patterns and excluded_by_auto_queue_filter(str(row["path"]), str(row["relative_path"]), patterns):
            skipped += 1
            continue
        if pause_patterns and excluded_by_auto_queue_filter(str(row["path"]), str(row["relative_path"]), pause_patterns):
            paused += 1
            continue
        if stability_seconds and not file_is_stable(str(row["path"]), int(row["size"]), int(row["mtime_ns"]), stability_seconds):
            unstable += 1
            continue
        db.queue_file(int(row["id"]), priority=100, reason="unbacked")
        count += 1
    suffix = f", skipped {skipped} by auto-queue filter" if skipped else ""
    suffix += f", paused {paused} by queue pause pattern" if paused else ""
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
