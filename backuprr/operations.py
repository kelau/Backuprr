import math
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

from .config import Config
from .db import Database, utcnow
from .restore import restore_sample
from .usenet import UsenetClient


def dry_run_plan(db: Database, config: Config) -> Dict[str, Any]:
    stats = db.stats()
    queued_bytes = int(stats.get("files_bytes_queued", 0)) + int(stats.get("files_bytes_posting", 0))
    unprotected_bytes = max(0, int(stats.get("files_bytes_total", 0)) - int(stats.get("files_bytes_backed_up", 0)))
    article_size = max(1, int(config.article_size))
    target_bytes = max(queued_bytes, unprotected_bytes)
    article_count = math.ceil(target_bytes / article_size) if target_bytes else 0
    hourly_limit = int(config.hourly_post_limit_bytes or 0)
    estimated_hours = round(target_bytes / hourly_limit, 2) if hourly_limit else None
    estimated_days = round(estimated_hours / 24, 2) if estimated_hours is not None else None
    return {
        "files_total": int(stats.get("files_total", 0)),
        "files_unprotected": int(stats.get("files_total", 0)) - int(stats.get("files_backed_up", 0)),
        "bytes_unprotected": unprotected_bytes,
        "bytes_queued_or_posting": queued_bytes,
        "article_size": article_size,
        "estimated_articles": article_count,
        "hourly_limit_bytes": hourly_limit,
        "estimated_hours_at_limit": estimated_hours,
        "estimated_days_at_limit": estimated_days,
    }


def check_usenet_hosts(db: Database, config: Config) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for host in config.usenet_hosts:
        started = time.perf_counter()
        status = "ok"
        message = "connection/auth ok"
        try:
            with UsenetClient(host) as client:
                if host.mode == "read" and client.conn:
                    client.conn.group(config.newsgroup)
        except Exception as exc:
            status = "failed"
            message = str(exc)
        latency_ms = max(1, int((time.perf_counter() - started) * 1000))
        db.record_host_check(host.name, host.mode, status, message, latency_ms)
        results.append(
            {
                "host_name": host.name,
                "mode": host.mode,
                "status": status,
                "message": message,
                "latency_ms": latency_ms,
            }
        )
    return results


def run_maintenance(db: Database, config: Config, vacuum: bool = False) -> Dict[str, Any]:
    started = utcnow()
    pruned = db.prune_events(config.log_retention_days, config.verbose_log_retention_days)
    compacted_samples = db.compact_transfer_samples()
    details = f"pruned {pruned} log events, compacted {compacted_samples} transfer samples"
    if vacuum:
        db.vacuum_analyze()
        details += ", vacuum/analyze completed"
    db.record_maintenance("database", started, "ok", details)
    db.log("info", "maintenance", details)
    return {"ok": True, "pruned_events": pruned, "compacted_transfer_samples": compacted_samples, "vacuum": bool(vacuum), "details": details}


def restore_confidence(db: Database, source_path: str) -> Dict[str, Any]:
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM files WHERE path=? OR relative_path=?", (source_path, source_path)).fetchone()
        if not row:
            raise FileNotFoundError(f"No cataloged file matches {source_path}")
        chunks = conn.execute(
            """
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN status='missing' THEN 1 ELSE 0 END) AS missing,
                   SUM(CASE WHEN status='verified' THEN 1 ELSE 0 END) AS verified,
                   MAX(verified_at) AS last_verified
            FROM chunks
            WHERE file_id=?
            """,
            (row["id"],),
        ).fetchone()
    total = int(chunks["total"] or 0)
    missing = int(chunks["missing"] or 0)
    verified = int(chunks["verified"] or 0)
    return {
        "file_id": int(row["id"]),
        "path": row["path"],
        "state": row["state"],
        "chunk_count": total,
        "verified_chunks": verified,
        "missing_chunks": missing,
        "last_verified": row["last_verify_at"] or chunks["last_verified"] or "",
        "restorable": total > 0 and missing == 0,
        "warning": "" if total > 0 and missing == 0 else "missing or unavailable chunks may prevent restore",
    }


def run_restore_drill(db: Database, config: Config) -> Dict[str, Any]:
    candidate = db.restore_drill_candidate()
    if not candidate:
        db.record_restore_drill(None, "", "skipped", 0, "no backed up files with chunks")
        return {"status": "skipped", "message": "no backed up files with chunks"}
    try:
        sample = restore_sample(db, config, candidate["path"], int(config.restore_drill_sample_bytes))
        size = len(sample)
        db.record_restore_drill(int(candidate["id"]), candidate["path"], "ok", size, "restore drill succeeded")
        return {"status": "ok", "file_id": int(candidate["id"]), "path": candidate["path"], "bytes_checked": size}
    except Exception as exc:
        db.record_restore_drill(int(candidate["id"]), candidate["path"], "failed", 0, str(exc))
        db.log("warning", "restore.drill", f"Restore drill failed for {candidate['path']}: {exc}", int(candidate["id"]))
        return {"status": "failed", "file_id": int(candidate["id"]), "path": candidate["path"], "message": str(exc)}


def restore_drill_due(db: Database, config: Config) -> bool:
    rows = db.restore_drill_rows(1)
    if not rows:
        return True
    last = datetime.fromisoformat(rows[0]["checked_at"])
    return last <= datetime.now(timezone.utc) - timedelta(days=config.restore_drill_interval_days)
