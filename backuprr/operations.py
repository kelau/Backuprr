import hashlib
import math
import os
import time
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

from .config import Config
from .db import Database, utcnow
from .restore import restore_sample
from .usenet import UsenetClient


ARTICLE_TEST_MIN_BYTES = 100 * 1024
ARTICLE_TEST_MAX_BYTES = 5 * 1024 * 1024
ARTICLE_TEST_STEP_BYTES = 100 * 1024


def dry_run_plan(db: Database, config: Config) -> Dict[str, Any]:
    """Estimate the next backup wave without touching files or the provider."""
    stats = db.stats()
    queued_bytes = int(stats.get("files_bytes_queued", 0)) + int(stats.get("files_bytes_posting", 0))
    unprotected_bytes = max(0, int(stats.get("files_bytes_total", 0)) - int(stats.get("files_bytes_backed_up", 0)))
    article_size = max(1, int(config.article_size))
    target_bytes = max(queued_bytes, unprotected_bytes)
    article_count = math.ceil(target_bytes / article_size) if target_bytes else 0
    hourly_limit = int(config.hourly_post_limit_bytes or 0)
    estimated_hours = round(target_bytes / hourly_limit, 2) if hourly_limit else None
    estimated_days = round(estimated_hours / 24, 2) if estimated_hours is not None else None
    par2_percent = int((config.par2 or {}).get("redundancy_percent", 0) or 0) if (config.par2 or {}).get("enabled") else 0
    par2_overhead = math.ceil(target_bytes * (par2_percent / 100)) if par2_percent else 0
    encrypted_overhead = article_count * (len(b"BACKUPRR-ENC1") + 16) if config.encrypt_bodies else 0
    estimated_rows = {
        "files": int(stats.get("files_total", 0)),
        "chunks": int(stats.get("chunks_total", 0)) + article_count,
        "backup_manifests": int(stats.get("backup_runs_total", 0)) + int(stats.get("files_total", 0)),
    }
    warnings = []
    if target_bytes and not config.usenet_hosts:
        warnings.append("no Usenet hosts configured")
    if target_bytes and hourly_limit and estimated_days and estimated_days > 7:
        warnings.append("current hourly posting limit will stretch this backup over more than a week")
    if article_count > 1_000_000:
        warnings.append("article count is very high; test provider max article size and consider larger articles")
    if par2_percent and not (config.par2 or {}).get("command"):
        warnings.append("PAR2 is enabled without a command")
    return {
        "files_total": int(stats.get("files_total", 0)),
        "files_unprotected": int(stats.get("files_total", 0)) - int(stats.get("files_backed_up", 0)),
        "bytes_unprotected": unprotected_bytes,
        "bytes_queued_or_posting": queued_bytes,
        "article_size": article_size,
        "estimated_articles": article_count,
        "estimated_chunk_rows": article_count,
        "estimated_par2_overhead_bytes": par2_overhead,
        "estimated_encryption_overhead_bytes": encrypted_overhead,
        "estimated_post_bytes": target_bytes + par2_overhead + encrypted_overhead,
        "estimated_db_rows_after_backup": estimated_rows,
        "manifest_compaction_hint": "Use larger article sizes or compact chunk metadata; future manifest blobs can reduce per-chunk row pressure.",
        "hourly_limit_bytes": hourly_limit,
        "estimated_hours_at_limit": estimated_hours,
        "estimated_days_at_limit": estimated_days,
        "warnings": warnings,
    }


def synthetic_catalog_plan(file_count: int, average_file_size: int, article_size: int, folders: int = 100) -> Dict[str, Any]:
    file_count = max(0, int(file_count))
    average_file_size = max(0, int(average_file_size))
    article_size = max(1, int(article_size))
    folders = max(1, int(folders))
    total_bytes = file_count * average_file_size
    chunk_rows = file_count * max(1, math.ceil(average_file_size / article_size)) if file_count else 0
    return {
        "files": file_count,
        "folders": min(folders, file_count) if file_count else 0,
        "average_file_size": average_file_size,
        "total_bytes": total_bytes,
        "article_size": article_size,
        "estimated_chunk_rows": chunk_rows,
        "estimated_chunk_table_bytes": chunk_rows * 220,
        "estimated_file_table_bytes": file_count * 350,
        "recommended_article_size": min(5 * 1024 * 1024, max(article_size, 2 * 1024 * 1024 if total_bytes > 1024**4 else article_size)),
    }


def disaster_recovery_report(db: Database, config: Config) -> Dict[str, Any]:
    """Summarize whether the app can be rebuilt and controlled after host loss."""
    db_path = config.db_path()
    config_path = Path(config.source_path) if config.source_path else None
    stats = db.stats()
    issues = []
    if not db_path.exists():
        issues.append("database file is missing")
    if not config_path or not config_path.exists():
        issues.append("config file is missing or was not loaded from disk")
    if not config.external_api_keys:
        issues.append("no external API keys configured")
    if not config.cloud_backups:
        issues.append("no config/database cloud backup targets configured")
    if int(stats.get("chunks_total", 0)) <= 0 and int(stats.get("files_backed_up", 0)) > 0:
        issues.append("backed-up files exist without chunk metadata")
    return {
        "ok": not issues,
        "issues": issues,
        "database": str(db_path),
        "database_exists": db_path.exists(),
        "config": str(config_path) if config_path else "",
        "config_exists": bool(config_path and config_path.exists()),
        "cloud_backup_targets": len(config.cloud_backups),
        "external_api_key_count": len(config.external_api_keys),
        "files_total": int(stats.get("files_total", 0)),
        "chunks_total": int(stats.get("chunks_total", 0)),
    }


def setup_health_check(db: Database, config: Config) -> Dict[str, Any]:
    """Build the user-facing first-run checklist from catalog, provider, and safety state."""
    stats = db.stats()
    host_rows = db.host_health_rows(10)
    recovery = disaster_recovery_report(db, config)
    checks = [
        {"id": "endpoints", "label": "Media endpoints configured", "ok": bool(config.endpoints), "detail": f"{len(config.endpoints)} endpoint(s)"},
        {"id": "catalog", "label": "Catalog has files", "ok": int(stats.get("files_total", 0)) > 0, "detail": f"{int(stats.get('files_total', 0))} active file(s)"},
        {"id": "post-host", "label": "Post host configured", "ok": bool(config.hosts_for_mode("post")), "detail": f"{len(config.hosts_for_mode('post'))} post host(s)"},
        {"id": "read-host", "label": "Read host configured", "ok": bool(config.hosts_for_mode("read")), "detail": f"{len(config.hosts_for_mode('read'))} read host(s)"},
        {"id": "provider-tested", "label": "Provider health checked", "ok": bool(host_rows), "detail": "run Check hosts + article size" if not host_rows else f"{len(host_rows)} recent check(s)"},
        {"id": "external-api", "label": "External API key configured", "ok": bool(config.external_api_keys), "detail": f"{len(config.external_api_keys)} key(s)"},
        {"id": "web-auth", "label": "Web UI password enabled", "ok": bool(config.web_ui_password), "detail": "optional but recommended on LAN/container deployments"},
        {"id": "cloud-backup", "label": "Config/database cloud backup configured", "ok": bool(config.cloud_backups), "detail": f"{len(config.cloud_backups)} target(s)"},
        {"id": "recovery", "label": "Disaster recovery readiness", "ok": bool(recovery["ok"]), "detail": "; ".join(recovery["issues"]) if recovery["issues"] else "ready"},
    ]
    return {"ok": all(item["ok"] for item in checks), "checks": checks}


def notification_alerts(db: Database, config: Config) -> List[Dict[str, Any]]:
    """Return high-signal conditions suitable for Status cards or external notifiers."""
    stats = db.stats()
    alerts: List[Dict[str, Any]] = []
    if int(stats.get("queue_attention_count", 0)):
        alerts.append({"level": "warning", "title": "Queue needs attention", "detail": f"{stats.get('queue_attention_count')} queue item(s) are failed or blocked"})
    if int(stats.get("chunks_missing", 0)):
        alerts.append({"level": "error", "title": "Missing Usenet chunks", "detail": f"{stats.get('chunks_missing')} chunk(s) are marked missing"})
    if int(stats.get("restore_drills_failed", 0)):
        alerts.append({"level": "warning", "title": "Restore drill failures", "detail": f"{stats.get('restore_drills_failed')} failed restore drill(s) recorded"})
    if not config.cloud_backups:
        alerts.append({"level": "info", "title": "No config/database cloud backup", "detail": "add a cloud target so the catalog can be recovered after host loss"})
    if not config.web_ui_password:
        alerts.append({"level": "info", "title": "Web UI password disabled", "detail": "enable Web UI auth before exposing the app beyond localhost"})
    return alerts


def diagnostics_bundle(db: Database, config: Config) -> Dict[str, Any]:
    """Create a redacted support bundle that is safe to download or attach to bug reports."""
    cfg = config.public_dict()
    for host in cfg.get("usenet_hosts", []):
        host["username"] = "***" if host.get("username") else ""
    return {
        "generated_at": utcnow(),
        "config": cfg,
        "status": {
            "stats": db.stats(),
            "setup": setup_health_check(db, config),
            "disaster_recovery": disaster_recovery_report(db, config),
            "alerts": notification_alerts(db, config),
        },
        "tasks": [dict(row) for row in db.worker_state_rows()],
        "tables": db.table_stats(),
        "provider_profiles": [dict(row) for row in db.provider_profiles()],
        "host_health": [dict(row) for row in db.host_health_rows(20)],
        "recent_events": [dict(row) for row in db.list_events(limit=100, exclude_event_types=["web.access"])],
    }


def prometheus_metrics(db: Database, config: Config) -> str:
    stats = db.stats()
    tasks = db.worker_state_rows()
    lines = [
        "# HELP backuprr_files_total Active cataloged files.",
        "# TYPE backuprr_files_total gauge",
        f"backuprr_files_total {int(stats.get('files_total', 0))}",
        "# HELP backuprr_queue_items Queue items by status.",
        "# TYPE backuprr_queue_items gauge",
    ]
    for key, value in sorted(stats.items()):
        if key.startswith("queue_"):
            lines.append(f'backuprr_queue_items{{status="{key.removeprefix("queue_")}"}} {int(value or 0)}')
    lines.extend(
        [
            "# HELP backuprr_chunks_total Stored Usenet chunk metadata rows.",
            "# TYPE backuprr_chunks_total gauge",
            f"backuprr_chunks_total {int(stats.get('chunks_total', 0))}",
            "# HELP backuprr_bytes_total Cataloged file bytes.",
            "# TYPE backuprr_bytes_total gauge",
            f"backuprr_bytes_total {int(stats.get('files_bytes_total', 0))}",
            "# HELP backuprr_hourly_post_limit_bytes Configured hourly upload limit.",
            "# TYPE backuprr_hourly_post_limit_bytes gauge",
            f"backuprr_hourly_post_limit_bytes {int(config.hourly_post_limit_bytes or 0)}",
            "# HELP backuprr_worker_runs Worker run count by kind.",
            "# TYPE backuprr_worker_runs counter",
        ]
    )
    for task in tasks:
        lines.append(f'backuprr_worker_runs{{kind="{task["kind"]}"}} {int(task["runs"] or 0)}')
    return "\n".join(lines) + "\n"


def check_usenet_hosts(db: Database, config: Config) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for host in config.usenet_hosts:
        started = time.perf_counter()
        status = "ok"
        message = "connection/auth ok"
        article_size_bytes = None
        try:
            with UsenetClient(host) as client:
                if host.mode == "read" and client.conn:
                    client.conn.group(config.newsgroup)
            if host.mode == "post":
                article_size_bytes = test_post_host_article_size(db, config, host.name)
                message = f"connection/auth ok; max article size {article_size_bytes} bytes"
        except Exception as exc:
            status = "failed"
            message = str(exc)
        latency_ms = max(1, int((time.perf_counter() - started) * 1000))
        db.record_host_check(host.name, host.mode, status, message, latency_ms, article_size_bytes)
        results.append(
            {
                "host_name": host.name,
                "mode": host.mode,
                "status": status,
                "message": message,
                "latency_ms": latency_ms,
                "article_size_bytes": article_size_bytes,
            }
        )
    return results


def test_post_host_article_size(
    db: Database,
    config: Config,
    host_name: str,
    min_bytes: int = ARTICLE_TEST_MIN_BYTES,
    max_bytes: int = ARTICLE_TEST_MAX_BYTES,
    step_bytes: int = ARTICLE_TEST_STEP_BYTES,
) -> int:
    hosts = [host for host in config.hosts_for_mode("post") if host.name == host_name]
    if not hosts:
        raise RuntimeError(f"No post host named {host_name}")
    host = hosts[0]
    low_units = max(1, math.ceil(min_bytes / step_bytes))
    high_units = max(low_units, max_bytes // step_bytes)
    best = 0
    last_error = ""
    while low_units <= high_units:
        mid = (low_units + high_units) // 2
        size = mid * step_bytes
        try:
            post_article_size_probe(host, config.newsgroup, size)
            best = size
            low_units = mid + 1
        except Exception as exc:
            last_error = str(exc)
            high_units = mid - 1
    if best <= 0:
        raise RuntimeError(f"Article size probe failed at minimum {min_bytes} bytes: {last_error}")
    db.record_host_check(host.name, host.mode, "article_size", f"max article size {best} bytes", article_size_bytes=best)
    db.log("info", "host.article_size", f"{host.name} supports article bodies up to {best} bytes")
    return best


def post_article_size_probe(host, newsgroup: str, size: int) -> None:
    token = hashlib.sha256(f"{host.name}:{size}:{time.time()}:{os.urandom(8).hex()}".encode()).hexdigest()[:32]
    subject = f"[backuprr-size-probe-{token}] ({size})"
    body = bytes((index % 251 for index in range(size)))
    with UsenetClient(host) as client:
        client.post(newsgroup, subject, body)


def run_maintenance(db: Database, config: Config, vacuum: bool = False) -> Dict[str, Any]:
    """Run bounded local cleanup; VACUUM is explicit because it can be expensive."""
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
    """Score whether a file is likely restorable from currently cataloged chunk data."""
    with db.connect() as conn:
        row = conn.execute("SELECT * FROM files WHERE path=? OR relative_path=?", (source_path, source_path)).fetchone()
        if not row:
            raise FileNotFoundError(f"No cataloged file matches {source_path}")
        chunks = conn.execute(
            """
            SELECT
              (SELECT COUNT(*) FROM chunks WHERE file_id=?) + COALESCE((SELECT chunk_count FROM chunk_manifests WHERE file_id=?), 0) AS total,
              COALESCE((SELECT SUM(CASE WHEN status='missing' THEN 1 ELSE 0 END) FROM chunks WHERE file_id=?), 0) + COALESCE((SELECT missing_count FROM chunk_manifests WHERE file_id=?), 0) AS missing,
              COALESCE((SELECT SUM(CASE WHEN status='verified' THEN 1 ELSE 0 END) FROM chunks WHERE file_id=?), 0) + COALESCE((SELECT verified_count FROM chunk_manifests WHERE file_id=?), 0) AS verified,
              COALESCE((SELECT MAX(verified_at) FROM chunks WHERE file_id=?), (SELECT updated_at FROM chunk_manifests WHERE file_id=?)) AS last_verified
            """,
            (row["id"], row["id"], row["id"], row["id"], row["id"], row["id"], row["id"], row["id"]),
        ).fetchone()
    total = int(chunks["total"] or 0)
    missing = int(chunks["missing"] or 0)
    verified = int(chunks["verified"] or 0)
    verified_ratio = (verified / total) if total else 0
    score = 0
    if total > 0:
        score += 45
    if missing == 0 and total > 0:
        score += 25
    score += int(verified_ratio * 20)
    if row["backup_par2"]:
        score += 10
    score = max(0, min(100, score))
    return {
        "file_id": int(row["id"]),
        "path": row["path"],
        "state": row["state"],
        "chunk_count": total,
        "verified_chunks": verified,
        "missing_chunks": missing,
        "confidence_score": score,
        "par2_protected": bool(row["backup_par2"]),
        "compressed": bool(row["backup_compressed"]),
        "last_verified": row["last_verify_at"] or chunks["last_verified"] or "",
        "restorable": total > 0 and missing == 0,
        "warning": "" if total > 0 and missing == 0 else "missing or unavailable chunks may prevent restore",
    }


def compression_sample(path: Path, sample_bytes: int = 2 * 1024 * 1024) -> Dict[str, Any]:
    sample_bytes = max(0, int(sample_bytes))
    if sample_bytes == 0:
        data = path.read_bytes()
    else:
        with path.open("rb") as handle:
            data = handle.read(sample_bytes)
    if not data:
        return {"sampled_bytes": 0, "compressed_bytes": 0, "gain_percent": 0.0, "compressible": False}
    compressed = zlib.compress(data, level=6)
    gain = max(0.0, round(((len(data) - len(compressed)) / len(data)) * 100, 2))
    return {
        "sampled_bytes": len(data),
        "compressed_bytes": len(compressed),
        "gain_percent": gain,
        "compressible": gain > 0,
    }


def restore_plan(db: Database, source_path: str, dest: str = "") -> Dict[str, Any]:
    confidence = restore_confidence(db, source_path)
    file_row = db.file_by_id(int(confidence["file_id"]))
    target = Path(dest) if dest else Path(confidence["path"])
    if dest and (target.exists() and target.is_dir()):
        target = target / Path(confidence["path"]).name
    return {
        **confidence,
        "target": str(target),
        "target_exists": target.exists(),
        "will_overwrite": target.exists() and target.is_file(),
        "bytes_total": int(file_row["size"]),
        "estimated_download_bytes": int(file_row["size"]),
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
