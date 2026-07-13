import fnmatch
import hashlib
import base64
import hmac
import json
import math
import os
import time
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

from .cloud_backup import backup_config_and_database
from .config import Config
from .db import Database, utcnow
from .restore import restore_sample
from .usenet import UsenetClient


ARTICLE_TEST_MIN_BYTES = 100 * 1024
ARTICLE_TEST_MAX_BYTES = 5 * 1024 * 1024
ARTICLE_TEST_STEP_BYTES = 100 * 1024
CONFIG_HISTORY_KEY = "config_history"


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
        {"id": "read-only", "label": "Read-only mode disabled", "ok": not bool(getattr(config, "read_only_mode", False)), "detail": "read-only mode is active" if getattr(config, "read_only_mode", False) else "writes enabled"},
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
    if getattr(config, "read_only_mode", False):
        alerts.append({"level": "warning", "title": "Read-only mode enabled", "detail": "posting, restore-to-origin, queue changes, and settings writes are disabled"})
    return alerts


def secret_health_report(config: Config) -> List[Dict[str, Any]]:
    key_env = getattr(config, "config_secret_key_env", "BACKUPRR_CONFIG_SECRET")
    rows = [
        {"name": "Config secret protection", "ok": bool(os.getenv(key_env)), "detail": f"{key_env} {'is set' if os.getenv(key_env) else 'is not set'}"},
        {"name": "Web UI password", "ok": bool(config.web_ui_password), "detail": "configured" if config.web_ui_password else "not configured"},
        {"name": "TOTP admin step-up", "ok": bool(os.getenv(getattr(config, "web_ui_totp_secret_env", "BACKUPRR_TOTP_SECRET"))), "detail": getattr(config, "web_ui_totp_secret_env", "BACKUPRR_TOTP_SECRET")},
        {"name": "External API keys", "ok": bool(config.external_api_keys), "detail": f"{len(config.external_api_keys)} key(s)"},
        {"name": "Manifest export encryption", "ok": (not config.manifest_export_encrypt) or bool(os.getenv(config.manifest_export_passphrase_env)), "detail": config.manifest_export_passphrase_env},
    ]
    if config.encrypt_bodies:
        rows.append({"name": "Body encryption passphrase", "ok": bool(os.getenv(config.encryption_passphrase_env)), "detail": config.encryption_passphrase_env})
    provider_passwords = sum(1 for host in config.usenet_hosts if host.password)
    rows.append({"name": "Provider credentials", "ok": provider_passwords > 0, "detail": f"{provider_passwords} stored credential(s)"})
    return rows


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


def provider_confidence_report(db: Database) -> List[Dict[str, Any]]:
    rows = db.provider_profiles()
    report = []
    for row in rows:
        checks = max(1, int(row["checks"] or 0))
        failures = int(row["failures"] or 0)
        latency = int(row["avg_latency_ms"] or 0)
        article_size = int(row["max_article_size_bytes"] or 0)
        score = 100 - min(60, int((failures / checks) * 100)) - min(20, latency // 1000)
        if article_size and article_size < 768 * 1024:
            score -= 10
        report.append({**dict(row), "confidence_score": max(0, min(100, score))})
    return report


def retention_policy_for_path(config: Config, path: str) -> Dict[str, Any]:
    """Resolve lightweight per-object retention hints from configured path patterns."""
    text = str(path or "").replace("\\", "/")
    name = Path(text).name
    for pattern in getattr(config, "retention_policy_patterns", []) or []:
        raw = str(pattern).strip()
        if not raw:
            continue
        label = "critical"
        expression = raw
        interval = int(getattr(config, "critical_verification_interval_days", 30) or 30)
        parts = raw.split(":", 2)
        if len(parts) == 3 and parts[0].strip():
            label = parts[0].strip()
            expression = parts[1].strip()
            try:
                interval = int(parts[2])
            except ValueError:
                interval = int(getattr(config, "critical_verification_interval_days", 30) or 30)
        elif len(parts) == 2 and parts[0].strip().isdigit():
            expression = parts[1].strip()
            interval = int(parts[0])
        expression = expression or raw
        lowered = expression.lower()
        if fnmatch.fnmatch(text.lower(), lowered) or fnmatch.fnmatch(name.lower(), lowered):
            return {
                "policy": label,
                "verification_interval_days": max(1, min(180, interval)),
                "matched_pattern": raw,
            }
    return {
        "policy": "standard",
        "verification_interval_days": int(getattr(config, "verification_interval_days", 90) or 90),
        "matched_pattern": "",
    }


def provider_failover_simulation(config: Config, failed_host: str = "") -> Dict[str, Any]:
    """Model whether configured read/post paths survive a single host outage."""
    failed = str(failed_host or "").strip()
    results: Dict[str, Any] = {"failed_host": failed, "modes": {}, "ok": True}
    for mode in ("read", "post"):
        hosts = config.hosts_for_mode(mode)
        remaining = [host for host in hosts if not failed or host.name != failed]
        mode_ok = bool(remaining)
        results["modes"][mode] = {
            "configured": [host.name for host in hosts],
            "remaining": [host.name for host in remaining],
            "primary": remaining[0].name if remaining else "",
            "ok": mode_ok,
            "recommendation": "" if mode_ok else f"Add at least one {mode} host or reduce dependency on {failed or 'the failed host'}.",
        }
        results["ok"] = bool(results["ok"] and mode_ok)
    return results


def threat_model_report(db: Database, config: Config) -> Dict[str, Any]:
    """Return the deployment assumptions and mitigations Backuprr can currently see."""
    stats = db.stats()
    secrets = secret_health_report(config)
    mitigations = [
        {"area": "Web UI", "status": "ok" if config.web_ui_password else "warning", "detail": "Basic Auth enabled" if config.web_ui_password else "No Web UI password configured"},
        {"area": "TOTP", "status": "ok" if os.getenv(getattr(config, "web_ui_totp_secret_env", "BACKUPRR_TOTP_SECRET")) else "warning", "detail": "Admin actions require TOTP" if os.getenv(getattr(config, "web_ui_totp_secret_env", "BACKUPRR_TOTP_SECRET")) else "TOTP env not configured"},
        {"area": "Internal API", "status": "ok", "detail": "Browser AJAX calls require an in-memory token and CSRF token"},
        {"area": "External API", "status": "ok" if config.external_api_keys else "warning", "detail": f"{len(config.external_api_keys)} API key(s) configured"},
        {"area": "Secrets", "status": "ok" if os.getenv(config.config_secret_key_env) else "warning", "detail": f"Config secret env {config.config_secret_key_env} {'is set' if os.getenv(config.config_secret_key_env) else 'is not set'}"},
        {"area": "Restore safety", "status": "ok" if config.restore_sandbox_enabled else "warning", "detail": "Origin restores are rehearsed in sandbox first" if config.restore_sandbox_enabled else "Restore sandbox is disabled"},
        {"area": "Recovery metadata", "status": "ok" if int(stats.get("chunks_total", 0) or 0) else "warning", "detail": f"{int(stats.get('chunks_total', 0) or 0)} chunk metadata row(s) tracked"},
    ]
    return {
        "assumptions": [
            "The Web UI is intended for localhost, VPN, or trusted LAN access.",
            "Usenet article subjects are obfuscated, but provider access and local config remain sensitive.",
            "The catalog database is critical restore metadata and should be backed up independently.",
        ],
        "not_protected_against": [
            "A fully compromised host with access to environment variables and config files.",
            "Provider-side retention loss beyond what verification and re-posting can detect.",
            "Exposure of the Web UI through an unauthenticated reverse proxy.",
        ],
        "mitigations": mitigations,
        "secret_health": secrets,
        "recommendations": [item["detail"] for item in mitigations if item["status"] != "ok"],
    }


def backup_readiness_report(db: Database, config: Config) -> Dict[str, Any]:
    stats = db.stats()
    total = max(1, int(stats.get("files_total", 0) or 0))
    backed = int(stats.get("files_backed_up", 0) or 0)
    missing = int(stats.get("chunks_missing", 0) or 0)
    attention = int(stats.get("queue_attention_count", 0) or 0)
    verified_chunks = int(stats.get("chunks_verified", 0) or 0)
    chunks = max(1, int(stats.get("chunks_total", 0) or 0))
    score = int((backed / total) * 55) + int((verified_chunks / chunks) * 25)
    if config.par2.get("enabled"):
        score += 10
    if config.cloud_backups:
        score += 5
    if config.restore_sandbox_enabled:
        score += 5
    score -= min(40, missing * 5 + attention * 3)
    folders = []
    for row in db.folder_rollups(25):
        item = dict(row)
        files = max(1, int(item.get("files") or 0))
        folder_score = int((int(item.get("backed_up_files") or 0) / files) * 60) + int((int(item.get("verified_files") or 0) / files) * 25)
        folder_score += min(10, int(item.get("par2_files") or 0))
        folder_score -= min(30, int(item.get("attention_files") or 0) * 5)
        folders.append({**item, "readiness_score": max(0, min(100, folder_score))})
    return {
        "score": max(0, min(100, score)),
        "files_total": int(stats.get("files_total", 0) or 0),
        "files_backed_up": backed,
        "chunks_total": int(stats.get("chunks_total", 0) or 0),
        "chunks_verified": verified_chunks,
        "chunks_missing": missing,
        "queue_attention": attention,
        "folders": folders,
    }


def maintenance_schedule_report(db: Database, config: Config) -> Dict[str, Any]:
    rows = db.maintenance_rows(10)
    tables = db.table_stats()
    reclaimable_hint = sum(int(dict(row).get("estimated_bytes") or 0) for row in tables if str(dict(row).get("table")) in {"events", "transfer_samples", "chunks"})
    return {
        "last_runs": [dict(row) for row in rows],
        "next_interval_seconds": int(config.maintenance_interval_seconds or 0),
        "estimated_reclaimable_hint_bytes": reclaimable_hint,
        "vacuum_note": "Vacuum after large chunk compaction or log pruning to return space to the filesystem.",
    }


def config_history_rows(db: Database, limit: int = 20) -> List[Dict[str, Any]]:
    try:
        rows = json.loads(db.get_meta(CONFIG_HISTORY_KEY) or "[]")
    except json.JSONDecodeError:
        rows = []
    return list(rows)[-limit:][::-1]


def record_config_history(db: Database, actor: str, keys: List[str]) -> None:
    rows = config_history_rows(db, 200)[::-1]
    rows.append({"ts": utcnow(), "actor": actor, "keys": sorted(set(keys))})
    db.set_meta(CONFIG_HISTORY_KEY, json.dumps(rows[-200:], sort_keys=True))


def restore_preflight(db: Database, config: Config, source_path: str, dest: str = "") -> Dict[str, Any]:
    plan = restore_plan(db, source_path, dest)
    issues = []
    if not plan["restorable"]:
        issues.append("file is not currently considered restorable")
    if plan["will_overwrite"] and not config.restore_sandbox_enabled:
        issues.append("restore would overwrite an existing file without restore sandbox enabled")
    if getattr(config, "read_only_mode", False) and not dest:
        issues.append("read-only mode blocks restore-to-origin")
    quarantine_recommended = bool(issues or plan["missing_chunks"])
    quarantine_path = str(Path(config.restore_sandbox_path or (Path(plan["path"]).parent / ".backuprr-quarantine")) / Path(plan["path"]).name)
    return {**plan, "issues": issues, "quarantine_recommended": quarantine_recommended, "quarantine_path": quarantine_path}


def db_growth_report(db: Database, config: Config) -> Dict[str, Any]:
    stats = db.stats()
    tables = db.table_stats()
    current_bytes = sum(int(row.get("estimated_bytes") or 0) for row in tables)
    active_files = max(1, int(stats.get("files_total", 0) or 1))
    active_bytes = max(1, int(stats.get("files_bytes_total", 0) or 1))
    bytes_per_file = current_bytes / active_files
    bytes_per_data_byte = current_bytes / active_bytes
    projections = {}
    for label, size in {"1 TiB": 1024**4, "10 TiB": 10 * 1024**4, "100 TiB": 100 * 1024**4}.items():
        projections[label] = int(max(bytes_per_file * active_files, bytes_per_data_byte * size))
    return {
        "current_estimated_bytes": current_bytes,
        "table_stats": tables,
        "reclaimable_hint": "Run maintenance with vacuum after large compaction or log pruning.",
        "projected_db_bytes": projections,
        "chunk_compaction_enabled": bool(config.compact_chunk_rows),
    }


def file_integrity_receipt(db: Database, file_id: int) -> Dict[str, Any]:
    file_row = db.file_by_id(file_id)
    manifests = []
    with db.connect() as conn:
        manifests = [dict(row) for row in conn.execute("SELECT * FROM backup_manifests WHERE file_id=? ORDER BY id DESC", (file_id,)).fetchall()]
    return {
        "file_id": int(file_row["id"]),
        "path": file_row["path"],
        "relative_path": file_row["relative_path"],
        "state": file_row["state"],
        "original_sha256": file_row["sha256"],
        "size": int(file_row["size"]),
        "chunk_count": db.chunk_count_for_file(file_id),
        "compressed": bool(file_row["backup_compressed"]),
        "par2_protected": bool(file_row["backup_par2"]),
        "last_backup_at": file_row["last_backup_at"] or "",
        "last_verify_at": file_row["last_verify_at"] or "",
        "latest_manifest": manifests[0] if manifests else {},
    }


def backup_manifest_export(db: Database, config: Config) -> Dict[str, Any]:
    if not config.manifest_export_enabled:
        return {"enabled": False, "message": "manifest export is disabled"}
    with db.connect() as conn:
        files = [dict(row) for row in conn.execute("SELECT id, path, relative_path, size, sha256, state, last_backup_at, last_verify_at, backup_compressed, backup_par2 FROM files WHERE state!='deleted' ORDER BY relative_path").fetchall()]
        manifests = [dict(row) for row in conn.execute("SELECT file_id, file_sha256, app_version, article_size, chunk_count, bytes_total, flags, manifest_json, created_at FROM backup_manifests ORDER BY file_id, id").fetchall()]
    payload = {
        "version": 1,
        "generated_at": utcnow(),
        "app_newsgroup": config.newsgroup,
        "files": files,
        "backup_manifests": manifests,
    }
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    encrypted = False
    if config.manifest_export_encrypt:
        secret = os.getenv(config.manifest_export_passphrase_env)
        if not secret:
            raise RuntimeError(f"{config.manifest_export_passphrase_env} must be set for encrypted manifest export")
        stream = hashlib.sha256(secret.encode("utf-8")).digest()
        protected = bytes(byte ^ stream[index % len(stream)] for index, byte in enumerate(raw))
        mac = hmac.new(secret.encode("utf-8"), protected, hashlib.sha256).hexdigest()
        raw = json.dumps({"encrypted": True, "mac": mac, "payload": base64.b64encode(protected).decode("ascii")}).encode("utf-8")
        encrypted = True
    return {
        "enabled": True,
        "encrypted": encrypted,
        "generated_at": payload["generated_at"],
        "file_count": len(files),
        "manifest_count": len(manifests),
        "bytes": len(raw),
        "payload": raw.decode("utf-8"),
    }


def restore_preview(db: Database, file_ids: List[int], dest: str = "") -> Dict[str, Any]:
    rows = [db.file_by_id(int(file_id)) for file_id in file_ids]
    overwrite = 0
    total_bytes = 0
    for row in rows:
        target = Path(dest) / Path(row["path"]).name if dest else Path(row["path"])
        overwrite += 1 if target.exists() else 0
        total_bytes += int(row["size"] or 0)
    return {"files": len(rows), "bytes_total": total_bytes, "overwrite_count": overwrite, "destination": dest or "origin"}


def audit_event(db: Database, config: Config, actor: str, action: str, data: Dict[str, Any]) -> None:
    if not config.audit_mode:
        return
    secret = os.getenv(config.audit_secret_key_env) or "backuprr-local-audit"
    payload = {"actor": actor, "action": action, "data": data, "ts": utcnow()}
    signature = hmac.new(secret.encode("utf-8"), json.dumps(payload, sort_keys=True).encode("utf-8"), hashlib.sha256).hexdigest()
    db.log("info", "audit", f"{actor} {action}", data=json.dumps({**payload, "signature": signature}, sort_keys=True))


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


def restore_confidence(db: Database, source_path: str, config: Config | None = None) -> Dict[str, Any]:
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
    policy = retention_policy_for_path(config, str(row["relative_path"] or row["path"])) if config else {
        "policy": "standard",
        "verification_interval_days": 90,
        "matched_pattern": "",
    }
    if config:
        provider_scores = [int(item.get("confidence_score", 0) or 0) for item in provider_confidence_report(db)]
        if provider_scores:
            score += int((sum(provider_scores) / len(provider_scores) - 50) / 10)
        drill_rows = db.restore_drill_rows(1)
        if drill_rows and drill_rows[0]["status"] == "ok":
            score += 5
        if policy["policy"] != "standard":
            score += 3
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
        "retention_policy": policy,
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


def run_restore_rehearsal(db: Database, config: Config, source_path: str, sample_bytes: int | None = None) -> Dict[str, Any]:
    """Read restore data into memory and discard it, proving the path without writing files."""
    size = int(sample_bytes or config.restore_drill_sample_bytes or 1024 * 1024)
    started = time.perf_counter()
    payload = restore_sample(db, config, source_path, size)
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    with db.connect() as conn:
        row = conn.execute("SELECT id FROM files WHERE path=? OR relative_path=?", (source_path, source_path)).fetchone()
    file_id = int(row["id"]) if row else None
    db.record_restore_drill(file_id, source_path, "ok", len(payload), f"restore rehearsal read {len(payload)} bytes in {elapsed_ms} ms")
    return {"status": "ok", "path": source_path, "bytes_checked": len(payload), "elapsed_ms": elapsed_ms}


def incident_mode(db: Database, config: Config) -> Dict[str, Any]:
    """Pause workers and gather recovery artifacts after a suspected incident."""
    db.set_paused("all", True)
    diagnostics = diagnostics_bundle(db, config)
    manifest = backup_manifest_export(db, config) if config.manifest_export_enabled else {"enabled": False}
    cloud_results = backup_config_and_database(db, config) if config.cloud_backups else []
    db.log("warning", "incident.mode", "Incident mode enabled: workers paused and recovery artifacts prepared")
    return {
        "ok": True,
        "paused": db.paused_kinds(),
        "diagnostics_events": len(diagnostics.get("recent_events", [])),
        "manifest_bytes": manifest.get("bytes", 0),
        "cloud_backups": cloud_results,
    }
