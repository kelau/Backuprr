import itertools
import base64
import copy
import hmac
import json
import math
import os
import secrets
import struct
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlparse
from zipfile import ZIP_DEFLATED, ZipFile

from . import __version__
from .backup import discover_par2_command, verify_due_chunks, verify_file_chunks
from .cloud_backup import backup_config_and_database
from .config import Config, update_config
from .db import Database
from .log_forwarding import LogForwarder
from .monitor import BackupMonitor, CatalogMonitor, VerificationMonitor, CloudBackupMonitor, MaintenanceMonitor, RestoreDrillMonitor, UpdateCheckMonitor
from .operations import (
    audit_event,
    backup_manifest_export,
    backup_readiness_report,
    check_usenet_hosts,
    config_history_rows,
    db_growth_report,
    diagnostics_bundle,
    disaster_recovery_report,
    dry_run_plan,
    file_integrity_receipt,
    incident_mode,
    notification_alerts,
    prometheus_metrics,
    provider_failover_simulation,
    provider_confidence_report,
    record_config_history,
    restore_confidence,
    restore_plan,
    restore_preflight,
    restore_preview,
    run_restore_rehearsal,
    run_maintenance,
    run_restore_drill,
    setup_health_check,
    maintenance_schedule_report,
    synthetic_catalog_plan,
    test_post_host_article_size,
    threat_model_report,
)
from .queueing import enqueue_unbacked, move, prioritize
from .restore import restore_file, restore_folder, restored_payloads
from .update_checker import check_for_updates, update_result


def rowdicts(rows):
    return [dict(row) for row in rows]


def queue_reason_detail(reason: str, status: str = "") -> str:
    """Translate internal queue reason codes into UI-safe next-action guidance."""
    details = {
        "network-blocked": "The OS or sandbox blocked NNTP socket access; restart/elevate the web process and retry.",
        "missing-chunks": "Verification found missing articles; the file is queued for another backup run.",
        "file-changing": "The file is still changing or locked; Backuprr will retry after the stability window.",
        "hourly-limit": "The hourly posting limit paused this file; it will continue when budget is available.",
        "startup-posting-retry": "Posting was interrupted by restart; existing chunks will be reused where safe.",
        "manual": "Manually queued by the user.",
    }
    if status == "failed":
        return details.get(reason, "Posting failed; check the Log page for the provider/tool error and then retry.")
    return details.get(reason, "")


def mbps_from_bps(value: float) -> float:
    return round((float(value or 0) * 8) / 1_000_000, 2)


def throughput_summary(samples: list[dict[str, Any]]) -> dict[str, float]:
    if not samples:
        return {"upload_mbps": 0.0, "download_mbps": 0.0, "average_upload_mbps": 0.0, "average_download_mbps": 0.0}
    recent = samples[-5:]
    current = samples[-1]
    avg_upload = sum(float(sample.get("upload_bps") or 0) for sample in recent) / max(1, len(recent))
    avg_download = sum(float(sample.get("download_bps") or 0) for sample in recent) / max(1, len(recent))
    return {
        "upload_mbps": mbps_from_bps(float(current.get("upload_bps") or 0)),
        "download_mbps": mbps_from_bps(float(current.get("download_bps") or 0)),
        "average_upload_mbps": mbps_from_bps(avg_upload),
        "average_download_mbps": mbps_from_bps(avg_download),
    }


PAGE_ROUTES = {
    "/": "Status",
    "/status": "Status",
    "/files": "Files",
    "/search": "Search",
    "/log": "Log",
    "/queue": "Queue",
    "/tasks": "Tasks",
    "/verification": "Verification",
    "/statistics": "Statistics",
    "/operations": "Operations",
    "/security": "Security",
    "/settings": "Settings",
    "/about": "About",
}

INTERNAL_API_TOKEN = secrets.token_urlsafe(32)
CSRF_TOKEN = secrets.token_urlsafe(32)


def thread_usage_summary(posting_rows: list[dict[str, Any]], article_size: int, configured_threads: int) -> dict[str, int]:
    total = max(1, int(configured_threads or 1))
    size = max(1, int(article_size or 1))
    remaining_chunks = 0
    for row in posting_rows:
        expected = max(1, math.ceil(int(row.get("size") or 0) / size))
        posted = int(row.get("posted_chunks") or row.get("progress_chunks") or 0)
        remaining_chunks += max(0, expected - posted)
    return {"in_use": min(total, remaining_chunks), "total": total}


def hourly_post_budget(db: Database, config: Config) -> dict[str, Any]:
    limit = max(0, int(getattr(config, "hourly_post_limit_bytes", 0) or 0))
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(microsecond=0).isoformat()
    used = db.transfer_bytes_since("upload", cutoff)
    return {
        "used_bytes": used,
        "limit_bytes": limit,
        "remaining_bytes": max(0, limit - used) if limit else 0,
        "percent": min(100.0, round((used / limit) * 100, 1)) if limit else 0,
        "enabled": 1 if limit else 0,
    }


def totp_valid(secret: str, code: str, now: int | None = None) -> bool:
    secret = str(secret or "").strip().replace(" ", "")
    code = str(code or "").strip()
    if not secret or not code.isdigit():
        return False
    try:
        key = base64.b32decode(secret.upper(), casefold=True)
    except Exception:
        key = secret.encode("utf-8")
    timestamp = int(now if now is not None else time.time())
    for offset in (-1, 0, 1):
        counter = int(timestamp // 30) + offset
        digest = hmac.new(key, struct.pack(">Q", counter), "sha1").digest()
        index = digest[-1] & 0x0F
        value = struct.unpack(">I", digest[index : index + 4])[0] & 0x7FFFFFFF
        if hmac.compare_digest(f"{value % 1_000_000:06d}", code):
            return True
    return False


class Handler(BaseHTTPRequestHandler):
    config: Config
    config_path: str
    db: Database
    monitor: CatalogMonitor
    backup_monitor: BackupMonitor
    verification_monitor: VerificationMonitor
    cloud_backup_monitor: CloudBackupMonitor
    maintenance_monitor: MaintenanceMonitor
    restore_drill_monitor: RestoreDrillMonitor
    update_check_monitor: UpdateCheckMonitor
    operation_lock = threading.Lock()
    operation_counter = itertools.count(1)
    operation_revision = 0
    operations: dict[str, dict[str, Any]] = {}
    rate_limit_lock = threading.Lock()
    rate_limit_hits: dict[str, list[float]] = {}

    def log_message(self, fmt: str, *args: Any) -> None:
        if getattr(self.config, "log_web_access", False):
            self.db.log("verbose", "web.access", fmt % args)

    def send_json(self, data: Any, status: int = 200) -> None:
        payload = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(payload)

    def send_text(self, text: str, content_type: str = "text/plain; charset=utf-8", status: int = 200) -> None:
        payload = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(payload)

    def send_security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")

    def unauthorized(self, message: str = "unauthorized") -> None:
        if self.config.web_ui_password:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("WWW-Authenticate", 'Basic realm="Backuprr"')
            self.send_security_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"error": message}).encode("utf-8"))
            return
        self.send_json({"error": message}, 401)

    def forbidden(self, message: str = "forbidden") -> None:
        self.send_json({"error": message}, 403)

    def web_ui_authorized(self) -> bool:
        """Optional Basic Auth for browser pages and the internal AJAX API."""
        if not self.config.web_ui_password:
            return True
        auth = self.headers.get("Authorization", "")
        if not auth.lower().startswith("basic "):
            return False
        try:
            decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
            username, password = decoded.split(":", 1)
        except Exception:
            return False
        return hmac.compare_digest(username, self.config.web_ui_username) and hmac.compare_digest(password, self.config.web_ui_password)

    def web_role_allows(self, action: str) -> bool:
        if getattr(self.config, "read_only_mode", False) and action != "read":
            return False
        role = getattr(self.config, "web_ui_role", "admin")
        if role == "admin":
            return True
        if role == "operator":
            return action in {"run", "restore", "queue", "read"}
        return action == "read"

    def require_role(self, action: str) -> bool:
        if getattr(self.config, "read_only_mode", False) and action != "read":
            if self.path.startswith("/api/settings") and getattr(self, "_allow_read_only_disable", False):
                return True
            self.forbidden("read-only mode is enabled")
            return False
        if self.web_role_allows(action):
            return True
        self.forbidden(f"{getattr(self.config, 'web_ui_role', 'read_only')} role cannot perform {action} actions")
        return False

    def require_totp(self, action: str) -> bool:
        secret = os.getenv(getattr(self.config, "web_ui_totp_secret_env", "BACKUPRR_TOTP_SECRET"))
        if not secret or action != "admin":
            return True
        if totp_valid(secret, self.headers.get("X-Backuprr-TOTP", "")):
            return True
        self.forbidden("valid TOTP code is required for admin actions")
        return False

    def client_key(self, external: bool = False) -> str:
        supplied = self.headers.get("X-API-Key", "") if external else ""
        return f"{self.client_address[0]}:{'external' if external else 'internal'}:{supplied[:12]}"

    def rate_limit_allows(self, external: bool = False) -> bool:
        limit = int(
            getattr(
                self.config,
                "external_api_rate_limit_per_minute" if external else "api_rate_limit_per_minute",
                0,
            )
            or 0
        )
        if limit <= 0:
            return True
        now = time.time()
        cutoff = now - 60
        key = self.client_key(external)
        with Handler.rate_limit_lock:
            hits = [item for item in Handler.rate_limit_hits.get(key, []) if item >= cutoff]
            if len(hits) >= limit:
                Handler.rate_limit_hits[key] = hits
                return False
            hits.append(now)
            Handler.rate_limit_hits[key] = hits
        return True

    def csrf_allows(self) -> bool:
        supplied = self.headers.get("X-Backuprr-CSRF", "")
        return bool(supplied) and secrets.compare_digest(supplied, CSRF_TOKEN)

    def action_for_post_path(self, path: str) -> str:
        if path in {"/api/settings", "/api/settings/validate", "/api/settings/profile/import", "/api/settings/par2/discover", "/api/maintenance/run", "/api/update-check/run"}:
            return "admin"
        if path.startswith("/api/restore"):
            return "restore"
        if path.startswith("/api/queue") or path.startswith("/api/files") or path.startswith("/api/folders"):
            return "queue"
        return "run"

    def internal_api_authorized(self, query: dict[str, list[str]] | None = None) -> bool:
        supplied = self.headers.get("X-Backuprr-Internal-Token", "")
        if not supplied and query:
            supplied = query.get("internal_token", [""])[0]
        return bool(supplied) and secrets.compare_digest(supplied, INTERNAL_API_TOKEN)

    def external_api_key(self) -> str:
        configured = [str(key) for key in getattr(self.config, "external_api_keys", []) if str(key)]
        if not configured:
            return ""
        supplied = self.headers.get("X-API-Key", "")
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            supplied = auth.split(" ", 1)[1].strip()
        for key in configured:
            if secrets.compare_digest(supplied, key):
                return key
        return ""

    def external_api_authorized(self) -> bool:
        return bool(self.external_api_key())

    def external_api_scope_allows(self, scope: str) -> bool:
        key = self.external_api_key()
        if not key:
            return False
        scopes = getattr(self.config, "external_api_key_scopes", {}).get(key, [])
        return not scopes or "admin" in scopes or scope in scopes

    def external_scope_for_path(self, suffix: str, method: str = "GET") -> str:
        if method == "GET":
            return "read"
        if suffix == "/backup/run":
            return "backup"
        if suffix == "/scan":
            return "scan"
        if suffix == "/verify/start":
            return "verify"
        return "admin"

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def create_operation(self, kind: str, file_id: int | None, label: str, total: int = 0) -> str:
        with Handler.operation_lock:
            operation_id = str(next(Handler.operation_counter))
            correlation_id = f"{kind}-{operation_id}-{secrets.token_hex(4)}"
            Handler.operations[operation_id] = {
                "id": operation_id,
                "correlation_id": correlation_id,
                "kind": kind,
                "file_id": file_id,
                "label": label,
                "status": "running",
                "cancel_requested": False,
                "done": 0,
                "total": int(total or 0),
                "bytes_done": 0,
                "message": "Starting",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            Handler.operation_revision += 1
            return operation_id

    def operation_canceled(self, operation_id: str) -> bool:
        with Handler.operation_lock:
            return bool(Handler.operations.get(operation_id, {}).get("cancel_requested"))

    def cancel_operation(self, operation_id: str) -> bool:
        with Handler.operation_lock:
            operation = Handler.operations.get(operation_id)
            if not operation or operation.get("status") != "running":
                return False
            operation["cancel_requested"] = True
            operation["message"] = "Cancellation requested"
            operation["updated_at"] = datetime.now(timezone.utc).isoformat()
            Handler.operation_revision += 1
            return True

    def update_operation(self, operation_id: str, done: int, total: int | None = None, bytes_done: int | None = None, message: str = "") -> None:
        with Handler.operation_lock:
            operation = Handler.operations.get(operation_id)
            if not operation:
                return
            operation["done"] = int(done)
            if total is not None:
                operation["total"] = int(total)
            if bytes_done is not None:
                operation["bytes_done"] = int(bytes_done)
            if message:
                operation["message"] = message
            operation["updated_at"] = datetime.now(timezone.utc).isoformat()
            Handler.operation_revision += 1

    def finish_operation(self, operation_id: str, status: str, message: str = "") -> None:
        with Handler.operation_lock:
            operation = Handler.operations.get(operation_id)
            if not operation:
                return
            operation["status"] = status
            if message:
                operation["message"] = message
            if status == "done" and operation.get("total"):
                operation["done"] = operation["total"]
            operation["updated_at"] = datetime.now(timezone.utc).isoformat()
            operation["finished_at"] = datetime.now(timezone.utc).isoformat()
            Handler.operation_revision += 1

    def operation_rows(self) -> list[dict[str, Any]]:
        cutoff = time.time() - 600
        rows: list[dict[str, Any]] = []
        with Handler.operation_lock:
            stale = []
            for operation_id, operation in Handler.operations.items():
                updated = datetime.fromisoformat(str(operation["updated_at"])).timestamp()
                if operation.get("status") != "running" and updated < cutoff:
                    stale.append(operation_id)
                else:
                    rows.append(dict(operation))
            for operation_id in stale:
                Handler.operations.pop(operation_id, None)
        return rows

    def start_restore_operation(self, source_path: str, dest: str | None = None) -> str:
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT id, path, relative_path FROM files WHERE path=? OR relative_path=?",
                (source_path, source_path),
            ).fetchone()
            if not row:
                raise FileNotFoundError(f"No cataloged file matches {source_path}")
        operation_id = self.create_operation("restore", int(row["id"]), str(row["relative_path"] or row["path"]), self.db.chunk_count_for_file(int(row["id"])))

        def worker() -> None:
            try:
                def progress(done: int, total_chunks: int, bytes_done: int) -> None:
                    if self.operation_canceled(operation_id):
                        raise RuntimeError("operation canceled")
                    self.update_operation(operation_id, done, total_chunks, bytes_done, f"Restored {done}/{total_chunks} chunks")

                target = restore_file(self.db, self.config, source_path, dest, progress=progress)
                self.finish_operation(operation_id, "done", f"Restored to {target}")
            except Exception as exc:
                self.db.log("error", "restore", f"Restore failed for {source_path}: {exc}", int(row["id"]))
                self.finish_operation(operation_id, "canceled" if "canceled" in str(exc).lower() else "failed", str(exc))

        threading.Thread(target=worker, name=f"backuprr-restore-{operation_id}", daemon=True).start()
        return operation_id

    def start_folder_restore_operations(self, folder_path: str, dest: str | None = None) -> list[str]:
        raw_folder = str(folder_path).rstrip("\\/")
        alt_folder = raw_folder.replace("/", "\\")
        folder = str(Path(folder_path).resolve()) if Path(folder_path).is_absolute() else raw_folder
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, path, relative_path,
                       ((SELECT COUNT(*) FROM chunks WHERE file_id=files.id) + COALESCE((SELECT chunk_count FROM chunk_manifests WHERE file_id=files.id), 0)) AS chunk_count
                FROM files
                WHERE (
                    id IN (SELECT DISTINCT file_id FROM chunks)
                    OR id IN (SELECT file_id FROM chunk_manifests)
                )
                  AND (path LIKE ? OR relative_path = ? OR relative_path LIKE ? OR relative_path = ? OR relative_path LIKE ?)
                ORDER BY relative_path
                """,
                (folder + "%", raw_folder, raw_folder + "/%", alt_folder, alt_folder + "\\%"),
            ).fetchall()
        operations: list[tuple[str, Any, str | None]] = []
        for row in rows:
            target = None
            if dest:
                if Path(folder).is_absolute():
                    relative = Path(row["path"]).relative_to(folder)
                else:
                    relative_text = str(row["relative_path"]).replace("\\", "/")
                    relative = Path(relative_text).relative_to(raw_folder.replace("\\", "/"))
                target = str(Path(dest) / relative)
            operation_id = self.create_operation("restore", int(row["id"]), str(row["relative_path"] or row["path"]), int(row["chunk_count"] or 0))
            operations.append((operation_id, row, target))

        def worker() -> None:
            for operation_id, row, target in operations:
                try:
                    def progress(done: int, total_chunks: int, bytes_done: int, op_id: str = operation_id) -> None:
                        if self.operation_canceled(op_id):
                            raise RuntimeError("operation canceled")
                        self.update_operation(op_id, done, total_chunks, bytes_done, f"Restored {done}/{total_chunks} chunks")

                    restored_to = restore_file(self.db, self.config, str(row["path"]), target, progress=progress)
                    self.finish_operation(operation_id, "done", f"Restored to {restored_to}")
                except Exception as exc:
                    self.db.log("error", "restore", f"Restore failed for {row['path']}: {exc}", int(row["id"]))
                    self.finish_operation(operation_id, "canceled" if "canceled" in str(exc).lower() else "failed", str(exc))

        threading.Thread(target=worker, name="backuprr-folder-restore", daemon=True).start()
        return [operation_id for operation_id, _, _ in operations]

    def start_verification_operation(self, file_ids: list[int], force: bool = False) -> list[str]:
        if file_ids:
            operations: list[tuple[str, int]] = []
            for file_id in file_ids:
                row = self.db.file_by_id(int(file_id))
                label = str(row["relative_path"] or row["path"])
                operation_id = self.create_operation("verify", int(file_id), label, self.db.chunk_count_for_file(int(file_id)))
                operations.append((operation_id, int(file_id)))

            def selected_worker() -> None:
                for operation_id, file_id in operations:
                    try:
                        def progress(done: int, total: int, op_id: str = operation_id) -> None:
                            if self.operation_canceled(op_id):
                                raise RuntimeError("operation canceled")
                            self.update_operation(op_id, done, total, message=f"Verified {done}/{total} chunks")

                        verified = verify_file_chunks(self.db, self.config, [file_id], progress=progress)
                        self.finish_operation(operation_id, "done", f"Verified {verified} chunks")
                    except Exception as exc:
                        self.db.log("error", "verify", f"Verification failed: {exc}", file_id)
                        self.finish_operation(operation_id, "canceled" if "canceled" in str(exc).lower() else "failed", str(exc))

            threading.Thread(target=selected_worker, name="backuprr-selected-verify", daemon=True).start()
            return [operation_id for operation_id, _ in operations]

        operation_id = self.create_operation("verify", None, "All due chunks")

        def worker() -> None:
            try:
                def progress(done: int, total: int) -> None:
                    if self.operation_canceled(operation_id):
                        raise RuntimeError("operation canceled")
                    self.update_operation(operation_id, done, total, message=f"Verified {done}/{total} chunks")

                verified = verify_due_chunks(self.db, self.config, force=force, progress=progress)
                self.finish_operation(operation_id, "done", f"Verified {verified} chunks")
            except Exception as exc:
                self.db.log("error", "verify", f"Verification failed: {exc}")
                self.finish_operation(operation_id, "canceled" if "canceled" in str(exc).lower() else "failed", str(exc))

        threading.Thread(target=worker, name=f"backuprr-verify-{operation_id}", daemon=True).start()
        return [operation_id]

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/healthz":
            self.send_json({"ok": True, "version": __version__, "database": self.config.db_path().exists()})
        elif parsed.path == "/metrics":
            self.send_text(prometheus_metrics(self.db, self.config), "text/plain; version=0.0.4; charset=utf-8")
        elif parsed.path.startswith("/external-api/") and not self.rate_limit_allows(external=True):
            self.send_json({"error": "rate limit exceeded"}, 429)
        elif (parsed.path in PAGE_ROUTES or parsed.path.startswith("/api/")) and not self.web_ui_authorized():
            self.unauthorized("web UI authentication is required")
        elif parsed.path.startswith("/api/") and not self.rate_limit_allows(external=False):
            self.send_json({"error": "rate limit exceeded"}, 429)
        elif parsed.path in PAGE_ROUTES:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_security_headers()
            self.end_headers()
            self.wfile.write(INDEX_HTML.replace("__INTERNAL_API_TOKEN__", INTERNAL_API_TOKEN).replace("__CSRF_TOKEN__", CSRF_TOKEN).encode("utf-8"))
        elif parsed.path.startswith("/external-api/"):
            if not self.external_api_authorized():
                self.unauthorized("external API key is required")
                return
            suffix = parsed.path.removeprefix("/external-api")
            if not self.external_api_scope_allows(self.external_scope_for_path(suffix, "GET")):
                self.forbidden("external API key scope does not allow this action")
                return
            self.handle_external_get(parsed, query)
        elif parsed.path.startswith("/api/") and not self.internal_api_authorized(query):
            self.forbidden("internal API token is required")
        elif parsed.path == "/api/status":
            self.send_json(self.status_payload())
        elif parsed.path == "/api/speed":
            self.send_json(self.db.speed_samples(int(query.get("minutes", ["30"])[0]), int(query.get("bucket", ["60"])[0])))
        elif parsed.path == "/api/events/stream":
            self.stream_changes()
        elif parsed.path == "/api/files":
            page = max(1, int(query.get("page", ["1"])[0]))
            page_size = max(1, min(500, int(query.get("page_size", query.get("limit", ["200"]))[0])))
            search = query.get("q", [""])[0]
            include_deleted = query.get("include_deleted", ["0"])[0] in {"1", "true", "yes"}
            unbacked_only = query.get("unbacked", ["0"])[0] in {"1", "true", "yes"}
            sort_by = query.get("sort", ["relative_path"])[0]
            sort_dir = query.get("dir", ["asc"])[0]
            offset = (page - 1) * page_size
            self.send_json(
                {
                    "rows": rowdicts(self.db.list_files(page_size, offset, search, include_deleted, unbacked_only, sort_by, sort_dir)),
                    "page": page,
                    "page_size": page_size,
                    "total": self.db.file_count(search, include_deleted, unbacked_only),
                    "sort": sort_by,
                    "dir": sort_dir,
                }
            )
        elif parsed.path == "/api/search":
            self.send_json(rowdicts(self.db.search_files(query.get("q", [""])[0])))
        elif parsed.path == "/api/statistics":
            self.send_json(
                {
                    "stats": self.db.stats(),
                    "tasks": self.all_tasks(),
                    "speed": self.db.speed_samples(120, 300),
                    "events": rowdicts(self.db.list_events(limit=50, exclude_event_types=["web.access"])),
                    "backup_runs": rowdicts(self.db.backup_run_rows(20)),
                    "backup_manifests": rowdicts(self.db.backup_manifest_rows(20)),
                    "host_health": rowdicts(self.db.host_health_rows(20)),
                    "provider_profiles": rowdicts(self.db.provider_profiles()),
                    "db_tables": self.db.table_stats(),
                    "verification_backlog": self.db.verification_backlog_summary(self.config.verification_interval_days),
                    "maintenance": rowdicts(self.db.maintenance_rows(20)),
                    "restore_drills": rowdicts(self.db.restore_drill_rows(20)),
                    "folder_rollups": self.db.folder_rollups(100),
                    "provider_confidence": provider_confidence_report(self.db),
                    "db_growth": db_growth_report(self.db, self.config),
                }
            )
        elif parsed.path == "/api/setup-health":
            self.send_json(setup_health_check(self.db, self.config))
        elif parsed.path == "/api/alerts":
            self.send_json({"alerts": notification_alerts(self.db, self.config)})
        elif parsed.path == "/api/diagnostics":
            self.send_json(diagnostics_bundle(self.db, self.config))
        elif parsed.path == "/api/provider-confidence":
            self.send_json(provider_confidence_report(self.db))
        elif parsed.path == "/api/provider-failover":
            self.send_json(provider_failover_simulation(self.config, query.get("host", [""])[0]))
        elif parsed.path == "/api/threat-model":
            self.send_json(threat_model_report(self.db, self.config))
        elif parsed.path == "/api/readiness":
            self.send_json(backup_readiness_report(self.db, self.config))
        elif parsed.path == "/api/maintenance/schedule":
            self.send_json(maintenance_schedule_report(self.db, self.config))
        elif parsed.path == "/api/config/history":
            self.send_json({"rows": config_history_rows(self.db, int(query.get("limit", ["20"])[0]))})
        elif parsed.path == "/api/db-growth":
            self.send_json(db_growth_report(self.db, self.config))
        elif parsed.path == "/api/manifest/export":
            self.send_json(backup_manifest_export(self.db, self.config))
        elif parsed.path == "/api/files/receipt":
            self.send_json(file_integrity_receipt(self.db, int(query.get("file_id", ["0"])[0])))
        elif parsed.path == "/api/dry-run":
            self.send_json(dry_run_plan(self.db, self.config))
        elif parsed.path == "/api/benchmark":
            files = int(query.get("files", ["50000"])[0])
            size = int(query.get("size", [str(1024 * 1024 * 1024)])[0])
            folders = int(query.get("folders", ["1000"])[0])
            self.send_json(synthetic_catalog_plan(files, size, self.config.article_size, folders))
        elif parsed.path == "/api/disaster-recovery":
            self.send_json(disaster_recovery_report(self.db, self.config))
        elif parsed.path == "/api/health":
            self.send_json({"hosts": rowdicts(self.db.host_health_rows(50))})
        elif parsed.path == "/api/backup-runs":
            self.send_json(rowdicts(self.db.backup_run_rows(int(query.get("limit", ["50"])[0]))))
        elif parsed.path == "/api/backup-manifests":
            self.send_json(rowdicts(self.db.backup_manifest_rows(int(query.get("limit", ["50"])[0]))))
        elif parsed.path == "/api/provider-profiles":
            self.send_json(rowdicts(self.db.provider_profiles()))
        elif parsed.path == "/api/db-tables":
            self.send_json(self.db.table_stats())
        elif parsed.path == "/api/maintenance":
            self.send_json(rowdicts(self.db.maintenance_rows(int(query.get("limit", ["50"])[0]))))
        elif parsed.path == "/api/restore-drills":
            self.send_json(rowdicts(self.db.restore_drill_rows(int(query.get("limit", ["50"])[0]))))
        elif parsed.path == "/api/update-check":
            self.send_json(update_result(self.db))
        elif parsed.path == "/api/restore/download":
            self.stream_restore_download(query.get("path", [""])[0])
        elif parsed.path == "/api/restore/download-zip":
            self.stream_restore_zip([int(item) for item in query.get("file_id", [])])
        elif parsed.path == "/api/verification":
            page = max(1, int(query.get("page", ["1"])[0]))
            page_size = max(1, min(200, int(query.get("page_size", ["25"])[0])))
            verification_state = query.get("state", [""])[0]
            search = query.get("q", [""])[0]
            sort_by = query.get("sort", [""])[0]
            sort_dir = query.get("dir", ["asc"])[0]
            offset = (page - 1) * page_size
            self.send_json(
                {
                    "rows": rowdicts(self.db.verification_rows(page_size, offset, verification_state, search, sort_by, sort_dir)),
                    "page": page,
                    "page_size": page_size,
                    "total": self.db.verification_count(verification_state, search),
                    "state": verification_state,
                    "sort": sort_by,
                    "dir": sort_dir,
                }
            )
        elif parsed.path == "/api/log":
            levels = query.get("level", [])
            if not levels and query.get("levels"):
                levels = [item for group in query.get("levels", []) for item in group.split(",")]
            event_types = query.get("event_type", [])
            exclude_event_types = query.get("exclude_event_type", [])
            page = max(1, int(query.get("page", ["1"])[0]))
            page_size = max(1, min(500, int(query.get("page_size", query.get("limit", ["100"]))[0])))
            search = query.get("q", [""])[0]
            sort_by = query.get("sort", ["id"])[0]
            sort_dir = query.get("dir", ["desc"])[0]
            after_id = int(query.get("after_id", ["0"])[0] or 0)
            if after_id > 0:
                self.send_json(
                    {
                        "rows": rowdicts(self.db.list_events_after_id(after_id, levels, page_size, event_types, exclude_event_types, search)),
                        "page": 1,
                        "page_size": page_size,
                        "after_id": after_id,
                        "incremental": True,
                    }
                )
                return
            offset = (page - 1) * page_size
            self.send_json(
                {
                    "rows": rowdicts(self.db.list_events(levels, page_size, event_types, exclude_event_types, offset, search, sort_by, sort_dir)),
                    "page": page,
                    "page_size": page_size,
                    "total": self.db.event_count(levels, event_types, exclude_event_types, search),
                    "sort": sort_by,
                    "dir": sort_dir,
                }
            )
        elif parsed.path == "/api/log/event-types":
            self.send_json(self.db.event_types())
        elif parsed.path == "/api/queue":
            self.db.cleanup_completed_queue()
            page = max(1, int(query.get("page", ["1"])[0]))
            page_size = max(1, min(100, int(query.get("page_size", ["10"])[0])))
            status = query.get("status", [None])[0]
            sort_by = query.get("sort", [""])[0]
            sort_dir = query.get("dir", ["asc"])[0]
            offset = (page - 1) * page_size
            rows = [self.queue_row_payload(row) for row in self.db.list_queue_sorted(status=status, limit=page_size, offset=offset, sort_by=sort_by, sort_dir=sort_dir)]
            self.send_json({"rows": rows, "page": page, "page_size": page_size, "total": self.db.queue_count(status=status), "sort": sort_by, "dir": sort_dir})
        elif parsed.path == "/api/tasks":
            self.send_json(self.all_tasks())
        elif parsed.path == "/api/settings":
            self.send_json(self.config.public_dict())
        elif parsed.path == "/api/settings/profile/export":
            self.send_json({"profile": self.config.public_dict(), "exported_at": datetime.now(timezone.utc).isoformat(), "version": __version__})
        elif parsed.path == "/api/operations/progress":
            self.send_json({"operations": self.operation_rows()})
        else:
            self.send_json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path.startswith("/external-api/"):
                if not self.rate_limit_allows(external=True):
                    self.send_json({"error": "rate limit exceeded"}, 429)
                    return
                if not self.external_api_authorized():
                    self.unauthorized("external API key is required")
                    return
                suffix = parsed.path.removeprefix("/external-api")
                if not self.external_api_scope_allows(self.external_scope_for_path(suffix, "POST")):
                    self.forbidden("external API key scope does not allow this action")
                    return
                if getattr(self.config, "read_only_mode", False):
                    self.forbidden("read-only mode is enabled")
                    return
                self.handle_external_post(parsed)
                return
            if parsed.path.startswith("/api/") and not self.web_ui_authorized():
                self.unauthorized("web UI authentication is required")
                return
            if parsed.path.startswith("/api/") and not self.internal_api_authorized():
                self.forbidden("internal API token is required")
                return
            if parsed.path.startswith("/api/") and not self.csrf_allows():
                self.forbidden("CSRF token is required")
                return
            if parsed.path.startswith("/api/") and not self.rate_limit_allows(external=False):
                self.send_json({"error": "rate limit exceeded"}, 429)
                return
            data = self.read_json()
            self._allow_read_only_disable = (
                bool(getattr(self.config, "read_only_mode", False))
                and parsed.path == "/api/settings"
                and set(data.keys()) <= {"read_only_mode"}
                and data.get("read_only_mode") is False
            )
            if parsed.path.startswith("/api/") and not self.require_role(self.action_for_post_path(parsed.path)):
                return
            if parsed.path.startswith("/api/") and not self.require_totp(self.action_for_post_path(parsed.path)):
                return
            if parsed.path == "/api/scan":
                self.send_json({"files": self.monitor.scan_once()})
            elif parsed.path == "/api/queue/enqueue-unbacked":
                self.send_json({"queued": enqueue_unbacked(self.db, self.config)})
            elif parsed.path == "/api/queue/prioritize":
                self.send_json({"changed": prioritize(self.db, data.get("filter", "older-first"))})
            elif parsed.path == "/api/queue/move":
                move(self.db, int(data["file_id"]), int(data["position"]))
                self.send_json({"ok": True})
            elif parsed.path == "/api/files/queue":
                self.db.queue_file(int(data["file_id"]), priority=int(data.get("priority", 100)), reason="manual")
                self.send_json({"ok": True})
            elif parsed.path == "/api/files/priority":
                self.db.boost_queue_priority(int(data["file_id"]), amount=int(data.get("amount", 10)))
                self.send_json({"ok": True})
            elif parsed.path == "/api/files/priority-many":
                changed = 0
                for file_id in data.get("file_ids", []):
                    self.db.boost_queue_priority(int(file_id), amount=int(data.get("amount", 10)))
                    changed += 1
                self.send_json({"ok": True, "changed": changed})
            elif parsed.path == "/api/folders/priority":
                self.send_json({"changed": self.db.boost_folder_priority(data["path"], amount=int(data.get("amount", 10)))})
            elif parsed.path == "/api/post-next":
                self.send_json({"file_id": self.backup_monitor.post_once()})
            elif parsed.path == "/api/backup/run":
                self.backup_monitor.trigger()
                self.send_json({"ok": True})
            elif parsed.path == "/api/verify":
                file_ids = [int(file_id) for file_id in data.get("file_ids", [])]
                self.send_json({"verified": self.verification_monitor.verify_once(force=bool(data.get("force")) or bool(file_ids), file_ids=file_ids)})
            elif parsed.path == "/api/verify/start":
                file_ids = [int(file_id) for file_id in data.get("file_ids", [])]
                self.send_json({"operation_ids": self.start_verification_operation(file_ids, force=bool(data.get("force")) or bool(file_ids))})
            elif parsed.path == "/api/cloud-backup":
                results = backup_config_and_database(self.db, self.config)
                self.db.log("info", "cloud.backup", f"Backed up config/database to {len(results)} cloud targets")
                self.send_json({"ok": True, "results": results})
            elif parsed.path == "/api/worker/pause":
                kind = str(data.get("kind", "all"))
                self.db.set_paused(kind, True)
                audit_event(self.db, self.config, self.config.web_ui_username, "worker.pause", {"kind": kind})
                self.send_json({"ok": True, "paused": self.db.paused_kinds()})
            elif parsed.path == "/api/worker/resume":
                kind = str(data.get("kind", "all"))
                self.db.set_paused(kind, False)
                worker_kinds = ["catalog", "backup", "verification", "cloud_backup", "maintenance", "restore_drill", "update_check"] if kind == "all" else [kind]
                for worker_kind in worker_kinds:
                    self.db.clear_worker_error(worker_kind)
                audit_event(self.db, self.config, self.config.web_ui_username, "worker.resume", {"kind": kind})
                self.monitor.trigger()
                self.send_json({"ok": True, "paused": self.db.paused_kinds()})
            elif parsed.path == "/api/operations/cancel":
                operation_id = str(data.get("operation_id", ""))
                self.send_json({"ok": self.cancel_operation(operation_id), "operation_id": operation_id})
            elif parsed.path == "/api/health/check":
                self.send_json({"hosts": check_usenet_hosts(self.db, self.config)})
            elif parsed.path == "/api/health/article-size":
                host_names = data.get("hosts") or [host.name for host in self.config.hosts_for_mode("post")]
                results = []
                for host_name in host_names:
                    results.append(
                        {
                            "host_name": str(host_name),
                            "article_size_bytes": test_post_host_article_size(self.db, self.config, str(host_name)),
                        }
                    )
                self.send_json({"hosts": results})
            elif parsed.path == "/api/settings/par2/discover":
                result = discover_par2_command(self.config)
                if data.get("apply") and result.get("found"):
                    par2 = dict(self.config.par2 or {})
                    par2["command"] = result["command"]
                    self.config.par2 = par2
                    self.config.save(self.config_path)
                    record_config_history(self.db, self.config.web_ui_username, ["par2.command"])
                    self.db.log("info", "settings.par2", f"Detected PAR2 command: {result['command']}")
                self.send_json({**result, "settings": self.config.public_dict() if data.get("apply") and result.get("found") else None})
            elif parsed.path == "/api/maintenance/run":
                self.send_json(run_maintenance(self.db, self.config, vacuum=bool(data.get("vacuum"))))
            elif parsed.path == "/api/restore-drill/run":
                self.send_json(run_restore_drill(self.db, self.config))
            elif parsed.path == "/api/restore/rehearsal":
                self.send_json(run_restore_rehearsal(self.db, self.config, data["path"], int(data.get("sample_bytes") or 0) or None))
            elif parsed.path == "/api/incident/start":
                self.send_json(incident_mode(self.db, self.config))
            elif parsed.path == "/api/update-check/run":
                self.send_json(check_for_updates(self.db, self.config))
            elif parsed.path == "/api/restore/confidence":
                self.send_json(restore_confidence(self.db, data["path"], self.config))
            elif parsed.path == "/api/restore/plan":
                self.send_json(restore_plan(self.db, data["path"], data.get("dest") or ""))
            elif parsed.path == "/api/restore/preflight":
                self.send_json(restore_preflight(self.db, self.config, data["path"], data.get("dest") or ""))
            elif parsed.path == "/api/restore/preview":
                self.send_json(restore_preview(self.db, [int(item) for item in data.get("file_ids", [])], data.get("dest") or ""))
            elif parsed.path == "/api/restore":
                if data.get("folder"):
                    audit_event(self.db, self.config, self.config.web_ui_username, "restore.folder", {"path": data.get("path"), "dest": data.get("dest")})
                    self.send_json({"restored": restore_folder(self.db, self.config, data["path"], data.get("dest"))})
                else:
                    audit_event(self.db, self.config, self.config.web_ui_username, "restore.file", {"path": data.get("path"), "dest": data.get("dest")})
                    self.send_json({"target": str(restore_file(self.db, self.config, data["path"], data.get("dest")))})
            elif parsed.path == "/api/restore/start":
                audit_event(self.db, self.config, self.config.web_ui_username, "restore.start", {"path": data.get("path"), "dest": data.get("dest"), "folder": bool(data.get("folder"))})
                if data.get("folder"):
                    self.send_json({"operation_ids": self.start_folder_restore_operations(data["path"], data.get("dest"))})
                else:
                    self.send_json({"operation_id": self.start_restore_operation(data["path"], data.get("dest"))})
            elif parsed.path == "/api/settings/validate":
                candidate = copy.deepcopy(self.config)
                update_config(candidate, data)
                self.send_json({"ok": True, "settings": candidate.public_dict()})
            elif parsed.path == "/api/settings/profile/import":
                profile = dict(data.get("profile") or data)
                update_config(self.config, profile)
                self.config.save(self.config_path)
                record_config_history(self.db, self.config.web_ui_username, sorted(profile.keys()))
                self.db.log("info", "settings.profile", "Imported settings profile")
                self.send_json({"ok": True, "settings": self.config.public_dict()})
            elif parsed.path == "/api/settings":
                update_config(self.config, data)
                self.config.save(self.config_path)
                self.db.event_forwarder = LogForwarder(self.config.log_destinations)
                for endpoint in self.config.endpoints:
                    self.db.add_endpoint(endpoint)
                self.db.log("info", "settings", "Updated configuration from Web UI")
                record_config_history(self.db, self.config.web_ui_username, sorted(data.keys()))
                audit_event(self.db, self.config, self.config.web_ui_username, "settings.update", {"keys": sorted(data.keys())})
                self.monitor.trigger()
                self.send_json({"ok": True, "settings": self.config.public_dict()})
            else:
                self.send_json({"error": "not found"}, 404)
        except Exception as exc:
            self.db.log("error", "web.error", f"{parsed.path}: {exc}")
            self.send_json({"error": str(exc)}, 500)

    def status_payload(self) -> dict[str, Any]:
        self.db.cleanup_completed_queue()
        speed = self.db.speed_samples(5, 10)
        posting_rows = [dict(row) for row in self.db.list_queue(status="posting")]
        return {
            "version": __version__,
            "stats": self.db.stats(),
            "throughput": throughput_summary(speed),
            "hourly_post_budget": hourly_post_budget(self.db, self.config),
            "nntp_threads": thread_usage_summary(posting_rows, self.config.article_size, self.config.nntp_threads),
            "scan_interval_seconds": self.config.scan_interval_seconds,
            "backup_interval_seconds": self.config.backup_interval_seconds,
            "verification_task_interval_seconds": self.config.verification_task_interval_seconds,
            "verification_files_per_run": self.config.verification_files_per_run,
            "cloud_backup_interval_seconds": self.config.cloud_backup_interval_seconds,
            "maintenance_interval_seconds": self.config.maintenance_interval_seconds,
            "restore_drill_task_interval_seconds": self.config.restore_drill_task_interval_seconds,
            "update_check_interval_seconds": self.config.update_check_interval_seconds,
            "update_check": update_result(self.db),
            "paused_workers": self.db.paused_kinds(),
            "setup_health": setup_health_check(self.db, self.config),
            "alerts": notification_alerts(self.db, self.config),
            "provider_confidence": provider_confidence_report(self.db),
        }

    def handle_external_get(self, parsed: Any, query: dict[str, list[str]]) -> None:
        suffix = parsed.path.removeprefix("/external-api")
        if suffix == "/status":
            self.send_json(self.status_payload())
        elif suffix == "/files":
            page = max(1, int(query.get("page", ["1"])[0]))
            page_size = max(1, min(500, int(query.get("page_size", ["100"])[0])))
            offset = (page - 1) * page_size
            search = query.get("q", [""])[0]
            unbacked_only = query.get("unbacked", ["0"])[0] in {"1", "true", "yes"}
            self.send_json(
                {
                    "rows": rowdicts(self.db.list_files(page_size, offset, search, False, unbacked_only)),
                    "page": page,
                    "page_size": page_size,
                    "total": self.db.file_count(search, False, unbacked_only),
                }
            )
        elif suffix == "/queue":
            rows = [self.queue_row_payload(row) for row in self.db.list_queue(limit=100)]
            self.send_json({"rows": rows, "total": self.db.queue_count()})
        elif suffix == "/tasks":
            self.send_json(self.all_tasks())
        else:
            self.send_json({"error": "not found"}, 404)

    def handle_external_post(self, parsed: Any) -> None:
        suffix = parsed.path.removeprefix("/external-api")
        data = self.read_json()
        if suffix == "/backup/run":
            self.backup_monitor.trigger()
            self.send_json({"ok": True})
        elif suffix == "/scan":
            self.monitor.trigger()
            self.send_json({"ok": True})
        elif suffix == "/verify/start":
            file_ids = [int(file_id) for file_id in data.get("file_ids", [])]
            self.send_json({"operation_ids": self.start_verification_operation(file_ids, force=bool(data.get("force")) or bool(file_ids))})
        else:
            self.send_json({"error": "not found"}, 404)

    def queue_row_payload(self, row: Any) -> dict:
        payload = dict(row)
        expected = max(1, (int(payload["size"]) + self.config.article_size - 1) // self.config.article_size)
        posted = int(payload.get("posted_chunks") or 0)
        payload["expected_chunks"] = expected
        payload["chunk_count"] = posted
        if payload.get("status") == "done":
            payload["progress_percent"] = 100
            payload["progress"] = f"{posted} chunks stored"
            return payload
        payload["progress_percent"] = min(100, int((posted / expected) * 100))
        payload["progress"] = f"{posted}/{expected} chunks ({payload['progress_percent']}%)"
        payload["reason_detail"] = queue_reason_detail(payload.get("reason", ""), payload.get("status", ""))
        return payload

    def stream_restore_download(self, source_path: str) -> None:
        if not source_path:
            self.send_json({"error": "path is required"}, 400)
            return
        with self.db.connect() as conn:
            file_row = conn.execute("SELECT * FROM files WHERE path=? OR relative_path=?", (source_path, source_path)).fetchone()
        if not file_row:
            self.send_json({"error": f"No cataloged file matches {source_path}"}, 404)
            return
        operation_id = self.create_operation(
            "download",
            int(file_row["id"]),
            str(file_row["relative_path"] or file_row["path"]),
            self.db.chunk_count_for_file(int(file_row["id"])),
        )

        def progress(done: int, total_chunks: int, bytes_done: int) -> None:
            self.update_operation(operation_id, done, total_chunks, bytes_done, f"Downloaded {done}/{total_chunks} chunks")

        file_row, payloads = restored_payloads(self.db, self.config, source_path, progress=progress)
        filename = Path(file_row["path"]).name
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{quote(filename)}")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            for payload in payloads:
                self.wfile.write(payload)
                self.wfile.flush()
            self.finish_operation(operation_id, "done", f"Downloaded {source_path}")
            self.db.log("info", "restore.download", f"Downloaded restored copy of {source_path}", int(file_row["id"]))
        except Exception as exc:
            self.finish_operation(operation_id, "failed", str(exc))
            raise

    def stream_restore_zip(self, file_ids: list[int]) -> None:
        if not file_ids:
            self.send_json({"error": "file_id is required"}, 400)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        self.send_header("Content-Disposition", "attachment; filename*=UTF-8''backuprr-restore.zip")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        writer = ResponseZipWriter(self.wfile)
        restored = 0
        operations: dict[int, str] = {}
        with ZipFile(writer, "w", compression=ZIP_DEFLATED) as archive:
            for file_id in file_ids:
                file_row = self.db.file_by_id(int(file_id))
                operation_id = self.create_operation(
                    "download",
                    int(file_id),
                    str(file_row["relative_path"] or file_row["path"]),
                    self.db.chunk_count_for_file(int(file_id)),
                )
                operations[int(file_id)] = operation_id

                def progress(done: int, total_chunks: int, bytes_done: int, op_id: str = operation_id) -> None:
                    self.update_operation(op_id, done, total_chunks, bytes_done, f"Downloaded {done}/{total_chunks} chunks")

                _, payloads = restored_payloads(self.db, self.config, str(file_row["path"]), progress=progress)
                name = str(file_row["relative_path"] or Path(file_row["path"]).name).replace("\\", "/")
                try:
                    with archive.open(name, "w") as entry:
                        for payload in payloads:
                            entry.write(payload)
                    restored += 1
                    self.finish_operation(operation_id, "done", f"Added {name} to restore zip")
                except Exception as exc:
                    self.finish_operation(operation_id, "failed", str(exc))
                    raise
        self.db.log("info", "restore.download", f"Downloaded restore zip with {restored} files")

    def all_tasks(self) -> list[dict]:
        return (
            self.monitor.tasks()
            + self.backup_monitor.tasks()
            + self.verification_monitor.tasks()
            + self.cloud_backup_monitor.tasks()
            + self.maintenance_monitor.tasks()
            + self.restore_drill_monitor.tasks()
            + self.update_check_monitor.tasks()
        )

    def stream_changes(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        last_payload = ""
        try:
            while True:
                token = self.db.change_token()
                tasks = self.all_tasks()
                token["task_revision"] = sum(int(task.get("revision", 0)) for task in tasks)
                token["operation_revision"] = Handler.operation_revision
                if any(task.get("status") == "running" for task in tasks):
                    token["running_task_tick"] = int(time.time())
                payload = json.dumps(token, default=str)
                if payload != last_payload:
                    self.wfile.write(f"event: change\ndata: {payload}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    last_payload = payload
                time.sleep(1)
        except (BrokenPipeError, ConnectionError):
            return


class ResponseZipWriter:
    def __init__(self, handle: Any):
        self.handle = handle
        self.offset = 0

    def write(self, data: bytes) -> int:
        self.handle.write(data)
        self.handle.flush()
        self.offset += len(data)
        return len(data)

    def tell(self) -> int:
        return self.offset

    def flush(self) -> None:
        self.handle.flush()

    def seekable(self) -> bool:
        return False


def run_web(config: Config, db: Database, host: str, port: int) -> None:
    Handler.config = config
    Handler.config_path = str(config.source_path or (config.base_dir / "config.json"))
    Handler.db = db
    Handler.monitor = CatalogMonitor(db, config)
    Handler.backup_monitor = BackupMonitor(db, config)
    Handler.verification_monitor = VerificationMonitor(db, config)
    Handler.cloud_backup_monitor = CloudBackupMonitor(db, config)
    Handler.maintenance_monitor = MaintenanceMonitor(db, config)
    Handler.restore_drill_monitor = RestoreDrillMonitor(db, config)
    Handler.update_check_monitor = UpdateCheckMonitor(db, config)
    recovered = db.recover_interrupted_posting()
    if recovered:
        db.log("warning", "startup.recover", f"Recovered {recovered} interrupted posting queue item(s) before workers started")
    Handler.monitor.start()
    Handler.backup_monitor.start()
    Handler.verification_monitor.start()
    Handler.cloud_backup_monitor.start()
    Handler.maintenance_monitor.start()
    Handler.restore_drill_monitor.start()
    Handler.update_check_monitor.start()
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Backuprr {__version__} listening on http://{host}:{port}")
    try:
        server.serve_forever()
    finally:
        Handler.monitor.stop()
        Handler.backup_monitor.stop()
        Handler.verification_monitor.stop()
        Handler.cloud_backup_monitor.stop()
        Handler.maintenance_monitor.stop()
        Handler.restore_drill_monitor.stop()
        Handler.update_check_monitor.stop()


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Backuprr</title>
<style>
:root { color-scheme: light; --ink:#243238; --muted:#687c81; --line:#d5e2e1; --bg:#edf5f4; --surface:#f7fbfa; --panel:#ffffff; --panel-2:#eef8f6; --accent:#0f9f90; --accent-2:#04776e; --warn:#b45309; --bad:#dc2626; --good:#059669; --shadow:0 12px 28px rgba(13,36,40,.10); --body-bg:linear-gradient(135deg,#edf7f5 0%,#f8fbfa 48%,#e2f2ef 100%); --header-bg:rgba(248,251,250,.92); --sidebar-bg:linear-gradient(180deg,#f9fcfb,#eaf5f3); --toolbar-bg:rgba(255,255,255,.88); --input-bg:#ffffff; --table-head-bg:#edf6f4; --track-bg:#dcebe8; --row-hover:rgba(15,159,144,.07); --nav-text:#365056; --nav-active-bg:linear-gradient(90deg,rgba(15,159,144,.18),rgba(15,159,144,.05)); --nav-hover-bg:rgba(15,159,144,.10); --brand-bg:linear-gradient(145deg,#dcf7f2,#1fb8a6); --brand-lock:#093a36; --hero-bg:radial-gradient(circle at top right,rgba(31,184,166,.20),transparent 34%), linear-gradient(180deg,#ffffff,#eef8f6); }
html[data-theme="emerald_console"] { color-scheme: dark; --ink:#dce7e4; --muted:#8fa39f; --line:#2b3b3d; --bg:#0d1416; --surface:#121c1f; --panel:#182427; --panel-2:#1d2b2f; --accent:#18a999; --accent-2:#7dd3c7; --warn:#f59e0b; --bad:#ef4444; --good:#34d399; --shadow:0 14px 38px rgba(0,0,0,.28); --body-bg:linear-gradient(135deg,#0a1012 0%,#0f1b1d 48%,#102321 100%); --header-bg:rgba(13,20,22,.88); --sidebar-bg:linear-gradient(180deg,#111b1e,#0d1517); --toolbar-bg:rgba(18,28,31,.78); --input-bg:#0f181a; --table-head-bg:#111d20; --track-bg:#0d1517; --row-hover:rgba(125,211,199,.04); --nav-text:#b7c8c5; --nav-active-bg:linear-gradient(90deg,rgba(24,169,153,.20),rgba(24,169,153,.05)); --nav-hover-bg:rgba(125,211,199,.10); --brand-bg:linear-gradient(145deg,#143b39,#1eb7a5); --brand-lock:#d8fff9; --hero-bg:radial-gradient(circle at top right,rgba(24,169,153,.22),transparent 34%), linear-gradient(180deg,var(--panel-2),var(--panel)); }
html[data-theme="slate_cinema"] { color-scheme: dark; --ink:#d9e2e8; --muted:#9aa8b2; --line:#33414a; --bg:#111820; --surface:#151f28; --panel:#1c2832; --panel-2:#22313d; --accent:#22c7aa; --accent-2:#82e6d8; --warn:#fbbf24; --bad:#fb7185; --good:#4ade80; --shadow:0 16px 36px rgba(0,0,0,.30); --body-bg:linear-gradient(135deg,#0d131a,#17212a 52%,#172d2c); --header-bg:rgba(15,22,30,.90); --sidebar-bg:linear-gradient(180deg,#151f28,#101820); --toolbar-bg:rgba(28,40,50,.82); --input-bg:#121c25; --table-head-bg:#16222c; --track-bg:#111820; --row-hover:rgba(34,199,170,.06); --nav-text:#c4d0d6; --nav-active-bg:linear-gradient(90deg,rgba(34,199,170,.18),rgba(34,199,170,.04)); --nav-hover-bg:rgba(130,230,216,.09); --brand-bg:linear-gradient(145deg,#182b36,#22c7aa); --brand-lock:#e6fffb; --hero-bg:radial-gradient(circle at top right,rgba(34,199,170,.18),transparent 34%), linear-gradient(180deg,#22313d,#1c2832); }
html[data-theme="graphite"] { color-scheme: dark; --ink:#e2e8e5; --muted:#a3aca9; --line:#3b4140; --bg:#151716; --surface:#1a1d1c; --panel:#222625; --panel-2:#2b302f; --accent:#20b486; --accent-2:#9ee9c8; --warn:#f59e0b; --bad:#f87171; --good:#34d399; --shadow:0 14px 34px rgba(0,0,0,.27); --body-bg:linear-gradient(135deg,#101211,#1c201f 50%,#162620); --header-bg:rgba(22,24,23,.91); --sidebar-bg:linear-gradient(180deg,#1b1f1e,#141716); --toolbar-bg:rgba(34,38,37,.84); --input-bg:#191d1c; --table-head-bg:#1a1e1d; --track-bg:#121514; --row-hover:rgba(32,180,134,.06); --nav-text:#c3cbc8; --nav-active-bg:linear-gradient(90deg,rgba(32,180,134,.20),rgba(32,180,134,.04)); --nav-hover-bg:rgba(158,233,200,.08); --brand-bg:linear-gradient(145deg,#2b302f,#20b486); --brand-lock:#ecfff7; --hero-bg:radial-gradient(circle at top right,rgba(32,180,134,.18),transparent 34%), linear-gradient(180deg,#2b302f,#222625); }
html[data-theme="nordic_mint"] { color-scheme: light; --ink:#203033; --muted:#62787c; --line:#c8dcde; --bg:#eaf4f5; --surface:#f7fbfb; --panel:#ffffff; --panel-2:#ecf8f7; --accent:#0e9384; --accent-2:#0f766e; --warn:#b7791f; --bad:#c2410c; --good:#047857; --shadow:0 12px 28px rgba(44,76,80,.12); --body-bg:linear-gradient(135deg,#e8f4f5,#f9fcfb 52%,#dff4ef); --header-bg:rgba(247,251,251,.94); --sidebar-bg:linear-gradient(180deg,#eef8f8,#dfeff0); --toolbar-bg:rgba(255,255,255,.90); --input-bg:#ffffff; --table-head-bg:#e9f5f5; --track-bg:#d7e9e8; --row-hover:rgba(14,147,132,.07); --nav-text:#334e52; --nav-active-bg:linear-gradient(90deg,rgba(14,147,132,.16),rgba(14,147,132,.05)); --nav-hover-bg:rgba(14,147,132,.09); --brand-bg:linear-gradient(145deg,#d9fbf5,#10b6a4); --brand-lock:#073e39; --hero-bg:radial-gradient(circle at top right,rgba(16,182,164,.18),transparent 34%), linear-gradient(180deg,#ffffff,#edf9f8); }
* { box-sizing:border-box; }
body { margin:0; font:14px/1.45 system-ui, -apple-system, Segoe UI, sans-serif; color:var(--ink); background:var(--body-bg); min-height:100vh; }
.app-shell { display:grid; grid-template-columns:238px minmax(0,1fr); min-height:100vh; }
.sidebar { position:sticky; top:0; align-self:start; height:100vh; overflow:auto; display:flex; flex-direction:column; background:var(--sidebar-bg); border-right:1px solid var(--line); box-shadow:inset -1px 0 0 rgba(255,255,255,.02); }
.brand { display:flex; align-items:center; gap:12px; padding:18px 16px 14px; border-bottom:1px solid rgba(125,211,199,.12); }
.brand-mark { width:42px; height:42px; position:relative; border-radius:10px; background:var(--brand-bg); box-shadow:0 0 0 1px rgba(125,211,199,.35), 0 12px 28px rgba(24,169,153,.18); }
.brand-mark:before { content:""; position:absolute; left:10px; right:10px; top:8px; height:12px; border:3px solid var(--brand-lock); border-bottom:0; border-radius:12px 12px 0 0; opacity:.95; }
.brand-mark:after { content:""; position:absolute; left:10px; right:10px; bottom:9px; height:16px; border-radius:4px; background:var(--brand-lock); box-shadow:inset 0 -5px 0 rgba(13,20,22,.16); }
.brand-copy b { display:block; font-size:18px; line-height:1; }
.brand-copy span { color:var(--muted); font-size:12px; font-weight:700; text-transform:uppercase; }
nav { padding:12px 10px; }
nav button { width:100%; display:flex; align-items:center; gap:10px; margin:2px 0; padding:10px 12px; border:0; border-left:3px solid transparent; background:transparent; color:var(--nav-text); text-align:left; border-radius:4px; cursor:pointer; font-weight:650; }
nav button.active { background:var(--nav-active-bg); border-left-color:var(--accent-2); color:var(--ink); }
nav button:hover { background:var(--nav-hover-bg); color:var(--ink); }
.side-footer { margin-top:auto; padding:12px 16px 16px; color:var(--muted); border-top:1px solid rgba(125,211,199,.12); font-size:12px; display:grid; gap:8px; align-items:start; }
.nav-icon, .ui-icon { width:1.2em; display:inline-grid; place-items:center; flex:0 0 auto; }
main { display:block; }
section { padding:18px 20px 28px; min-width:0; }
.toolbar { display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin-bottom:12px; padding:10px; background:var(--toolbar-bg); border:1px solid var(--line); border-radius:6px; box-shadow:var(--shadow); }
.dropdown-group { display:grid; gap:4px; padding:6px 0; border-bottom:1px solid var(--line); }
.dropdown-group:last-child { border-bottom:0; }
.dropdown-group-title { font-weight:800; color:var(--ink); }
.dropdown-group-items { display:grid; gap:3px; padding-left:18px; }
button, select, input, textarea { border:1px solid var(--line); background:var(--input-bg); color:var(--ink); border-radius:4px; padding:8px 10px; font:inherit; accent-color:var(--accent); }
button { cursor:pointer; font-weight:700; }
button:hover { border-color:var(--accent); background:var(--panel-2); }
button.primary { background:linear-gradient(180deg,#1fb8a6,#0f867a); color:#ecfffb; border-color:#2cc7b5; box-shadow:0 0 0 1px rgba(125,211,199,.15), inset 0 1px 0 rgba(255,255,255,.13); }
button:disabled { opacity:.45; cursor:not-allowed; }
textarea { width:100%; min-height:120px; font-family:ui-monospace, SFMono-Regular, Consolas, monospace; }
label { display:inline-flex; align-items:center; gap:6px; }
table { width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--line); border-radius:6px; overflow:hidden; box-shadow:var(--shadow); }
th, td { padding:8px 10px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; overflow-wrap:anywhere; }
th { color:var(--muted); font-weight:800; background:var(--table-head-bg); font-size:12px; text-transform:uppercase; }
.sort-header { display:flex; align-items:center; gap:5px; width:100%; padding:0; border:0; background:transparent; color:inherit; text-align:left; text-transform:inherit; font:inherit; cursor:pointer; }
.sort-header:hover { background:transparent; color:var(--ink); border-color:transparent; }
.sort-header:after { content:"\2195"; opacity:.45; font-size:10px; }
th.sort-asc .sort-header:after { content:"\2191"; opacity:.9; }
th.sort-desc .sort-header:after { content:"\2193"; opacity:.9; }
.tree-sort.sort-asc .sort-header:after { content:"\2191"; opacity:.9; }
.tree-sort.sort-desc .sort-header:after { content:"\2193"; opacity:.9; }
tr:hover td { background:var(--row-hover); }
.stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:10px; margin-bottom:16px; }
.compact-stats { grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); margin-bottom:0; }
.stat { background:linear-gradient(180deg,var(--panel-2),var(--panel)); border:1px solid var(--line); border-radius:6px; padding:12px; box-shadow:var(--shadow); }
.stat b { display:block; font-size:24px; }
.compact-stats .stat b { font-size:18px; }
.dashboard { display:grid; gap:14px; }
.hero-status { background:var(--hero-bg); border:1px solid var(--line); border-radius:6px; padding:16px; display:grid; gap:10px; box-shadow:var(--shadow); }
.hero-status h2 { margin:0; font-size:20px; }
.task-strip { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:10px; }
.task-card { background:var(--panel); border:1px solid var(--line); border-radius:6px; padding:12px; display:grid; gap:6px; box-shadow:var(--shadow); }
.task-card h3 { margin:0; font-size:14px; }
.badge { display:inline-flex; align-items:center; width:max-content; padding:3px 7px; border-radius:999px; background:rgba(52,211,153,.13); color:var(--good); font-size:12px; font-weight:800; }
.badge.running { background:rgba(245,158,11,.14); color:var(--warn); }
.pill { display:inline-flex; align-items:center; gap:5px; width:max-content; max-width:100%; padding:3px 7px; border-radius:999px; background:#263539; color:#b4c5c2; font-size:12px; font-weight:800; }
.pill.ok { background:rgba(24,169,153,.18); color:var(--accent-2); }
.pill.warn { background:rgba(245,158,11,.15); color:var(--warn); }
.pill.bad { background:rgba(239,68,68,.16); color:#fca5a5; }
.pill.info { background:rgba(59,130,246,.16); color:#93c5fd; }
.pill.debug { background:rgba(168,85,247,.16); color:#d8b4fe; }
.pill.verbose { background:rgba(148,163,184,.12); color:#aebbb9; }
.pill.verified { padding:2px 6px; }
.pill.tone-compressed { background:rgba(59,130,246,.16); color:#93c5fd; }
.pill.tone-par2 { background:rgba(168,85,247,.16); color:#d8b4fe; }
.pill.tone-verified { background:rgba(20,184,166,.14); color:#5eead4; }
.stat span, .section-title, .chart-card h3, .task-card h3 { display:flex; align-items:center; gap:6px; }
.chart-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:12px; }
.chart-card { background:var(--panel); border:1px solid var(--line); border-radius:6px; padding:12px; box-shadow:var(--shadow); }
.chart-card h3 { margin:0 0 10px; font-size:14px; }
.setup-checks { display:grid; gap:6px; margin-top:10px; }
.setup-checks div { display:grid; grid-template-columns:auto minmax(160px, .8fr) 1fr; gap:8px; align-items:center; }
.flowchart { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:10px; align-items:stretch; margin-top:14px; }
.flow-node { background:var(--panel); border:1px solid var(--line); border-radius:6px; padding:12px; display:grid; gap:6px; box-shadow:var(--shadow); position:relative; }
.flow-node b { font-size:14px; }
.flow-node span { color:var(--muted); font-size:12px; }
.flow-node:after { content:""; position:absolute; right:-10px; top:50%; width:10px; height:2px; background:var(--accent); opacity:.7; }
.flow-node:last-child:after { display:none; }
.flow-branch { border-color:rgba(168,85,247,.38); }
.bar-row { display:grid; grid-template-columns:minmax(90px,150px) 1fr minmax(42px,max-content); gap:8px; align-items:center; margin:7px 0; }
.bar-track { height:12px; background:var(--track-bg); border-radius:999px; overflow:hidden; border:1px solid rgba(125,211,199,.08); }
.bar-fill { height:100%; background:var(--accent); border-radius:999px; min-width:2px; }
.bar-fill.warn { background:var(--warn); }
.bar-fill.bad { background:var(--bad); }
.progress-track { height:16px; background:var(--track-bg); border-radius:999px; overflow:hidden; border:1px solid rgba(125,211,199,.10); }
.progress-fill { height:100%; background:linear-gradient(90deg,#0f867a,#4adecf); border-radius:999px; transition:width .2s ease; }
.progress-fill.bad { background:var(--bad); }
.progress-fill.indeterminate { width:42%; min-width:32px; animation:progress-slide 1.1s ease-in-out infinite; }
@keyframes progress-slide { 0% { transform:translateX(-120%); } 100% { transform:translateX(260%); } }
.async-status { display:grid; gap:6px; max-width:560px; margin:8px 0 12px; }
.async-status .pill { width:max-content; }
.async-status .progress-track { height:10px; }
.file-progress { min-width:160px; max-width:220px; display:grid; gap:3px; }
.file-progress .progress-track { height:8px; }
.file-progress span { font-size:12px; color:var(--muted); }
.mini-progress { display:grid; gap:3px; min-width:180px; }
.mini-progress .progress-track { height:8px; }
.toolbar-grid { display:grid; grid-template-columns:minmax(220px,1fr) auto auto; gap:8px; align-items:center; margin-bottom:12px; padding:10px; background:var(--toolbar-bg); border:1px solid var(--line); border-radius:6px; box-shadow:var(--shadow); }
.toolbar-options { display:flex; flex-wrap:wrap; gap:8px; align-items:center; }
.toolbar-right { margin-left:auto; display:flex; gap:8px; align-items:center; }
.dropdown { position:relative; display:inline-block; }
.dropdown > summary { list-style:none; cursor:pointer; border:1px solid var(--line); background:var(--input-bg); border-radius:4px; padding:8px 10px; font-weight:700; }
.dropdown > summary::-webkit-details-marker { display:none; }
.dropdown-menu { position:absolute; right:0; top:calc(100% + 4px); z-index:10; min-width:220px; display:grid; gap:6px; padding:10px; background:var(--panel); border:1px solid var(--line); border-radius:6px; box-shadow:var(--shadow); }
.dropdown-menu label { justify-content:flex-start; }
.dropdown-menu button { text-align:left; }
.restore-destination { display:grid; gap:6px; min-width:260px; }
.thread-meter { display:flex; align-items:baseline; gap:8px; margin-bottom:10px; }
.thread-meter b { font-size:32px; }
.refresh-note { margin-left:auto; }
.push-note { margin-left:auto; }
.section-title { margin:16px 0 8px; font-size:16px; }
.pagination { display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin:8px 0 14px; }
.form-grid { display:grid; grid-template-columns:minmax(0,720px); gap:12px; margin-bottom:12px; align-items:start; }
.field { display:grid; gap:5px; }
.field span { color:var(--muted); font-size:12px; font-weight:700; }
.settings-help-toggle { white-space:nowrap; font-weight:700; }
.settings-help { display:none; color:var(--muted); font-size:12px; line-height:1.35; font-weight:500; }
.settings-show-help .settings-help { display:block; }
.range-field { display:grid; grid-template-columns:1fr auto; gap:8px; align-items:center; }
.range-field span { min-width:74px; text-align:right; color:var(--muted); font-size:12px; font-weight:700; }
.range-field input { padding:0; }
.full { grid-column:1 / -1; }
.host-list { display:grid; gap:12px; }
.host-row, .cloud-row { border:1px solid var(--line); background:var(--panel); border-radius:6px; padding:12px; box-shadow:var(--shadow); }
.host-row h3, .cloud-row h3 { margin:0 0 10px; font-size:14px; }
.host-grid { display:grid; grid-template-columns:minmax(0,1fr); gap:10px; }
.tabs { display:flex; flex-wrap:wrap; gap:6px; margin-bottom:12px; padding:8px; background:var(--toolbar-bg); border:1px solid var(--line); border-radius:6px; }
.settings-header { display:flex; flex-wrap:wrap; gap:10px; align-items:center; justify-content:space-between; margin-bottom:12px; }
.settings-header .tabs { margin-bottom:0; flex:1; }
.tab-panel { display:none; }
.tab-panel.active { display:block; }
.selection-summary { position:sticky; bottom:0; margin-top:12px; background:var(--panel); border:1px solid var(--line); border-radius:6px; padding:10px 12px; box-shadow:0 -10px 24px rgba(0,0,0,.18); }
.danger { color:var(--bad); }
.tree { background:var(--panel); border:1px solid var(--line); border-radius:6px; padding:8px; box-shadow:var(--shadow); overflow:auto; }
.tree ul { list-style:none; margin:0; padding-left:20px; }
.tree li { margin:2px 0; }
.tree-row { display:flex; align-items:center; gap:8px; min-height:32px; padding:4px 6px; border-radius:6px; }
.tree-row.file-row, .tree-row.folder-row, .tree-header { display:grid; grid-template-columns:24px 24px minmax(280px,1fr) minmax(178px,200px) minmax(88px,96px) minmax(112px,124px) minmax(112px,132px) max-content; gap:8px; align-items:center; min-width:940px; }
.tree-header { color:var(--muted); font-size:12px; font-weight:800; text-transform:uppercase; background:var(--table-head-bg); border:1px solid var(--line); border-radius:6px; padding:7px 6px; margin-bottom:6px; }
.tree-row:hover { background:var(--row-hover); }
.tree-name { flex:1; overflow-wrap:anywhere; }
.tree-meta { color:var(--muted); font-size:12px; text-align:right; justify-self:end; }
.tree-meta small { display:block; margin-top:2px; color:var(--muted); font-size:11px; font-weight:600; white-space:nowrap; }
.feature-pills { display:flex; flex-wrap:wrap; gap:4px; justify-content:flex-end; }
.tree-actions { display:flex; gap:2px; justify-content:flex-end; white-space:nowrap; }
.tree-actions button, .tree-actions summary { min-width:0; }
.icon-btn { width:28px; height:28px; display:inline-grid; place-items:center; padding:0; }
.folder > .tree-row { font-weight:600; }
.hidden { display:none; }
.muted { color:var(--muted); }
.error { color:var(--bad); }
pre { white-space:pre-wrap; background:var(--panel); border:1px solid var(--line); padding:12px; border-radius:6px; }
.task-detail { color:var(--muted); background:var(--panel-2); }
.task-detail td { padding-top:6px; padding-bottom:10px; }
.task-row-actions { display:flex; flex-wrap:wrap; gap:6px; justify-content:flex-end; }
.operation-line { display:grid; grid-template-columns:minmax(180px,1fr) minmax(220px,2fr) auto; gap:10px; align-items:center; padding:8px 0; border-bottom:1px solid var(--line); }
.operation-line:last-child { border-bottom:0; }
.version-notice { position:fixed; right:18px; bottom:18px; z-index:50; width:min(420px,calc(100vw - 36px)); background:var(--panel); border:1px solid var(--line); border-radius:6px; padding:14px; box-shadow:var(--shadow); display:grid; gap:10px; }
.version-notice h3 { margin:0; font-size:15px; display:flex; align-items:center; gap:6px; }
.version-notice ul { margin:0; padding-left:20px; color:var(--muted); }
.version-notice .toolbar { margin:0; padding:0; background:transparent; border:0; box-shadow:none; justify-content:flex-end; }
.health-bar { display:flex; flex-wrap:wrap; gap:8px; align-items:center; padding:10px 20px; border-bottom:1px solid var(--line); background:var(--header-bg); position:sticky; top:0; z-index:20; }
.health-chip { display:inline-flex; align-items:center; gap:5px; padding:5px 8px; border:1px solid var(--line); border-radius:999px; background:var(--panel); color:var(--muted); font-size:12px; font-weight:800; }
.health-chip.warn { color:var(--warn); border-color:rgba(180,83,9,.35); }
.health-chip.bad { color:var(--bad); border-color:rgba(220,38,38,.35); }
.command-palette { position:fixed; inset:0; z-index:100; display:grid; place-items:start center; padding-top:12vh; background:rgba(0,0,0,.28); }
.command-box { width:min(640px,calc(100vw - 32px)); background:var(--panel); border:1px solid var(--line); border-radius:6px; box-shadow:var(--shadow); padding:10px; }
.command-list button { width:100%; justify-content:flex-start; text-align:left; margin-top:4px; }
html[data-reduced-motion="true"] *, html[data-reduced-motion="true"] *:before, html[data-reduced-motion="true"] *:after { animation:none !important; transition:none !important; scroll-behavior:auto !important; }
@media (max-width:1100px) { .tree-row.file-row, .tree-row.folder-row, .tree-header { grid-template-columns:24px 24px minmax(180px,1fr) minmax(150px,170px) minmax(78px,90px) minmax(96px,max-content); min-width:720px; } .tree-row.file-row > :nth-child(7), .tree-row.folder-row > :nth-child(7), .tree-header > :nth-child(7) { display:none; } .tree-actions { grid-column:auto; } }
@media (max-width:860px) { .app-shell { display:block; } .sidebar { position:relative; top:auto; height:auto; overflow:visible; border-right:0; border-bottom:1px solid var(--line); } nav { display:grid; grid-template-columns:repeat(2,1fr); } .side-footer { display:none; } .toolbar-grid { grid-template-columns:1fr; } }
</style>
</head>
<body>
<main class="app-shell">
<aside class="sidebar"><div class="brand"><span class="brand-mark" aria-hidden="true"></span><span class="brand-copy"><b>Backuprr</b><span>Usenet vault</span></span></div><nav id="nav"></nav><div class="side-footer"><span>Obfuscated media backup engine</span><span id="version" class="pill ok"></span></div></aside>
<div><div id="healthBar" class="health-bar"></div><section id="content"></section></div>
</main>
<div id="versionNotice"></div>
<div id="commandPalette"></div>
<script>
const pages = ["Status","Files","Search","Log","Queue","Tasks","Verification","Statistics","Operations","Security","Settings","About"];
const pageSlugs = {
 Status:"/status", Files:"/files", Search:"/search", Log:"/log", Queue:"/queue", Tasks:"/tasks",
 Verification:"/verification", Statistics:"/statistics", Operations:"/operations", Security:"/security", Settings:"/settings", About:"/about"
};
const slugPages = Object.fromEntries(Object.entries(pageSlugs).map(([name, slug]) => [slug, name]));
const themeTemplates = [
 { id:"harbor_light", name:"Harbor Light" },
 { id:"emerald_console", name:"Emerald Console" },
 { id:"slate_cinema", name:"Slate Cinema" },
 { id:"graphite", name:"Graphite" },
 { id:"nordic_mint", name:"Nordic Mint" }
];
const internalApiToken = "__INTERNAL_API_TOKEN__";
const csrfToken = "__CSRF_TOKEN__";
let page = pageFromPath(location.pathname);
let settingsCache = null;
let fileRowsCache = [];
let operationRowsCache = [];
let verificationRowsCache = new Map();
let verificationTableCache = {};
let verificationRefreshSeq = 0;
let verificationRefreshRunning = false;
let verificationProgressFetchedAt = 0;
let apiRateLimitedUntil = 0;
let healthBarFetchedAt = 0;
let renderSeq = 0;
let appVersion = "";
let logLevelSelection = ["error","warning","info"];
let logEventTypeSelection = [];
let logPage = 1;
let logPageSize = 100;
let logTextFilter = "";
let logRowsCache = [];
let logResultCache = null;
let logSignature = "";
let logNewestId = 0;
let queueResultCache = {};
let tasksRowsCache = [];
let eventSource = null;
let lastChangeToken = null;
let activeQueuePage = 1;
let completedQueuePage = 1;
let attentionQueuePage = 1;
let filesPage = 1;
let filesPageSize = 100;
let queuePageSize = 10;
let verificationMissingPage = 1;
let verificationUnverifiedPage = 1;
let verificationVerifiedPage = 1;
let verificationNoChunksPage = 1;
let verificationPageSize = 10;
let verificationTextFilter = "";
let selectedFiles = new Set();
let selectedFileData = new Map();
let selectedVerificationFiles = new Set();
let settingsDirty = false;
let cachedTotpCode = "";
const defaultTableSorts = {
 files:{ col:"relative_path", dir:"asc" },
 log:{ col:"id", dir:"desc" },
 queueAttention:{ col:"", dir:"asc" },
 queueActive:{ col:"", dir:"asc" },
 queueCompleted:{ col:"", dir:"asc" },
 verificationMissing:{ col:"", dir:"asc" },
 verificationUnverified:{ col:"", dir:"asc" },
 verificationVerified:{ col:"", dir:"asc" },
 verificationNoChunks:{ col:"", dir:"asc" }
};
let tableSorts = loadTableSorts();
const releaseNotes = {
 "0.2.97":["Docker Compose setup docs now use a minimal compose file that builds Backuprr directly from GitHub while keeping app settings in the persistent config file."],
 "0.2.96":["The README now has generic Docker Compose setup-from-scratch instructions, including config, permissions, health checks, and upgrade steps."],
 "0.2.95":["Resuming workers now clears stale task errors and immediately nudges the worker so fixed configuration can retry without waiting for the next scheduled run."],
 "0.2.94":["Usenet host authentication is now explicit: missing or partial provider credentials are reported before posting instead of surfacing as a vague NNTP 480 response."],
 "0.2.93":["Docker and CLI startup now sync configured endpoints into the catalog database so first-boot scans start automatically."],
 "0.2.92":["Page navigation now ignores stale async renders and table views keep the last good data during temporary internal API cooldowns."],
 "0.2.91":["Manual and forced verification can now recheck missing chunks and recover stale failed missing-chunk rows when all chunks exist."],
 "0.2.90":["PAR2 creation now uses MultiPar par2j syntax when needed and reports captured tool output on failures."],
 "0.2.89":["The Log table now fetches only newly matching rows during live updates when the current view can be updated incrementally."],
 "0.2.88":["Verification table data now refreshes incrementally with request backoff to reduce internal API 429s during active runs."],
 "0.2.87":["Verification rate limits and temporary provider failures are now treated as retryable deferrals instead of missing chunks."],
 "0.2.86":["Verification tables now keep their last valid payload during live refreshes, preventing flicker while verification is running."],
 "0.2.85":["Settings field descriptions now include clearer purpose, tuning guidance, possible settings, examples, and defaults."],
 "0.2.84":["Added PAR2 executable auto-discovery and optional hidden Settings field descriptions."],
 "0.2.83":["Backup readiness now separates protection coverage from optional operational hardening so fully protected libraries show as 100% covered."],
 "0.2.82":["Added a dedicated read-only safety escape hatch and live reduced-motion toggle feedback."],
 "0.2.81":["Added scoped external API keys, read-only safety mode, optional TOTP admin step-up, global health bar, command palette, readiness scoring, provider capability cards, restore preflight warnings, maintenance visibility, and config change history."],
 "0.2.80":["GitHub update checks can use a token environment variable for private repositories."],
 "0.2.79":["GitHub update checks now fall back to repository tags when no formal latest release exists."],
 "0.2.78":["Added threat model reporting, CSRF protection, API rate limits, operation cancellation, incident mode, restore rehearsal, failover simulation, settings profiles, queue pause patterns, and retention hints."],
 "0.2.77":["Added role-gated web actions, manifest export, provider confidence, restore sandbox mode, integrity receipts, retry policy controls, signed audit events, safer bulk previews, and database growth reporting."],
 "0.2.76":["Added setup health checks, alerts, diagnostics export, optional Web UI Basic Auth, opt-in config secret protection, folder rollups, dry-run warnings, and restore drill rotation improvements."],
 "0.2.75":["Completed backup chunk rows can now compact into a per-file manifest after success, keeping in-flight posts resumable while reducing database volume at scale."],
 "0.2.74":["Added scale benchmark planning, disaster recovery readiness checks, Prometheus metrics, container health checks, smarter compression sampling, queue strategies, and worker safety pause controls."],
 "0.2.73":["Added daily GitHub release update checks with Status, Tasks, Settings, API, and CLI support."],
 "0.2.72":["Table sort preferences now persist per browser using cookies.","Backuprr now shows a first-use/update notice with recent feature highlights."],
 "0.2.71":["Fixed clickable table sorting headers after HTML attribute escaping broke handlers."],
 "0.2.70":["Table sorting now applies to the full paginated dataset.","Files gained sortable filesystem headers."],
 "0.2.69":["Completed queue defaults to oldest completed first.","Main tables gained sortable headers."],
 "0.2.68":["Queue removed duplicate Failed section.","Completed queue hides fields that are irrelevant after success."],
 "0.2.67":["Completed queue now shows stored chunk count instead of progress."],
 "0.2.66":["Retryable failed queue items recover after settings fixes.","Completed network-blocked rows no longer need attention."]
};
async function api(url, opts={}){
 if(Date.now() < apiRateLimitedUntil){
  return {error:"rate limit cooldown", rate_limited:true};
 }
 const headers = {"Content-Type":"application/json","X-Backuprr-Internal-Token":internalApiToken,"X-Backuprr-CSRF":csrfToken, ...(opts.headers || {})};
 if(cachedTotpCode) headers["X-Backuprr-TOTP"] = cachedTotpCode;
 let response = await fetch(url, {...opts, headers});
 let data = await response.json();
 if(response.status === 429){
  apiRateLimitedUntil = Date.now() + 2000;
  return {...data, rate_limited:true};
 }
 if(response.status === 403 && String(data.error || "").includes("TOTP")){
  cachedTotpCode = prompt("Admin action requires a 6-digit TOTP code") || "";
  if(cachedTotpCode){
   headers["X-Backuprr-TOTP"] = cachedTotpCode;
   response = await fetch(url, {...opts, headers});
   data = await response.json();
   if(response.status === 429){
    apiRateLimitedUntil = Date.now() + 2000;
    return {...data, rate_limited:true};
   }
  }
 }
 return data;
}
const post = (url, body={}) => api(url, {method:"POST", body:JSON.stringify(body)});
function esc(v){ return String(v ?? "").replace(/[&<>"']/g, s => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[s])); }
function jsString(v){ return JSON.stringify(String(v ?? "")).replace(/</g, "\\u003c"); }
function setCookie(name, value, maxAgeDays=365){
 document.cookie = `${encodeURIComponent(name)}=${encodeURIComponent(value)}; Max-Age=${maxAgeDays * 86400}; Path=/; SameSite=Lax`;
}
function getCookie(name){
 const key = `${encodeURIComponent(name)}=`;
 return document.cookie.split(";").map(item => item.trim()).find(item => item.startsWith(key))?.slice(key.length) || "";
}
function loadTableSorts(){
 try{
  const stored = JSON.parse(decodeURIComponent(getCookie("backuprr_table_sorts") || ""));
  return {...defaultTableSorts, ...stored};
 } catch {
  return JSON.parse(JSON.stringify(defaultTableSorts));
 }
}
function saveTableSorts(){
 setCookie("backuprr_table_sorts", JSON.stringify(tableSorts));
}
function labelize(value){
 const text = String(value ?? "").trim();
 if(!text) return "-";
 const known = {
  id:"ID", ts:"Time", file_id:"File ID", relative_path:"Path", event_type:"Event Type", last_verify_at:"Last Verified",
  last_chunk_verify_at:"Last Chunk Check", no_chunks:"No Chunks", missing_chunks:"Missing Chunks", backed_up:"Backed Up",
  cloud_backup:"Cloud Backup", restore_drill:"Restore Drill", backup_run_id:"Backup Run ID", app_version:"App Version",
  article_size:"Article Size", chunk_count:"Chunks", verified_chunks:"Verified", missing_chunks:"Missing",
  verification_state:"Verification", queue_status:"Queue Status", progress_chunks:"Progress Chunks", progress_bytes:"Progress Bytes",
  started_at:"Started", finished_at:"Finished", checked_at:"Checked", last_run:"Last Run", next_run_at:"Next Run At", last_error:"Last Error",
  interval_seconds:"Interval", time_until_next_run:"Next Run", last_run_duration:"Duration", bytes_total:"Total", bytes_done:"Done"
 };
 if(known[text]) return known[text];
 return text.replace(/[_-]+/g, " ").replace(/\b\w/g, char => char.toUpperCase());
}
function themeOptions(selected){
 return themeTemplates.map(theme => `<option value="${theme.id}" ${theme.id===selected ? "selected" : ""}>${esc(theme.name)}</option>`).join("");
}
function applyTheme(theme){
 const selected = themeTemplates.some(item => item.id === theme) ? theme : "harbor_light";
 document.documentElement.dataset.theme = selected;
 document.documentElement.dataset.reducedMotion = settingsCache?.ui_reduced_motion ? "true" : "false";
 return selected;
}
async function loadSettings(){
 settingsCache = await api("/api/settings");
 applyTheme(settingsCache.ui_theme);
 return settingsCache;
}
function table(rows, cols, options={}){
 if(!rows.length) return "<p class='muted'>No rows.</p>";
 return `<table><thead><tr>${cols.map(c=>sortableHeader(c, null, options)).join("")}</tr></thead><tbody>`+
 rows.map(r=>`<tr>${cols.map(c=>`<td data-sort-value="${esc(sortCellValue(c, r[c], r))}">${formatCellHtml(c, r[c], r)}</td>`).join("")}</tr>`).join("")+"</tbody></table>";
}
function validPagedResult(result){
 return Boolean(result && !result.error && Array.isArray(result.rows) && Number.isFinite(Number(result.total)));
}
function holdTableMessage(cached=null){
 if(cached) return "";
 const wait = Date.now() < apiRateLimitedUntil ? "Waiting for the internal API cooldown before loading this table..." : "Loading table data...";
 return `<p class='muted'>${esc(wait)}</p>`;
}
function isActiveRender(token, pageName){
 return token === renderSeq && page === pageName;
}
function sortableHeader(col, label, options={}){
 const sort = options.scope ? tableSorts[options.scope] || {} : {};
 const active = sort.col === col;
 const cls = active ? ` class="sort-${sort.dir === "desc" ? "desc" : "asc"}"` : "";
 const action = options.scope
  ? `sortServerTable(${jsString(options.scope)}, ${jsString(col)}, ${jsString(options.pageVar || "")}, ${jsString(options.updateFn || "")})`
  : "sortTableByHeader(this)";
 return `<th${cls}><button class="sort-header" type="button" onclick="${esc(action)}">${esc(label || labelize(col))}</button></th>`;
}
function sortQuery(scope){
 const sort = tableSorts[scope] || {};
 return sort.col ? `&sort=${encodeURIComponent(sort.col)}&dir=${encodeURIComponent(sort.dir || "asc")}` : "";
}
function sortServerTable(scope, col, pageVar, updateFn){
 const current = tableSorts[scope] || { col:"", dir:"asc" };
 tableSorts[scope] = { col, dir: current.col === col && current.dir !== "desc" ? "desc" : "asc" };
 saveTableSorts();
 if(pageVar) setPageVar(pageVar, 1);
 if(updateFn && typeof window[updateFn] === "function") window[updateFn]();
}
function setPageVar(pageVar, value){
 if(pageVar === "filesPage") filesPage = value;
 else if(pageVar === "logPage") logPage = value;
 else if(pageVar === "activeQueuePage") activeQueuePage = value;
 else if(pageVar === "completedQueuePage") completedQueuePage = value;
 else if(pageVar === "attentionQueuePage") attentionQueuePage = value;
 else if(pageVar === "verificationMissingPage") verificationMissingPage = value;
 else if(pageVar === "verificationUnverifiedPage") verificationUnverifiedPage = value;
 else if(pageVar === "verificationVerifiedPage") verificationVerifiedPage = value;
 else if(pageVar === "verificationNoChunksPage") verificationNoChunksPage = value;
}
function sortFilesBy(col){
 sortServerTable("files", col, "filesPage", "updateFilesPage");
}
function sortCellValue(col, value, row={}){
 if(col === "progress") return row.progress_percent ?? value ?? "";
 if(col === "state" || col === "status" || col === "verification_state" || col === "level" || col === "kind" || col === "reason" || col === "mode") return labelize(value);
 return value ?? "";
}
function sortTableByHeader(button){
 const th = button.closest("th");
 const table = button.closest("table");
 const tbody = table?.tBodies?.[0];
 if(!th || !table || !tbody) return;
 const index = Array.from(th.parentElement.children).indexOf(th);
 const descending = !th.classList.contains("sort-desc") && th.classList.contains("sort-asc");
 table.querySelectorAll("th").forEach(item => item.classList.remove("sort-asc","sort-desc"));
 th.classList.add(descending ? "sort-desc" : "sort-asc");
 const groups = [];
 Array.from(tbody.children).forEach(row => {
  if(row.classList.contains("task-detail") && groups.length){
   groups[groups.length - 1].push(row);
  } else {
   groups.push([row]);
  }
 });
 groups.sort((a,b) => compareSortValues(a[0].children[index], b[0].children[index], descending));
 groups.flat().forEach(row => tbody.appendChild(row));
}
function compareSortValues(aCell, bCell, descending){
 const a = aCell?.dataset?.sortValue ?? aCell?.textContent ?? "";
 const b = bCell?.dataset?.sortValue ?? bCell?.textContent ?? "";
 const an = Number(String(a).replace(/,/g, ""));
 const bn = Number(String(b).replace(/,/g, ""));
 let result;
 if(a !== "" && b !== "" && !Number.isNaN(an) && !Number.isNaN(bn)){
  result = an - bn;
 } else {
  result = String(a).localeCompare(String(b), undefined, { numeric:true, sensitivity:"base" });
 }
 return descending ? -result : result;
}
function formatCell(col, value){
 return ["size","size_bytes","files_bytes_total","files_bytes_backed_up","chunks_bytes_total","bytes_done","bytes_total","bytes_checked","article_size_bytes","max_article_size_bytes","estimated_bytes"].includes(col) ? formatBytes(value) : value;
}
function formatCellHtml(col, value, row={}){
 if(["size","size_bytes","files_bytes_total","files_bytes_backed_up","chunks_bytes_total","bytes_done","bytes_total","bytes_checked","article_size_bytes","max_article_size_bytes","estimated_bytes"].includes(col)) return esc(formatBytes(value));
 if(["ts","created_at","updated_at","last_backup_at","last_verify_at","last_chunk_verify_at","posted_at","verified_at","last_run","started_at","finished_at","checked_at"].includes(col)) return esc(formatDateTime(value));
 if(col === "time_until_next_run") return nextRunSpan(row);
 if(["state","status","verification_state"].includes(col)) return statePill(value);
 if(col === "level") return levelPill(value);
 if(col === "kind") return iconText(kindIcon(value), labelize(value));
 if(col === "progress") return iconText(iconForProgress(row.progress_percent), value);
 if(col === "last_error" && value) return iconText("&#9888;", value, "error");
 if(["event_type","reason","mode"].includes(col)) return esc(labelize(value));
 return esc(value);
}
function iconText(icon, text, cls=""){
 return `<span class="${cls}"><span class="ui-icon">${icon}</span>${esc(text)}</span>`;
}
function pageIcon(name){
 return ({Status:"&#128202;",Files:"&#128193;",Search:"&#128269;",Log:"&#128221;",Queue:"&#128230;",Tasks:"&#9881;",Verification:"&#10003;",Statistics:"&#128200;",Operations:"&#128736;",Security:"&#128737;",Settings:"&#128295;",About:"&#8505;"}[name] || "&#8226;");
}
function pageFromPath(path){
 const clean = String(path || "/").replace(/\/+$/, "") || "/";
 return slugPages[clean.toLowerCase()] || "Status";
}
function pagePath(name){
 return pageSlugs[name] || "/status";
}
function navigatePage(name){
 if(!pages.includes(name)) name = "Status";
 page = name;
 const path = pagePath(name);
 if(location.pathname !== path) history.pushState({ page:name }, "", path);
 render();
}
function stateIcon(value){
 return ({backed_up:"&#10003;",queued:"&#9203;",posting:"&#9658;",downloading:"&#11015;",failed:"&#9888;",deleted:"&#128465;",discovered:"&#128269;",changed:"&#9998;",missing_chunks:"&#9888;",unreadable:"&#128274;",restored:"&#8635;",done:"&#10003;",running:"&#9658;",scheduled:"&#9202;",verified:"&#10003;",missing:"&#9888;",unverified:"&#128269;",no_chunks:"&#128230;"}[String(value || "")] || "&#8226;");
}
function stateTone(value){
 return ({backed_up:"ok",done:"ok",restored:"ok",verified:"ok",queued:"warn",posting:"warn",running:"warn",verifying:"warn",restoring:"warn",downloading:"warn",unverified:"warn",no_chunks:"warn",failed:"bad",deleted:"bad",missing_chunks:"bad",missing:"bad",unreadable:"bad"}[String(value || "")] || "");
}
function statePill(value){
 const tone = stateTone(value);
 return `<span class="pill ${tone}"><span class="ui-icon">${stateIcon(value)}</span>${esc(labelize(value))}</span>`;
}
function levelPill(value){
 const key = String(value || "");
 const tone = ({error:"bad",warning:"warn",info:"info",debug:"debug",verbose:"verbose"}[key] || "");
 const icon = ({error:"&#10060;",warning:"&#9888;",info:"&#8505;",debug:"&#128027;",verbose:"&#128269;"}[key] || "&#8226;");
 return `<span class="pill ${tone}"><span class="ui-icon">${icon}</span>${esc(labelize(value))}</span>`;
}
function authPill(value){
 const key = String(value || "missing");
 const tone = ({configured:"ok",incomplete:"warn",missing:"bad"}[key] || "warn");
 const icon = ({configured:"&#128274;",incomplete:"&#9888;",missing:"&#128273;"}[key] || "&#9888;");
 return `<span class="pill ${tone}" title="Provider authentication is ${esc(labelize(key))}"><span class="ui-icon">${icon}</span>${esc(labelize(key))}</span>`;
}
function kindIcon(value){
 return ({catalog:"&#128193;",backup:"&#128230;",verification:"&#10003;",cloud_backup:"&#9729;",maintenance:"&#128736;",restore_drill:"&#8635;",update_check:"&#128260;"}[String(value || "")] || "&#9881;");
}
function iconForProgress(value){
 const pct = Number(value || 0);
 if(pct >= 100) return "&#10003;";
 if(pct > 0) return "&#9658;";
 return "&#9711;";
}
function nav(){
 document.getElementById("nav").innerHTML = pages.map(p=>`<button class="${p===page?"active":""}" onclick="navigatePage('${p}')"><span class="nav-icon">${pageIcon(p)}</span>${p}</button>`).join("");
 const title = document.getElementById("pageTitle");
 if(title) title.textContent = page;
}
async function updateHealthBar(){
 const target = document.getElementById("healthBar");
 if(!target) return;
 const now = Date.now();
 if(now - healthBarFetchedAt < 2500) return;
 healthBarFetchedAt = now;
 try{
  const [status, readiness] = await Promise.all([api("/api/status"), api("/api/readiness")]);
  const stats = status.stats || {};
  const paused = (status.paused_workers || []).length;
  const attention = Number(stats.queue_attention_count || 0);
  const missing = Number(stats.chunks_missing || 0);
  const readOnly = settingsCache?.read_only_mode;
  target.innerHTML = `
   <span class="health-chip ${attention ? "warn" : ""}"><span class="ui-icon">&#128230;</span>${attention ? `${attention} need attention` : "Queue ok"}</span>
   <span class="health-chip ${missing ? "bad" : ""}"><span class="ui-icon">&#10003;</span>${missing ? `${missing} missing chunks` : "Chunks ok"}</span>
   <span class="health-chip ${paused ? "warn" : ""}"><span class="ui-icon">&#9208;</span>${paused ? `${paused} paused` : "Workers active"}</span>
   <span class="health-chip"><span class="ui-icon">&#128737;</span>Coverage ${Number(readiness.protection_coverage ?? readiness.score ?? 0)}%</span>
   ${readOnly ? `<span class="health-chip warn"><span class="ui-icon">&#128274;</span>Read-only</span>` : ""}
   <button onclick="openCommandPalette()" title="Command palette">Ctrl+K</button>`;
 } catch {
  target.innerHTML = `<span class="health-chip warn">Health unavailable</span>`;
 }
}
function commandItems(){
 return [
  ["Status", () => navigatePage("Status")],
  ["Files", () => navigatePage("Files")],
  ["Queue", () => navigatePage("Queue")],
  ["Operations", () => navigatePage("Operations")],
  ["Settings", () => navigatePage("Settings")],
  ["Backup now", () => post("/api/backup/run").then(updateHealthBar)],
  ["Scan now", () => post("/api/scan").then(updateHealthBar)],
  ["Verify chunks", () => post("/api/verify/start", {force:true}).then(updateHealthBar)],
  ["Pause all workers", () => post("/api/worker/pause", {kind:"all"}).then(updateHealthBar)],
  ["Resume all workers", () => post("/api/worker/resume", {kind:"all"}).then(updateHealthBar)]
 ];
}
function openCommandPalette(){
 const target = document.getElementById("commandPalette");
 const items = commandItems();
 target.innerHTML = `<div class="command-palette" onclick="closeCommandPalette()"><div class="command-box" onclick="event.stopPropagation()"><input id="commandSearch" placeholder="Run command or jump to page" oninput="filterCommandPalette()" autofocus><div id="commandList" class="command-list">${items.map(([label], index)=>`<button data-command-index="${index}" onclick="runCommand(${index})">${esc(label)}</button>`).join("")}</div></div></div>`;
 setTimeout(()=>document.getElementById("commandSearch")?.focus(), 0);
}
function closeCommandPalette(){ document.getElementById("commandPalette").innerHTML = ""; }
function filterCommandPalette(){
 const q = document.getElementById("commandSearch")?.value.toLowerCase() || "";
 document.querySelectorAll("[data-command-index]").forEach(button => button.style.display = button.textContent.toLowerCase().includes(q) ? "" : "none");
}
function runCommand(index){
 const item = commandItems()[Number(index)];
 closeCommandPalette();
 if(item) item[1]();
}
function connectChanges(){
 if(eventSource) return;
 eventSource = new EventSource(`/api/events/stream?internal_token=${encodeURIComponent(internalApiToken)}`);
 eventSource.addEventListener("change", event => {
  const token = JSON.parse(event.data);
  const previous = lastChangeToken;
  lastChangeToken = token;
  if(previous) refreshPageForChanges(previous, token);
  else refreshCurrentLivePage();
 });
 eventSource.onerror = () => {};
}
function pushLabel(){
 return "";
}
function closeDropdowns(){
 document.querySelectorAll("details.dropdown[open]").forEach(dropdown => dropdown.removeAttribute("open"));
}
document.addEventListener("click", event => {
 document.querySelectorAll("details.dropdown[open]").forEach(dropdown => {
  if(!dropdown.contains(event.target)) dropdown.removeAttribute("open");
 });
});
document.addEventListener("keydown", event => {
 if(event.key === "Escape") closeDropdowns();
 if((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k"){ event.preventDefault(); openCommandPalette(); }
 if(event.key === "Escape") closeCommandPalette();
});
window.addEventListener("popstate", () => {
 page = pageFromPath(location.pathname);
 render();
});
if(location.pathname === "/"){
 history.replaceState({ page }, "", pagePath(page));
}
function logSelectionSummary(label, selected, total){
 if(!selected.length) return `${label}: None`;
 if(selected.length === total) return `All ${label}`;
 if(selected.length <= 2) return `${label}: ${selected.map(labelize).join(", ")}`;
 return `${label}: ${selected.length}`;
}
function multiSelectDropdown(label, cls, options, selected, renderer="", summaryId=""){
 const summary = logSelectionSummary(label, selected, options.length);
 const summaryAttr = summaryId ? ` id="${esc(summaryId)}"` : "";
 return `<details class="dropdown"><summary${summaryAttr}>${esc(summary)}</summary><div class="dropdown-menu">${options.map(option => {
  const content = renderer === "levelPill" ? levelPill(option) : esc(labelize(option));
  return `<label><input class="${cls}" type="checkbox" value="${esc(option)}" ${selected.includes(option) ? "checked" : ""} onchange="logPage=1;updateLogPage()"> ${content}</label>`;
 }).join("")}</div></details>`;
}
function eventTypeGroups(types){
 const groups = {};
 for(const type of types){
  const group = String(type).includes(".") ? String(type).split(".", 1)[0] : "general";
  groups[group] = groups[group] || [];
  groups[group].push(type);
 }
 return Object.entries(groups).sort((a,b)=>a[0].localeCompare(b[0]));
}
function groupedEventTypeDropdown(types, selected){
 const groups = eventTypeGroups(types);
 const summary = logSelectionSummary("Event types", selected, types.length);
 return `<details class="dropdown"><summary id="logEventTypeSummary">${esc(summary)}</summary><div class="dropdown-menu">${groups.map(([group, options]) => `
  <div class="dropdown-group">
   <label class="dropdown-group-title"><input class="logEventTypeGroup" type="checkbox" data-group="${esc(group)}" onchange="toggleLogEventTypeGroup(this)"> ${esc(labelize(group))}</label>
   <div class="dropdown-group-items">${options.map(option => `<label><input class="logEventType" data-group="${esc(group)}" type="checkbox" value="${esc(option)}" ${selected.includes(option) ? "checked" : ""} onchange="logPage=1;updateLogPage()"> ${esc(labelize(option))}</label>`).join("")}</div>
  </div>`).join("")}</div></details>`;
}
async function render(){
 const renderToken = ++renderSeq;
 const requestedPage = page;
 nav();
 connectChanges();
 if(!settingsCache) await loadSettings();
 else applyTheme(settingsCache.ui_theme);
 if(!isActiveRender(renderToken, requestedPage)) return;
 await updateVersionPill();
 await updateHealthBar();
 if(!isActiveRender(renderToken, requestedPage)) return;
 const c = document.getElementById("content");
 if(requestedPage==="Status"){
  c.innerHTML = `<div id="statusPanel"></div>`;
  await updateStatusPage({renderToken, pageName:requestedPage});
 }
 if(!isActiveRender(renderToken, requestedPage)) return;
 if(requestedPage==="Files"){
  c.innerHTML = `<div class="toolbar">
   <input id="filesSearch" placeholder="Search files" oninput="filesPage=1;updateFilesPage()">
   <label><input id="showUnbackedOnly" type="checkbox" onchange="filesPage=1;updateFilesPage()"> <span class="ui-icon">&#9888;</span>Only unbacked</label>
   <label><input id="showDeletedFiles" type="checkbox" onchange="filesPage=1;updateFilesPage()"> <span class="ui-icon">&#128465;</span>Show deleted</label>
   <button onclick="boostSelectedFiles()"><span class="ui-icon">&#8593;</span>Bump selected</button>
   ${selectedRestoreDropdown()}
   ${pushLabel()}
  </div><div id="restoreStatus" class="muted"></div><div id="filesTree"></div><div id="filesSelectionSummary" class="selection-summary"></div>`;
  await updateFilesPage({renderToken, pageName:requestedPage});
 }
 if(!isActiveRender(renderToken, requestedPage)) return;
 if(requestedPage==="Search"){
  c.innerHTML = `<div class="toolbar"><input id="q" placeholder="Search files"><button onclick="search()"><span class="ui-icon">&#128269;</span>Search</button></div><div id="results"></div>`;
 }
 if(!isActiveRender(renderToken, requestedPage)) return;
 if(requestedPage==="Log"){
  const eventTypes = await api("/api/log/event-types");
  if(!isActiveRender(renderToken, requestedPage)) return;
  const safeEventTypes = Array.isArray(eventTypes) ? eventTypes : [];
  if(!logEventTypeSelection.length) logEventTypeSelection = safeEventTypes.filter(type => type !== "web.access");
  const levels = ["error","warning","info","debug","verbose"];
  c.innerHTML = `<div class="toolbar-grid">
   <input id="logSearch" placeholder="Filter log text" value="${esc(logTextFilter)}" oninput="logTextFilter=this.value;logPage=1;updateLogPage(false)">
    <div class="toolbar-options">
    ${multiSelectDropdown("Levels", "logLevel", levels, logLevelSelection, "levelPill", "logLevelSummary")}
    ${groupedEventTypeDropdown(safeEventTypes, logEventTypeSelection)}
    ${pushLabel()}
   </div>
  </div><div id="logRows"></div>`;
  await updateLogPage({renderToken, pageName:requestedPage});
 }
 if(!isActiveRender(renderToken, requestedPage)) return;
 if(requestedPage==="Queue"){
  c.innerHTML = `<div class="toolbar"><select id="filter"><option>older-first</option><option>larger-first</option><option>smaller-first</option></select><button onclick="post('/api/queue/prioritize',{filter:document.getElementById('filter').value}).then(updateQueuePage)"><span class="ui-icon">&#8593;</span>Apply filter</button><button class="primary" onclick="post('/api/backup/run').then(updateQueuePage)"><span class="ui-icon">&#9658;</span>Backup now</button>${pushLabel()}</div><h2 class="section-title"><span class="ui-icon">&#9888;</span>Needs attention</h2><div id="attentionQueueRows"></div><h2 class="section-title"><span class="ui-icon">&#9658;</span>Active</h2><div id="activeQueueRows"></div><h2 class="section-title"><span class="ui-icon">&#10003;</span>Completed</h2><div id="completedQueueRows"></div>`;
  await updateQueuePage({renderToken, pageName:requestedPage});
 }
 if(!isActiveRender(renderToken, requestedPage)) return;
 if(requestedPage==="Tasks"){
  c.innerHTML = `<div id="taskRows"></div>`;
  await updateTasksPage({renderToken, pageName:requestedPage});
 }
 if(!isActiveRender(renderToken, requestedPage)) return;
 if(requestedPage==="Verification"){
  c.innerHTML = `<div class="toolbar"><input id="verificationSearch" placeholder="Filter verification files" value="${esc(verificationTextFilter)}" oninput="verificationTextFilter=this.value;verificationMissingPage=verificationUnverifiedPage=verificationVerifiedPage=verificationNoChunksPage=1;updateVerificationPage({invalidate:true})"><button class="primary" onclick="verifySelectedFiles()"><span class="ui-icon">&#10003;</span>Verify selected</button><button onclick="verifyAllFiles()"><span class="ui-icon">&#10003;</span>Verify all</button>${pushLabel()}</div><div id="verificationStatus" class="async-status"></div><h2 class="section-title"><span class="ui-icon">&#9888;</span>Missing chunks</h2><div id="verificationMissingRows"></div><h2 class="section-title"><span class="ui-icon">&#128269;</span>Unverified</h2><div id="verificationUnverifiedRows"></div><h2 class="section-title"><span class="ui-icon">&#10003;</span>Verified</h2><div id="verificationVerifiedRows"></div><h2 class="section-title"><span class="ui-icon">&#128230;</span>No chunks</h2><div id="verificationNoChunksRows"></div>`;
  await updateVerificationPage({invalidate:true, renderToken, pageName:requestedPage});
 }
 if(!isActiveRender(renderToken, requestedPage)) return;
 if(requestedPage==="Statistics"){
  c.innerHTML = `<div id="statisticsPanel"></div>`;
  await updateStatisticsPage({renderToken, pageName:requestedPage});
 }
 if(!isActiveRender(renderToken, requestedPage)) return;
 if(requestedPage==="Operations"){
  c.innerHTML = `<div id="operationsPanel"></div>`;
  await updateOperationsPage({renderToken, pageName:requestedPage});
 }
 if(!isActiveRender(renderToken, requestedPage)) return;
 if(requestedPage==="Security"){
  c.innerHTML = `<div id="securityPanel"></div>`;
  await updateSecurityPage({renderToken, pageName:requestedPage});
 }
 if(!isActiveRender(renderToken, requestedPage)) return;
 if(requestedPage==="Settings"){ settingsCache = await loadSettings(); if(!isActiveRender(renderToken, requestedPage)) return; c.innerHTML = settingsForm(settingsCache); addSettingsHelpText(); applySettingsHelpPreference(); initSettingsDirtyTracking(); }
 if(!isActiveRender(renderToken, requestedPage)) return;
 if(requestedPage==="About"){ c.innerHTML = aboutPage(); const s=await api("/api/status"); if(!isActiveRender(renderToken, requestedPage)) return; appVersion = s.version; updateVersionPillText(); maybeShowVersionNotice(appVersion); document.getElementById("aboutVersion").textContent=s.version; }
}
async function refreshCurrentLivePage(){
 await updateHealthBar();
 if(page==="Status") await updateStatusPage();
 if(page==="Files") await updateFilesPage();
 if(page==="Queue") await updateQueuePage();
 if(page==="Tasks") await updateTasksPage();
 if(page==="Verification") await updateVerificationPage();
 if(page==="Statistics") await updateStatisticsPage();
 if(page==="Operations") await updateOperationsPage();
 if(page==="Security") await updateSecurityPage();
}
async function refreshPageForChanges(previous, token){
 const filesChanged = previous.files_updated !== token.files_updated || previous.files_total !== token.files_total;
 const queueChanged = previous.queue_updated !== token.queue_updated || previous.queue_total !== token.queue_total;
 const eventsChanged = previous.event_id !== token.event_id;
 const transferChanged = previous.transfer_id !== token.transfer_id;
 const chunksChanged = previous.chunks_total !== token.chunks_total;
 const tasksChanged = previous.task_revision !== token.task_revision;
 const operationsChanged = previous.operation_revision !== token.operation_revision;
 if(page==="Status" && (filesChanged || queueChanged || chunksChanged || tasksChanged || transferChanged || operationsChanged)) await updateStatusPage();
 if(page==="Files" && (filesChanged || queueChanged || transferChanged || operationsChanged)) await updateFilesPage();
 if(page==="Log" && eventsChanged) await updateLogPage({incremental:true});
 if(page==="Queue" && (queueChanged || filesChanged || transferChanged)) await updateQueuePage();
 if(page==="Tasks" && (eventsChanged || tasksChanged)) await updateTasksPage();
 if(page==="Verification" && (chunksChanged || filesChanged || tasksChanged || operationsChanged)) await updateVerificationPage({invalidate:chunksChanged || filesChanged});
 if(page==="Statistics" && (filesChanged || queueChanged || chunksChanged || tasksChanged || eventsChanged || transferChanged)) await updateStatisticsPage();
 if(page==="Operations" && (eventsChanged || tasksChanged || transferChanged)) await updateOperationsPage();
 if(page==="Security" && eventsChanged) await updateSecurityPage();
 if(filesChanged || queueChanged || eventsChanged || tasksChanged || transferChanged) await updateHealthBar();
}
async function updateStatusPage(options={}){
 const [s, tasks, speed, readiness] = await Promise.all([
  api("/api/status"),
  api("/api/tasks"),
  api("/api/speed?minutes=10&bucket=10"),
  api("/api/readiness")
 ]);
 if(options.renderToken && !isActiveRender(options.renderToken, options.pageName || "Status")) return;
 if(s?.error || !Array.isArray(tasks)) return;
 appVersion = s.version;
 updateVersionPillText();
 maybeShowVersionNotice(appVersion);
 const panel = document.getElementById("statusPanel");
 if(panel) panel.innerHTML = statusDashboard(s, tasks, speed, readiness);
 updateNextRunLabels();
}
async function updateVersionPill(){
 if(appVersion) return updateVersionPillText();
 const target = document.getElementById("version");
 if(!target) return;
 const s = await api("/api/status");
 appVersion = s.version;
 updateVersionPillText();
 maybeShowVersionNotice(appVersion);
}
function updateVersionPillText(){
 const target = document.getElementById("version");
 if(target && appVersion) target.textContent = "v"+appVersion;
}
function maybeShowVersionNotice(version){
 if(!version) return;
 const seen = decodeURIComponent(getCookie("backuprr_seen_version") || "");
 if(seen === version) return;
 const firstUse = !seen;
 const notes = notesSince(seen, version);
 const target = document.getElementById("versionNotice");
 if(!target) return;
 target.innerHTML = `<div class="version-notice">
  <h3><span class="ui-icon">${firstUse ? "&#10024;" : "&#128230;"}</span>${firstUse ? "Welcome to Backuprr" : `Backuprr updated to v${esc(version)}`}</h3>
  <div class="muted">${firstUse ? "A quick look at what this build can do." : `Previously seen: ${esc(seen || "none")}`}</div>
  <ul>${notes.map(note => `<li>${esc(note)}</li>`).join("") || "<li>General fixes and polish.</li>"}</ul>
  <div class="toolbar"><button onclick="dismissVersionNotice()"><span class="ui-icon">&#10003;</span>Got it</button><button onclick="navigatePage('About');dismissVersionNotice()"><span class="ui-icon">&#8505;</span>About</button></div>
 </div>`;
}
function notesSince(seen, current){
 const versions = Object.keys(releaseNotes).sort(compareVersions);
 const seenIndex = seen ? versions.indexOf(seen) : -1;
 const currentIndex = versions.indexOf(current);
 const selected = currentIndex >= 0 ? versions.slice(Math.max(0, seenIndex + 1), currentIndex + 1) : [current];
 return selected.flatMap(version => releaseNotes[version] || [`Updated to ${version}.`]).slice(-8);
}
function compareVersions(a, b){
 const ap = String(a).split(".").map(Number);
 const bp = String(b).split(".").map(Number);
 for(let i=0; i<Math.max(ap.length, bp.length); i++){
  const delta = (ap[i] || 0) - (bp[i] || 0);
  if(delta) return delta;
 }
 return 0;
}
function dismissVersionNotice(){
 if(appVersion) setCookie("backuprr_seen_version", appVersion);
 const target = document.getElementById("versionNotice");
 if(target) target.innerHTML = "";
}
async function updateFilesPage(options={}){
 await refreshOperationProgress();
 if(options.renderToken && !isActiveRender(options.renderToken, options.pageName || "Files")) return;
 const openFolders = new Set(Array.from(document.querySelectorAll("#filesTree details[data-path][open]")).map(item => item.dataset.path));
 const showDeleted = !!document.getElementById("showDeletedFiles")?.checked;
 const unbacked = !!document.getElementById("showUnbackedOnly")?.checked;
 const q = document.getElementById("filesSearch")?.value || "";
 const result = await api(`/api/files?page=${filesPage}&page_size=${filesPageSize}&include_deleted=${showDeleted ? 1 : 0}&unbacked=${unbacked ? 1 : 0}&q=${encodeURIComponent(q)}${sortQuery("files")}`);
 if(options.renderToken && !isActiveRender(options.renderToken, options.pageName || "Files")) return;
 const valid = validPagedResult(result);
 if(valid) fileRowsCache = result.rows || [];
 for(const row of fileRowsCache){
  if(selectedFiles.has(Number(row.id))) selectedFileData.set(Number(row.id), row);
 }
 const target = document.getElementById("filesTree");
 if(target){
  const pageResult = valid ? result : {rows:fileRowsCache, page:filesPage, page_size:filesPageSize, total:fileRowsCache.length};
  target.innerHTML = holdTableMessage(valid ? pageResult : (fileRowsCache.length ? pageResult : null)) + fileTree(fileRowsCache, showDeleted) + paginationControls(pageResult, "filesPage", "updateFilesPage", "filesPageSize");
  target.querySelectorAll("details[data-path]").forEach(details => {
   if(openFolders.has(details.dataset.path)) details.open = true;
  });
  updateFolderCheckboxStates();
  updateFilesSelectionSummary();
 }
}
async function refreshOperationProgress(){
 const result = await api("/api/operations/progress");
 if(result && !result.error && Array.isArray(result.operations)){
  operationRowsCache = result.operations;
 }
}
async function updateQueuePage(options={}){
 const attention = await api(`/api/queue?status=attention&page=${attentionQueuePage}&page_size=${queuePageSize}${sortQuery("queueAttention")}`);
 const active = await api(`/api/queue?page=${activeQueuePage}&page_size=${queuePageSize}${sortQuery("queueActive")}`);
 const done = await api(`/api/queue?status=done&page=${completedQueuePage}&page_size=${queuePageSize}${sortQuery("queueCompleted")}`);
 if(options.renderToken && !isActiveRender(options.renderToken, options.pageName || "Queue")) return;
 queueResultCache.attention = validPagedResult(attention) ? attention : queueResultCache.attention;
 queueResultCache.active = validPagedResult(active) ? active : queueResultCache.active;
 queueResultCache.done = validPagedResult(done) ? done : queueResultCache.done;
 const attentionTarget = document.getElementById("attentionQueueRows");
 const activeTarget = document.getElementById("activeQueueRows");
 const doneTarget = document.getElementById("completedQueueRows");
 if(attentionTarget) attentionTarget.innerHTML = pagedTable(queueResultCache.attention, "attentionQueuePage", ["file_id","position","priority","status","reason","path","size","progress","state"], "queueAttention");
 if(activeTarget) activeTarget.innerHTML = pagedTable(queueResultCache.active, "activeQueuePage", ["file_id","position","priority","status","reason","path","size","progress","state"], "queueActive");
 if(doneTarget) doneTarget.innerHTML = pagedTable(queueResultCache.done, "completedQueuePage", ["file_id","path","size","chunk_count","state"], "queueCompleted");
}
function pagedTable(result, pageVar, cols, scope){
 if(!validPagedResult(result)) return holdTableMessage(null);
 const totalPages = Math.max(1, Math.ceil(Number(result.total || 0) / Number(result.page_size || queuePageSize)));
 const pageNo = Number(result.page || 1);
 return table(result.rows || [], cols, { scope, pageVar, updateFn:"updateQueuePage" }) + paginationControls(result, pageVar, "updateQueuePage", "queuePageSize");
}
function verificationTable(rows, tableKey){
 if(!rows.length) return "<p class='muted'>No rows.</p>";
 const colsByTable = {
  missing:["relative_path","progress","state","chunk_count","missing_chunks","last_chunk_verify_at"],
  unverified:["relative_path","progress","state","chunk_count"],
  verified:["relative_path","progress","state","chunk_count","last_verify_at","last_chunk_verify_at"],
  no_chunks:["relative_path","progress","state"]
 };
 const cols = colsByTable[tableKey] || ["relative_path","state"];
 const scope = `verification${verificationScopeSuffix(tableKey)}`;
 const pageVar = `verification${verificationScopeSuffix(tableKey)}Page`;
 return `<table><thead><tr><th><input class="verificationTableSelect" data-table-key="${esc(tableKey)}" type="checkbox" onchange="toggleVerificationTable('${esc(tableKey)}', this.checked)"></th>${cols.map(c=>sortableHeader(c, null, { scope, pageVar, updateFn:"updateVerificationPage" })).join("")}</tr></thead><tbody>`+
 rows.map(row => `<tr><td data-sort-value=""><input class="verificationSelect" type="checkbox" value="${Number(row.id)}" ${selectedVerificationFiles.has(Number(row.id)) ? "checked" : ""} onchange="setVerificationSelected(${Number(row.id)}, this.checked)"></td>${cols.map(c=>`<td data-sort-value="${esc(sortCellValue(c, row[c], row))}">${c === "progress" ? operationProgressHtml("verify", Number(row.id)) || "<span></span>" : formatCellHtml(c, row[c], row)}</td>`).join("")}</tr>`).join("")+
 "</tbody></table>";
}
function verificationScopeSuffix(state){
 return ({missing:"Missing",unverified:"Unverified",verified:"Verified",no_chunks:"NoChunks"}[state] || "Rows");
}
function verificationPagedTable(result, pageVar, state){
 const totalPages = Math.max(1, Math.ceil(Number(result.total || 0) / Number(result.page_size || 25)));
 const pageNo = Number(result.page || 1);
 return verificationTable(result.rows || [], state) + paginationControls(result, pageVar, "updateVerificationPage", "verificationPageSize", `${Number(result.total || 0)} ${labelize(state)}`);
}
function verificationStateConfigs(){
 const q = encodeURIComponent(verificationTextFilter);
 return [
  {state:"missing", pageVar:"verificationMissingPage", scope:"verificationMissing", page:verificationMissingPage},
  {state:"unverified", pageVar:"verificationUnverifiedPage", scope:"verificationUnverified", page:verificationUnverifiedPage},
  {state:"verified", pageVar:"verificationVerifiedPage", scope:"verificationVerified", page:verificationVerifiedPage},
  {state:"no_chunks", pageVar:"verificationNoChunksPage", scope:"verificationNoChunks", page:verificationNoChunksPage}
 ].map(item => ({
  ...item,
  url:`/api/verification?state=${item.state}&page=${item.page}&page_size=${verificationPageSize}&q=${q}${sortQuery(item.scope)}`,
  signature:`${item.state}|${item.page}|${verificationPageSize}|${verificationTextFilter}|${sortQuery(item.scope)}`
 }));
}
function validVerificationResult(result){
 return Boolean(result && !result.error && Array.isArray(result.rows) && Number.isFinite(Number(result.total)));
}
function emptyVerificationResult(state){
 return {rows:[], page:1, page_size:verificationPageSize, total:0, state};
}
function invalidateVerificationTableCache(){
 for(const key of Object.keys(verificationTableCache)){
  verificationTableCache[key] = {...verificationTableCache[key], signature:""};
 }
}
function cacheVerificationResult(state, result, signature=""){
 if(validVerificationResult(result)){
  verificationTableCache[state] = {
   ...result,
   signature,
   rows:(result.rows || []).map(row => ({...row}))
  };
  return result;
 }
 const cached = verificationTableCache[state];
 if(cached) return {...cached, rows:(cached.rows || []).map(row => ({...row}))};
 return emptyVerificationResult(state);
}
function renderVerificationTables(){
 let missing = cacheVerificationResult("missing", null);
 let unverified = cacheVerificationResult("unverified", null);
 let verified = cacheVerificationResult("verified", null);
 let noChunks = cacheVerificationResult("no_chunks", null);
 ({missing, unverified, verified, noChunks} = normalizeVerificationResults(missing, unverified, verified, noChunks));
 const missingTarget = document.getElementById("verificationMissingRows");
 const unverifiedTarget = document.getElementById("verificationUnverifiedRows");
 const verifiedTarget = document.getElementById("verificationVerifiedRows");
 const noChunksTarget = document.getElementById("verificationNoChunksRows");
 if(missingTarget) missingTarget.innerHTML = verificationPagedTable(missing, "verificationMissingPage", "missing");
 if(unverifiedTarget) unverifiedTarget.innerHTML = verificationPagedTable(unverified, "verificationUnverifiedPage", "unverified");
 if(verifiedTarget) verifiedTarget.innerHTML = verificationPagedTable(verified, "verificationVerifiedPage", "verified");
 if(noChunksTarget) noChunksTarget.innerHTML = verificationPagedTable(noChunks, "verificationNoChunksPage", "no_chunks");
 updateVerificationSelectionState([...(missing.rows || []), ...(unverified.rows || []), ...(verified.rows || []), ...(noChunks.rows || [])]);
}
async function refreshVerificationProgress(){
 const now = Date.now();
 if(now - verificationProgressFetchedAt < 1000) return;
 await refreshOperationProgress();
 verificationProgressFetchedAt = now;
}
function setVerificationSelected(fileId, checked){
 if(checked) selectedVerificationFiles.add(Number(fileId));
 else selectedVerificationFiles.delete(Number(fileId));
 updateVerificationSelectionState();
}
function toggleSelectAllVerification(checked){
 document.querySelectorAll(".verificationSelect").forEach(box => {
  box.checked = checked;
  setVerificationSelected(Number(box.value), checked);
 });
}
function toggleVerificationTable(tableKey, checked){
 const container = document.getElementById(`verification${verificationTableId(tableKey)}Rows`);
 if(!container) return;
 container.querySelectorAll(".verificationSelect").forEach(box => {
  box.checked = checked;
  setVerificationSelected(Number(box.value), checked);
 });
}
function verificationTableId(tableKey){
 return ({missing:"Missing",unverified:"Unverified",verified:"Verified",no_chunks:"NoChunks"}[tableKey] || "");
}
function updateVerificationSelectionState(rows=[]){
 const ids = rows.length ? rows.map(row => Number(row.id)) : Array.from(document.querySelectorAll(".verificationSelect")).map(box => Number(box.value));
 const selected = ids.filter(id => selectedVerificationFiles.has(id)).length;
 const selectAll = document.getElementById("selectAllVerification");
 if(selectAll){
  selectAll.checked = ids.length > 0 && selected === ids.length;
  selectAll.indeterminate = selected > 0 && selected < ids.length;
 }
 document.querySelectorAll(".verificationTableSelect").forEach(box => {
  const container = document.getElementById(`verification${verificationTableId(box.dataset.tableKey)}Rows`);
  const tableIds = Array.from(container?.querySelectorAll(".verificationSelect") || []).map(item => Number(item.value));
  const tableSelected = tableIds.filter(id => selectedVerificationFiles.has(id)).length;
  box.checked = tableIds.length > 0 && tableSelected === tableIds.length;
  box.indeterminate = tableSelected > 0 && tableSelected < tableIds.length;
 });
}
function normalizeVerificationResults(missing, unverified, verified, noChunks){
 for(const bucket of [missing, unverified, verified, noChunks]){
  for(const row of (bucket.rows || [])){
   verificationRowsCache.set(Number(row.id), row);
  }
 }
 const activeIds = new Set(operationRowsCache.filter(op => op.kind === "verify" && op.status === "running" && op.file_id).map(op => Number(op.file_id)));
 if(!activeIds.size) return {missing, unverified, verified, noChunks};
 const buckets = [missing, unverified, verified, noChunks];
 const activeRows = [];
 for(const bucket of buckets){
  bucket.rows = (bucket.rows || []).filter(row => {
   if(activeIds.has(Number(row.id))){
    activeRows.push({...row, state:"verifying", verification_state:"verifying"});
    return false;
   }
   return true;
  });
 }
 const existing = new Set((unverified.rows || []).map(row => Number(row.id)));
 for(const activeId of activeIds){
  if(!activeRows.some(row => Number(row.id) === activeId) && verificationRowsCache.has(activeId)){
   activeRows.push({...verificationRowsCache.get(activeId), state:"verifying", verification_state:"verifying"});
  }
 }
 for(const row of activeRows){
  if(!existing.has(Number(row.id))){
   unverified.rows = [row, ...(unverified.rows || [])];
   existing.add(Number(row.id));
  }
 }
 return {missing, unverified, verified, noChunks};
}
async function verifySelectedFiles(){
 const ids = Array.from(selectedVerificationFiles);
 if(!ids.length) return setVerificationStatus("Select files to verify first.", "bad");
 setVerificationStatus(`Starting verification for ${ids.length} selected file${ids.length === 1 ? "" : "s"}...`, "warn");
 const out = await post("/api/verify/start", { file_ids:ids });
 if(out.error) setVerificationStatus(out.error, "bad");
 else setVerificationStatus(`Verification started for ${ids.length} selected file${ids.length === 1 ? "" : "s"}.`, "warn", true);
 await updateVerificationPage();
}
async function verifyAllFiles(){
 setVerificationStatus("Starting verification for due chunks...", "warn");
 const out = await post("/api/verify/start", { force:true });
 if(out.error) setVerificationStatus(out.error, "bad");
 else setVerificationStatus("Verification started.", "warn", true);
 await updateVerificationPage();
}
function setVerificationStatus(message, tone="warn", transient=false){
 const target = document.getElementById("verificationStatus");
 if(!target) return;
 target.className = "async-status";
 target.innerHTML = statusMessageHtml(message, tone);
 if(transient) setTimeout(() => {
  if(target.innerHTML === statusMessageHtml(message, tone)) target.innerHTML = "";
 }, 3500);
}
async function updateTasksPage(options={}){
 const rows = await api("/api/tasks");
 if(options.renderToken && !isActiveRender(options.renderToken, options.pageName || "Tasks")) return;
 if(Array.isArray(rows)) tasksRowsCache = rows;
 const target = document.getElementById("taskRows");
 if(target) target.innerHTML = Array.isArray(rows) || tasksRowsCache.length ? tasksTable(tasksRowsCache) : holdTableMessage(null);
 updateNextRunLabels();
}
function taskActionButtons(kind, refresh="updateTasksPage"){
 if(kind === "catalog") return `<button class="primary" onclick="post('/api/scan').then(${refresh})"><span class="ui-icon">&#128193;</span>Scan now</button>`;
 if(kind === "backup") return `<button class="primary" onclick="post('/api/backup/run').then(${refresh})"><span class="ui-icon">&#9658;</span>Backup now</button>`;
 if(kind === "verification") return `<button onclick="post('/api/verify/start',{force:true}).then(${refresh})"><span class="ui-icon">&#10003;</span>Verify chunks</button>`;
 if(kind === "cloud_backup") return `<button onclick="post('/api/cloud-backup').then(${refresh})"><span class="ui-icon">&#9729;</span>Backup config/db</button>`;
 if(kind === "update_check") return `<button onclick="post('/api/update-check/run').then(${refresh})"><span class="ui-icon">&#128260;</span>Check now</button>`;
 return "";
}
function tasksTable(rows){
 if(!rows.length) return "<p class='muted'>No tasks.</p>";
 return `<table><thead><tr>${["Name","Kind","Status","Interval","Last Run","Duration","Next Run","Runs","Actions"].map(label=>sortableHeader(label, label)).join("")}</tr></thead><tbody>`+
 rows.map(task => {
  const result = task.last_result ? `<tr class="task-detail"><td colspan="9"><b>Last Result</b>: ${esc(task.last_result)}</td></tr>` : "";
  const error = task.last_error ? `<tr class="task-detail"><td colspan="9" class="error"><b>Last Error</b>: ${esc(task.last_error)}</td></tr>` : "";
  return `<tr><td data-sort-value="${esc(task.name)}">${esc(task.name)}</td><td data-sort-value="${esc(labelize(task.kind))}">${esc(labelize(task.kind))}</td><td data-sort-value="${esc(task.paused ? "paused" : task.status)}">${statePill(task.paused ? "paused" : task.status)}</td><td data-sort-value="${esc(task.interval_seconds)}">${esc(task.interval_seconds)}</td><td data-sort-value="${esc(task.last_run || "")}">${esc(formatDateTime(task.last_run) || "not yet")}</td><td data-sort-value="${esc(task.last_duration_seconds ?? "")}">${esc(task.last_run_duration || "-")}</td><td data-sort-value="${esc(task.next_run_at || "")}">${nextRunSpan(task)}</td><td data-sort-value="${esc(task.runs || 0)}">${esc(task.runs || 0)}</td><td data-sort-value=""><div class="task-row-actions">${taskActionButtons(task.kind)}</div></td></tr>${result}${error}`;
 }).join("")+
 "</tbody></table>";
}
async function updateVerificationPage(options={}){
 if(options.renderToken && !isActiveRender(options.renderToken, options.pageName || "Verification")) return;
 if(verificationRefreshRunning){
  clearTimeout(updateVerificationPage.retryTimer);
  updateVerificationPage.retryTimer = setTimeout(() => updateVerificationPage(options), 350);
  return;
 }
 verificationRefreshRunning = true;
 const seq = ++verificationRefreshSeq;
 try{
  if(options.invalidate) invalidateVerificationTableCache();
  await refreshVerificationProgress();
  verificationTextFilter = document.getElementById("verificationSearch")?.value || verificationTextFilter;
  const configs = verificationStateConfigs();
  const stale = configs.filter(item => verificationTableCache[item.state]?.signature !== item.signature);
  if(stale.length && Date.now() >= apiRateLimitedUntil){
   const item = stale[0];
   const result = await api(item.url);
   if(!result.rate_limited && validVerificationResult(result)) cacheVerificationResult(item.state, result, item.signature);
  }
  if(options.renderToken && !isActiveRender(options.renderToken, options.pageName || "Verification")) return;
  if(seq !== verificationRefreshSeq) return;
  renderVerificationTables();
  const remaining = verificationStateConfigs().some(item => verificationTableCache[item.state]?.signature !== item.signature);
  if(remaining){
   clearTimeout(updateVerificationPage.nextTimer);
   updateVerificationPage.nextTimer = setTimeout(() => updateVerificationPage(), Date.now() < apiRateLimitedUntil ? 2200 : 300);
  }
 } finally {
  verificationRefreshRunning = false;
 }
}
async function updateStatisticsPage(options={}){
 const data = await api("/api/statistics");
 if(!settingsCache) settingsCache = await api("/api/settings");
 if(options.renderToken && !isActiveRender(options.renderToken, options.pageName || "Statistics")) return;
 if(data?.error) return;
 const target = document.getElementById("statisticsPanel");
 if(target) target.innerHTML = statisticsDashboard(data);
}
async function updateOperationsPage(options={}){
 await refreshOperationProgress();
 const [tasks, plan, benchmark, recovery, health, maintenance, drills, runs, setup, alerts, failover, readiness, schedule, history] = await Promise.all([
  api("/api/tasks"),
  api("/api/dry-run"),
  api("/api/benchmark?files=50000&size=1073741824&folders=1000"),
  api("/api/disaster-recovery"),
  api("/api/health"),
  api("/api/maintenance"),
  api("/api/restore-drills"),
  api("/api/backup-runs?limit=20"),
  api("/api/setup-health"),
  api("/api/alerts"),
  api("/api/provider-failover"),
  api("/api/readiness"),
  api("/api/maintenance/schedule"),
  api("/api/config/history")
 ]);
 if(options.renderToken && !isActiveRender(options.renderToken, options.pageName || "Operations")) return;
 if(!Array.isArray(tasks)) return;
 const target = document.getElementById("operationsPanel");
 if(target) target.innerHTML = operationsDashboard(tasks, plan, benchmark, recovery, health.hosts || [], maintenance || [], drills || [], runs || [], setup, alerts.alerts || [], failover, readiness, schedule, history.rows || []);
}
async function updateSecurityPage(options={}){
 const [model, setup, recovery, settings] = await Promise.all([
  api("/api/threat-model"),
  api("/api/setup-health"),
  api("/api/disaster-recovery"),
  api("/api/settings")
 ]);
 if(options.renderToken && !isActiveRender(options.renderToken, options.pageName || "Security")) return;
 if(model?.error || setup?.error || recovery?.error || settings?.error) return;
 const target = document.getElementById("securityPanel");
 if(target) target.innerHTML = securityDashboard(model, setup, recovery, settings);
}
function paginationControls(result, pageVar, updateFn, pageSizeVar="", label=""){
 const totalPages = Math.max(1, Math.ceil(Number(result.total || 0) / Number(result.page_size || 1)));
 const pageNo = Number(result.page || 1);
 const pageSize = pageSizeVar ? `<label class="muted">Rows <select onchange="${pageSizeVar}=Number(this.value);${pageVar}=1;${updateFn}()">${[10,25,50,100,250].map(size=>`<option value="${size}" ${Number(result.page_size || 0)===size ? "selected" : ""}>${size}</option>`).join("")}</select></label>` : "";
 return `<div class="pagination"><button ${pageNo <= 1 ? "disabled" : ""} onclick="${pageVar}=Math.max(1,${pageVar}-1);${updateFn}()">Previous</button><span class="muted">Page ${pageNo} of ${totalPages} &middot; ${esc(label || `${Number(result.total || 0)} rows`)}</span><button ${pageNo >= totalPages ? "disabled" : ""} onclick="${pageVar}=${pageVar}+1;${updateFn}()">Next</button>${pageSize}</div>`;
}
function statusDashboard(status, tasks, speed, readiness={}){
 const stats = status.stats || {};
 const total = Number(stats.files_total || 0);
 const backed = Number(stats.files_backed_up || 0);
 const queued = Number(stats.files_queued || 0);
 const posting = Number(stats.files_posting || 0);
 const deleted = Number(stats.files_deleted || 0);
 const chunks = Number(stats.chunks_total || 0);
 const verifiedChunks = Number(stats.chunks_verified || 0);
 const missingChunks = Number(stats.chunks_missing || 0);
 const totalBytes = Number(stats.files_bytes_total || 0);
 const backedBytes = Number(stats.files_bytes_backed_up || 0);
 const queuedBytes = Number(stats.files_bytes_queued || 0);
 const postingBytes = Number(stats.files_bytes_posting || 0);
 const chunkBytes = Number(stats.chunks_bytes_total || 0);
 const doneQueue = Number(stats.queue_done || 0);
 const queuedQueue = Number(stats.queue_queued || 0);
 const postingQueue = Number(stats.queue_posting || 0);
 const throughput = status.throughput || {};
 const hourlyPostBudget = status.hourly_post_budget || {};
 const nntpThreads = status.nntp_threads || {};
 const compression = compressionSummary(stats);
  const par2 = par2Summary(stats);
  const attention = queueAttentionSummary(stats);
  const setup = status.setup_health || {};
  const alerts = status.alerts || [];
  const providerConfidence = status.provider_confidence || [];
  const protectedPct = total ? Math.round((backed / total) * 100) : 0;
 const activeTask = tasks.find(task => task.status === "running");
 const nextTask = tasks
  .filter(task => task.status !== "running" && (task.next_run_at || task.time_until_next_run))
  .sort((a,b) => nextRunMillis(a) - nextRunMillis(b))[0];
 return `<div class="dashboard">
  <div class="hero-status">
   <h2><span class="ui-icon">${activeTask ? "&#9658;" : "&#10003;"}</span>${esc(activeTask ? `${activeTask.name} is running` : "Backuprr is standing by")}</h2>
   <div class="muted">${activeTask ? esc(activeTask.last_result || "Working through the current task") : nextTask ? `Next: ${esc(nextTask.name)} in ${nextRunSpan(nextTask)}` : "No scheduled task time reported"}</div>
  <div class="progress-track"><div class="progress-fill" style="width:${protectedPct}%"></div></div>
  <div>${protectedPct}% backed up &middot; ${backed} of ${total} files protected (${formatBytes(backedBytes)} of ${formatBytes(totalBytes)}) &middot; ${queued + posting} waiting or posting (${formatBytes(queuedBytes + postingBytes)}) &middot; ${chunks} chunks posted (${formatBytes(chunkBytes)})</div>
   <div>${pushLabel()}</div>
  </div>
   <div class="task-strip">${tasks.map(taskCard).join("")}</div>
   ${setupHealthPanel(setup)}
   ${alertsPanel(alerts)}
   ${queueAttentionPanel(attention)}
   ${readinessPanel(readiness)}
  ${updateCheckPanel(status.update_check || {})}
  <div class="stats">
   ${statCard("Files", total, "&#128196;")}
   ${statCard("Data", formatBytes(totalBytes), "&#128190;")}
   ${statCard("Backed up", `${backed} / ${formatBytes(backedBytes)}`, "&#10003;")}
   ${statCard("Queued", `${queued} / ${formatBytes(queuedBytes)}`, "&#9203;")}
   ${statCard("Posting", `${posting} / ${formatBytes(postingBytes)}`, "&#9658;")}
   ${statCard("Deleted", deleted, "&#128465;")}
   ${statCard("Chunks", chunks, "&#129513;")}
   ${statCard("Verified chunks", verifiedChunks, "&#10003;")}
   ${statCard("Missing chunks", missingChunks, "&#9888;")}
  </div>
  <div class="chart-grid">
   ${throughputPanel(throughput)}
   ${hourlyPostBudgetPanel(hourlyPostBudget)}
    ${threadPanel(nntpThreads)}
    ${providerConfidencePanel(providerConfidence)}
    ${compressionPanel(compression)}
   ${par2Panel(par2)}
  </div>
  <div class="chart-grid">
   ${speedChart("Transfer speed", speed || [])}
   ${barChart("File states", [
    ["backed up", backed, "ok"],
    ["queued", queued, "warn"],
    ["posting", posting, "warn"],
    ["deleted", deleted, "bad"],
    ["other", Math.max(0, total - backed - queued - posting - deleted), "ok"]
   ])}
   ${barChart("Queue", [
    ["done", doneQueue, "ok"],
    ["queued", queuedQueue, "warn"],
    ["posting", postingQueue, "warn"]
   ])}
   ${barChart("Verification", [
    ["verified", verifiedChunks, "ok"],
    ["missing", missingChunks, "bad"],
    ["unchecked", Math.max(0, chunks - verifiedChunks - missingChunks), "warn"]
   ])}
  </div>
 </div>`;
}
function providerConfidencePanel(rows){
 const best = rows.length ? Math.round(rows.reduce((sum,row)=>sum + Number(row.confidence_score || 0), 0) / rows.length) : 0;
 return `<div class="chart-card">
  <h3><span class="ui-icon">&#128225;</span>Provider confidence</h3>
  <div class="thread-meter"><b>${rows.length ? `${best}%` : "-"}</b><span class="muted">${rows.length || 0} profiled host${rows.length === 1 ? "" : "s"}</span></div>
  <div class="progress-track"><div class="progress-fill" style="width:${best}%"></div></div>
  <div class="muted">${rows.slice(0,3).map(row => `${esc(row.host_name)} ${Number(row.confidence_score || 0)}%`).join(" / ") || "Run provider health checks to build confidence history."}</div>
 </div>`;
}
function setupHealthPanel(setup){
 if(!setup || !Array.isArray(setup.checks)) return "";
 const failed = setup.checks.filter(check => !check.ok);
 const pct = setup.checks.length ? Math.round(((setup.checks.length - failed.length) / setup.checks.length) * 100) : 100;
 return `<div class="chart-card">
  <h3><span class="ui-icon">${failed.length ? "&#9888;" : "&#10003;"}</span>Setup health</h3>
  <div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div>
  <div class="muted">${pct}% complete${failed.length ? ` / ${failed.length} item${failed.length === 1 ? "" : "s"} to fix` : ""}</div>
  <div class="setup-checks">${setup.checks.map(check => `<div><span class="ui-icon">${check.ok ? "&#10003;" : "&#9888;"}</span><b>${esc(check.label)}</b><span class="muted">${esc(check.detail || "")}</span></div>`).join("")}</div>
 </div>`;
}
function readinessPanel(readiness){
 if(!readiness || readiness.score == null) return "";
 const coverage = Number(readiness.protection_coverage ?? readiness.score ?? 0);
 const hardening = Number(readiness.hardening_score ?? readiness.score ?? 0);
 const gaps = (readiness.hardening_gaps || []).slice(0, 3);
 return `<div class="chart-card">
  <h3><span class="ui-icon">&#128737;</span>Protection coverage</h3>
  <div class="thread-meter"><b>${coverage}%</b><span class="muted">${Number(readiness.files_backed_up || 0)} of ${Number(readiness.files_total || 0)} files backed up</span></div>
  <div class="progress-track"><div class="progress-fill" style="width:${coverage}%"></div></div>
  <div class="muted">${Number(readiness.chunks_verified || 0)} verified chunks / ${Number(readiness.queue_attention || 0)} queue attention / ${Number(readiness.chunks_missing || 0)} missing</div>
  <div class="muted">Operational hardening: ${hardening}%${gaps.length ? ` / optional improvements: ${gaps.map(esc).join(", ")}` : ""}</div>
 </div>`;
}
function alertsPanel(alerts){
 if(!alerts.length) return "";
 return `<div class="hero-status danger-zone">
  <h2><span class="ui-icon">&#128276;</span>Notifications</h2>
  ${alerts.map(alert => `<div><b>${esc(alert.title)}</b> <span class="muted">${esc(alert.detail)}</span></div>`).join("")}
 </div>`;
}
function queueAttentionSummary(stats){
 return {
  count: Number(stats.queue_attention_count || 0),
  failed: Number(stats.queue_attention_failed || 0),
  networkBlocked: Number(stats.queue_attention_network_blocked || 0)
 };
}
function updateCheckPanel(update){
 if(!update || !update.status) return "";
 const checked = update.checked_at ? `Checked ${formatDateTime(update.checked_at)}` : "Not checked yet";
 if(update.status === "disabled") return `<div class="chart-card"><h3><span class="ui-icon">&#128260;</span>Updates</h3><div class="muted">GitHub update checks are disabled.</div></div>`;
 if(update.status === "error") return `<div class="hero-status"><h2><span class="ui-icon">&#9888;</span>Update check failed</h2><div class="muted">${esc(checked)}</div><div>${esc(update.error || "Unknown error")}</div></div>`;
 if(update.update_available) return `<div class="hero-status"><h2><span class="ui-icon">&#128230;</span>Update available: v${esc(update.latest_version)}</h2><div class="muted">${esc(checked)} / current v${esc(update.current_version || appVersion)}</div><div><a href="${esc(update.html_url || "#")}" target="_blank" rel="noreferrer">Open GitHub release</a></div></div>`;
 return `<div class="chart-card"><h3><span class="ui-icon">&#10003;</span>Updates</h3><div class="muted">${esc(checked)} / running v${esc(update.current_version || appVersion)} is current.</div></div>`;
}
function queueAttentionPanel(attention){
 if(!attention.count) return "";
 const details = [`${attention.count} item${attention.count === 1 ? "" : "s"} need attention`];
 if(attention.failed) details.push(`${attention.failed} failed`);
 if(attention.networkBlocked) details.push(`${attention.networkBlocked} network blocked`);
 return `<div class="hero-status">
  <h2><span class="ui-icon">&#9888;</span>Queue needs attention</h2>
  <div class="muted">${esc(details.join(" · "))}</div>
  <div>Open Queue for the failed or blocked items. Typical fixes are installing/configuring PAR2, checking provider auth, or retrying after network access is restored.</div>
 </div>`;
}
function queueAttentionPanel(attention){
 if(!attention.count) return "";
 const details = [`${attention.count} item${attention.count === 1 ? "" : "s"} need attention`];
 if(attention.failed) details.push(`${attention.failed} failed`);
 if(attention.networkBlocked) details.push(`${attention.networkBlocked} network blocked`);
 return `<div class="hero-status">
  <h2><span class="ui-icon">&#9888;</span>Queue needs attention</h2>
  <div class="muted">${esc(details.join(" / "))}</div>
  <div>Open Queue -> Needs attention for the failed or blocked items. Typical fixes are installing/configuring PAR2, checking provider auth, or retrying after network access is restored.</div>
 </div>`;
}
function compressionSummary(stats){
 const original = Number(stats.backup_uncompressed_bytes_total || 0);
 const compressed = Number(stats.backup_compressed_bytes_total || 0);
 const saved = Math.max(0, original - compressed);
 const gain = original ? Math.round((saved / original) * 1000) / 10 : 0;
 return {
  files: Number(stats.files_compressed || 0),
  tracked: Number(stats.files_compressible_backed_up || 0),
  original,
  compressed,
  saved,
  gain
 };
}
function par2Summary(stats){
 return {
  files: Number(stats.files_par2 || 0),
  protectedBytes: Number(stats.backup_par2_bytes_total || 0),
  totalBackedFiles: Number(stats.files_backed_up || 0),
  totalBackedBytes: Number(stats.files_bytes_backed_up || 0)
 };
}
function compressionPanel(summary){
 const pct = Math.min(100, Math.max(0, Number(summary.gain || 0)));
 return `<div class="chart-card">
  <h3><span class="ui-icon">&#128451;</span>Compression gain</h3>
  <div class="thread-meter"><b>${esc(`${summary.gain}%`)}</b><span class="muted">${formatBytes(summary.saved)} saved</span></div>
  <div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div>
  <div class="muted">${summary.files} compressed file${summary.files === 1 ? "" : "s"} &middot; ${formatBytes(summary.compressed)} posted from ${formatBytes(summary.original)} original</div>
 </div>`;
}
function par2Panel(summary){
 const pct = summary.totalBackedFiles ? Math.round((summary.files / summary.totalBackedFiles) * 100) : 0;
 return `<div class="chart-card">
  <h3><span class="ui-icon">&#128737;</span>PAR2 protection</h3>
  <div class="thread-meter"><b>${summary.files}</b><span class="muted">protected file${summary.files === 1 ? "" : "s"}</span></div>
  <div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div>
  <div class="muted">${pct}% of backed-up files &middot; ${formatBytes(summary.protectedBytes)} protected payload data</div>
 </div>`;
}
function aboutPage(){
 return `<h1><span class="ui-icon">&#128230;</span>Backuprr</h1>
 <p><span class="ui-icon">&#128278;</span>Version <span id="aboutVersion"></span></p>
 <p><span class="ui-icon">&#128274;</span>Catalog media folders, post obfuscated Usenet backups, verify article availability, and restore files when needed.</p>
 <h2 class="section-title"><span class="ui-icon">&#128202;</span>Application flow</h2>
 <div class="flowchart">
  ${flowNode("1", "Watch endpoints", "Catalog configured folders and detect new, changed, moved, or deleted files.")}
  ${flowNode("2", "Queue work", "Automatically queue unprotected files while respecting exclude filters and priorities.")}
  ${flowNode("3", "Prepare payload", "Optionally compress, encrypt article bodies, and add PAR2 recovery data.")}
  ${flowNode("4", "Post to Usenet", "Split payloads into articles, obfuscate subjects, retry/fail over hosts, and track progress.")}
  ${flowNode("5", "Verify chunks", "Check per-file chunk availability on schedule and requeue missing data.")}
  ${flowNode("6", "Restore", "Read chunks back, decrypt/decompress when needed, and restore to origin, destination, or browser download.")}
 </div>`;
}
function flowNode(step, title, body){
 return `<div class="flow-node ${step === "3" || step === "5" ? "flow-branch" : ""}"><b><span class="ui-icon">${esc(step)}</span>${esc(title)}</b><span>${esc(body)}</span></div>`;
}
function statCard(label, value, icon="&#8226;"){
 return `<div class="stat"><span><span class="ui-icon">${icon}</span>${esc(label)}</span><b>${esc(value)}</b></div>`;
}
function throughputPanel(throughput){
 return `<div class="chart-card">
  <h3><span class="ui-icon">&#128225;</span>Mbps throughput</h3>
  <div class="stats compact-stats">
   ${statCard("Upload now", `${Number(throughput.upload_mbps || 0).toFixed(2)} Mbps`, "&#8679;")}
   ${statCard("Download now", `${Number(throughput.download_mbps || 0).toFixed(2)} Mbps`, "&#8681;")}
   ${statCard("5 min upload", `${Number(throughput.average_upload_mbps || 0).toFixed(2)} Mbps`, "&#128200;")}
   ${statCard("5 min download", `${Number(throughput.average_download_mbps || 0).toFixed(2)} Mbps`, "&#128201;")}
  </div>
 </div>`;
}
function hourlyPostBudgetPanel(budget){
 const enabled = Boolean(Number(budget.enabled || 0));
 const used = Number(budget.used_bytes || 0);
 const limit = Number(budget.limit_bytes || 0);
 const remaining = Number(budget.remaining_bytes || 0);
 const pct = enabled ? Math.min(100, Math.max(0, Number(budget.percent || 0))) : 0;
 return `<div class="chart-card">
  <h3><span class="ui-icon">&#9201;</span>Hourly posting limit</h3>
  <div class="thread-meter"><b>${formatBytes(used)}</b><span class="muted">used in the last hour</span></div>
  <div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div>
  <div class="muted">${enabled ? `${pct}% of ${formatBytes(limit)} used, ${formatBytes(remaining)} remaining` : "No hourly posting limit configured"}</div>
 </div>`;
}
function threadPanel(threads){
 const total = Math.max(1, Number(threads.total || 1));
 const inUse = Math.max(0, Math.min(total, Number(threads.in_use || 0)));
 const pct = Math.round((inUse / total) * 100);
 return `<div class="chart-card">
  <h3><span class="ui-icon">&#129489;</span>NNTP threads</h3>
  <div class="thread-meter"><b>${inUse}</b><span class="muted">of ${total} in use</span></div>
  <div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div>
  <div class="muted">${pct}% active capacity</div>
 </div>`;
}
function taskCard(task){
 const running = task.status === "running";
 return `<div class="task-card">
  <h3><span class="ui-icon">${kindIcon(task.kind)}</span>${esc(task.name)}</h3>
  <span class="badge ${running ? "running" : ""}"><span class="ui-icon">${task.paused ? "&#9208;" : stateIcon(task.status)}</span>${esc(task.paused ? "paused" : task.status)}</span>
  <div class="muted"><span class="ui-icon">&#9201;</span>Last run: ${esc(formatDateTime(task.last_run) || "not yet")}</div>
  <div><span class="ui-icon">&#9201;</span>Duration: ${esc(task.last_run_duration || "-")}</div>
  <div><span class="ui-icon">&#9202;</span>Next run: ${nextRunSpan(task)}</div>
  <div class="${task.last_error ? "error" : "muted"}">${esc(task.last_error || task.last_result || "")}</div>
  <div class="toolbar-options">${taskActionButtons(task.kind, "updateStatusPage")}</div>
 </div>`;
}
function barChart(title, rows){
 const max = Math.max(1, ...rows.map(row => Number(row[1] || 0)));
 return `<div class="chart-card"><h3><span class="ui-icon">${title === "Queue" ? "&#128230;" : "&#128202;"}</span>${esc(title)}</h3>${rows.map(([label, value, tone]) => {
  const width = Math.max(0, Math.round((Number(value || 0) / max) * 100));
  return `<div class="bar-row"><span><span class="ui-icon">${stateIcon(label.replace(" ", "_"))}</span>${esc(label)}</span><div class="bar-track"><div class="bar-fill ${tone === "bad" ? "bad" : tone === "warn" ? "warn" : ""}" style="width:${width}%"></div></div><b>${esc(value)}</b></div>`;
 }).join("")}</div>`;
}
function statisticsDashboard(data){
 const stats = data.stats || {};
 const tasks = data.tasks || [];
 const speed = data.speed || [];
 const events = data.events || [];
 const backupRuns = data.backup_runs || [];
 const backupManifests = data.backup_manifests || [];
 const hostHealth = data.host_health || [];
 const providerProfiles = data.provider_profiles || [];
 const dbTables = data.db_tables || [];
 const verificationBacklog = data.verification_backlog || {};
  const maintenance = data.maintenance || [];
  const restoreDrills = data.restore_drills || [];
  const folderRollups = data.folder_rollups || [];
  const providerConfidence = data.provider_confidence || [];
  const dbGrowth = data.db_growth || {};
 const eventCounts = {};
 for(const event of events){ eventCounts[event.event_type] = (eventCounts[event.event_type] || 0) + 1; }
 const eventRows = Object.entries(eventCounts).sort((a,b)=>b[1]-a[1]).slice(0, 10).map(([label, value]) => [label, value, "ok"]);
 return `<div class="dashboard">
  <div class="stats">
   ${statCard("Active files", Number(stats.files_total || 0), "&#128196;")}
   ${statCard("All records", Number(stats.files_all_total || 0), "&#128452;")}
   ${statCard("Data cataloged", formatBytes(stats.files_bytes_total || 0), "&#128190;")}
   ${statCard("Chunks", Number(stats.chunks_total || 0), "&#129513;")}
   ${statCard("NNTP threads", settingsCache?.nntp_threads || "-", "&#128225;")}
   ${statCard("Verify backlog", verificationBacklog.due_files || 0, "&#10003;")}
  </div>
  <div class="chart-grid">
   ${speedChart("Two hour transfer speed", speed)}
   ${barChart("Engine tasks", tasks.map(task => [task.name, task.runs || 0, task.status === "running" ? "warn" : "ok"]))}
   ${barChart("Recent event types", eventRows.length ? eventRows : [["none", 0, "ok"]])}
  </div>
  <h2 class="section-title"><span class="ui-icon">&#9881;</span>Workers</h2>
  ${table(tasks, ["name","kind","status","interval_seconds","last_run","last_run_duration","time_until_next_run","runs","last_result","last_error"])}
  <h2 class="section-title"><span class="ui-icon">&#128230;</span>Backup runs</h2>
  ${table(backupRuns, ["id","file_id","status","reason","host","started_at","finished_at","chunks_done","chunks_total","bytes_done","bytes_total","error"])}
  <h2 class="section-title"><span class="ui-icon">&#128221;</span>Backup manifests</h2>
  ${table(backupManifests, ["id","file_id","backup_run_id","app_version","article_size","chunk_count","bytes_total","flags","created_at"])}
   <h2 class="section-title"><span class="ui-icon">&#128202;</span>Database tables</h2>
   ${table(dbTables, ["table","rows","estimated_bytes"])}
   <h2 class="section-title"><span class="ui-icon">&#128200;</span>Database growth controls</h2>
   <div class="stats">
    ${statCard("Current DB estimate", formatBytes(dbGrowth.current_estimated_bytes || 0), "&#128190;")}
    ${statCard("Projected @ 10 TiB", formatBytes((dbGrowth.projected_db_bytes || {})["10 TiB"] || 0), "&#128202;")}
    ${statCard("Chunk compaction", dbGrowth.chunk_compaction_enabled ? "Enabled" : "Disabled", "&#129513;")}
   </div>
   <h2 class="section-title"><span class="ui-icon">&#128193;</span>Folder rollups</h2>
   ${table(folderRollups, ["folder","files","bytes_total","backed_up_files","backed_up_bytes","verified_files","compressed_files","par2_files","attention_files"])}
   <h2 class="section-title"><span class="ui-icon">&#128225;</span>Provider confidence</h2>
   ${table(providerConfidence, ["host_name","mode","checks","failures","max_article_size_bytes","avg_latency_ms","confidence_score","last_checked_at"])}
   <h2 class="section-title"><span class="ui-icon">&#128225;</span>Provider profiles</h2>
  ${table(providerProfiles, ["host_name","mode","checks","failures","max_article_size_bytes","avg_latency_ms","last_checked_at"])}
  <h2 class="section-title"><span class="ui-icon">&#128225;</span>Host health</h2>
  ${table(hostHealth, ["host_name","mode","status","article_size_bytes","latency_ms","checked_at","message"])}
  <h2 class="section-title"><span class="ui-icon">&#128736;</span>Maintenance</h2>
  ${table(maintenance, ["kind","started_at","finished_at","result","details"])}
  <h2 class="section-title"><span class="ui-icon">&#8635;</span>Restore drills</h2>
  ${table(restoreDrills, ["file_id","path","status","checked_at","bytes_checked","message"])}
 </div>`;
}
function operationsDashboard(tasks, plan, benchmark, recovery, health, maintenance, drills, runs, setup, alerts, failover, readiness, schedule, history){
  return `<div class="dashboard">
   <div class="toolbar">
   <button class="danger" onclick="post('/api/worker/pause',{kind:'all'}).then(updateOperationsPage)"><span class="ui-icon">&#9208;</span>Pause all workers</button>
   <button onclick="post('/api/worker/resume',{kind:'all'}).then(updateOperationsPage)"><span class="ui-icon">&#9658;</span>Resume all workers</button>
   <button class="danger" onclick="post('/api/incident/start').then(out=>showInlineJson('operationsIncidentOut', out)).then(updateOperationsPage)"><span class="ui-icon">&#128680;</span>Incident mode</button>
   <button class="primary" onclick="post('/api/health/check').then(updateOperationsPage)"><span class="ui-icon">&#128225;</span>Check hosts + article size</button>
   <button onclick="post('/api/maintenance/run', { vacuum:false }).then(updateOperationsPage)"><span class="ui-icon">&#128736;</span>Prune logs</button>
    <button onclick="post('/api/maintenance/run', { vacuum:true }).then(updateOperationsPage)"><span class="ui-icon">&#128190;</span>Vacuum database</button>
    <button onclick="post('/api/restore-drill/run').then(updateOperationsPage)"><span class="ui-icon">&#8635;</span>Run restore drill</button>
    <button onclick="downloadDiagnostics()"><span class="ui-icon">&#128221;</span>Export diagnostics</button>
    <button onclick="downloadManifestExport()"><span class="ui-icon">&#128230;</span>Export manifest</button>
    ${pushLabel()}
   </div>
   <pre id="operationsIncidentOut"></pre>
   ${setupHealthPanel(setup)}
   ${alertsPanel(alerts || [])}
   ${operationProgressPanel()}
   ${providerCapabilityPanel(health)}
   ${readinessPanel(readiness)}
   <h2 class="section-title"><span class="ui-icon">&#9208;</span>Worker controls</h2>
  <div class="task-strip">${tasks.map(task => `<div class="task-card"><h3><span class="ui-icon">${kindIcon(task.kind)}</span>${esc(task.name)}</h3><div>${statePill(task.paused ? "paused" : task.status)}</div><div class="toolbar"><button onclick="post('/api/worker/pause',{kind:${jsString(task.kind)}}).then(updateOperationsPage)">Pause</button><button onclick="post('/api/worker/resume',{kind:${jsString(task.kind)}}).then(updateOperationsPage)">Resume</button></div></div>`).join("")}</div>
  <h2 class="section-title"><span class="ui-icon">&#128221;</span>Dry-run backup plan</h2>
  <div class="stats">
   ${statCard("Files", plan.files_total || 0, "&#128196;")}
   ${statCard("Unprotected", plan.files_unprotected || 0, "&#9888;")}
   ${statCard("Data to protect", formatBytes(plan.bytes_unprotected || 0), "&#128190;")}
   ${statCard("Estimated articles", plan.estimated_articles || 0, "&#129513;")}
   ${statCard("Estimated DB chunks", plan.estimated_chunk_rows || 0, "&#128202;")}
   ${statCard("PAR2 overhead", formatBytes(plan.estimated_par2_overhead_bytes || 0), "&#128737;")}
   ${statCard("Estimated time", plan.estimated_days_at_limit == null ? "No limit" : `${plan.estimated_days_at_limit} days`, "&#9201;")}
   </div>
   ${(plan.warnings || []).length ? `<div class="hero-status danger-zone"><h2><span class="ui-icon">&#9888;</span>Preflight warnings</h2>${plan.warnings.map(warning => `<div>${esc(warning)}</div>`).join("")}</div>` : ""}
  <h2 class="section-title"><span class="ui-icon">&#128300;</span>Scale benchmark model</h2>
  <div class="stats">
   ${statCard("Model files", benchmark.files || 0, "&#128196;")}
   ${statCard("Model data", formatBytes(benchmark.total_bytes || 0), "&#128190;")}
   ${statCard("Chunk rows", benchmark.estimated_chunk_rows || 0, "&#129513;")}
   ${statCard("Chunk table", formatBytes(benchmark.estimated_chunk_table_bytes || 0), "&#128202;")}
   ${statCard("Recommended article", formatBytes(benchmark.recommended_article_size || 0), "&#128225;")}
  </div>
  <h2 class="section-title"><span class="ui-icon">&#128737;</span>Disaster recovery readiness</h2>
  <div class="hero-status ${recovery.ok ? "" : "danger-zone"}">
   <h2><span class="ui-icon">${recovery.ok ? "&#10003;" : "&#9888;"}</span>${recovery.ok ? "Recovery inputs look complete" : "Recovery needs attention"}</h2>
   <div class="muted">Database: ${esc(recovery.database || "")} &middot; Config: ${esc(recovery.config || "")}</div>
   <div>${esc((recovery.issues || []).join(" / ") || "Config, database, and catalog metadata are present.")}</div>
  </div>
  <h2 class="section-title"><span class="ui-icon">&#8644;</span>Provider failover simulation</h2>
  ${failoverPanel(failover)}
  <h2 class="section-title"><span class="ui-icon">&#128225;</span>Provider health</h2>
  ${table(health, ["host_name","mode","status","article_size_bytes","latency_ms","checked_at","message"])}
  <h2 class="section-title"><span class="ui-icon">&#128736;</span>Maintenance schedule</h2>
  ${maintenanceSchedulePanel(schedule)}
  <h2 class="section-title"><span class="ui-icon">&#128230;</span>Recent backup sessions</h2>
  ${table(runs, ["id","file_id","status","reason","host","chunks_done","chunks_total","bytes_done","bytes_total","error"])}
  <h2 class="section-title"><span class="ui-icon">&#128736;</span>Maintenance history</h2>
  ${table(maintenance, ["kind","started_at","finished_at","result","details"])}
  <h2 class="section-title"><span class="ui-icon">&#8635;</span>Restore drill history</h2>
  ${table(drills, ["file_id","path","status","checked_at","bytes_checked","message"])}
  <h2 class="section-title"><span class="ui-icon">&#128221;</span>Config change history</h2>
  ${table(history || [], ["ts","actor","keys"])}
  </div>`;
}
function providerCapabilityPanel(health){
 const postRows = (health || []).filter(row => row.mode === "post");
 const maxArticle = Math.max(0, ...postRows.map(row => Number(row.article_size_bytes || 0)));
 const failures = (health || []).filter(row => row.status === "failed").length;
 return `<div class="chart-card">
  <h3><span class="ui-icon">&#128225;</span>Provider capability</h3>
  <div class="stats compact-stats">
   ${statCard("Post hosts", postRows.length, "&#8679;")}
   ${statCard("Max article", maxArticle ? formatBytes(maxArticle) : "Unknown", "&#129513;")}
   ${statCard("Recent failures", failures, "&#9888;")}
  </div>
  <div class="muted">${maxArticle ? "Article size has been probed." : "Run Check hosts + article size to profile provider limits."}</div>
 </div>`;
}
function maintenanceSchedulePanel(schedule){
 if(!schedule) return "<p class='muted'>No maintenance schedule data.</p>";
 return `<div class="stats">
  ${statCard("Interval", formatCountdownSeconds(schedule.next_interval_seconds || 0), "&#9201;")}
  ${statCard("Reclaim hint", formatBytes(schedule.estimated_reclaimable_hint_bytes || 0), "&#128190;")}
  ${statCard("Runs shown", (schedule.last_runs || []).length, "&#128736;")}
 </div><p class="muted">${esc(schedule.vacuum_note || "")}</p>${table(schedule.last_runs || [], ["kind","started_at","finished_at","result","details"])}`;
}
function showInlineJson(id, out){
 const target = document.getElementById(id);
 if(target) target.textContent = JSON.stringify(out, null, 2);
 return out;
}
function operationProgressPanel(){
 const running = operationRowsCache.filter(op => op.status === "running");
 if(!running.length) return "";
 return `<div class="chart-card">
  <h3><span class="ui-icon">&#9658;</span>Running operations</h3>
  ${running.map(op => `<div class="operation-line"><div><b>${esc(labelize(op.kind))}</b> <span class="muted">${esc(op.label || "")}</span></div>${inlineOperationProgress(op)}<button class="danger" onclick="cancelOperation(${jsString(op.id)})">Cancel</button></div>`).join("")}
 </div>`;
}
function inlineOperationProgress(op){
 const total = Number(op.total || 0);
 const done = Number(op.done || 0);
 const pct = total ? Math.min(100, Math.round((done / total) * 100)) : 5;
 const bytes = Number(op.bytes_done || 0) ? ` / ${formatBytes(op.bytes_done)}` : "";
 return `<div class="file-progress"><div class="progress-track"><div class="progress-fill" style="width:${Math.max(3,pct)}%"></div></div><span>${esc(op.message || `${done}/${total || "?"}`)}${esc(bytes)}</span></div>`;
}
async function cancelOperation(operationId){
 await post("/api/operations/cancel", { operation_id: operationId });
 await refreshOperationProgress();
 if(page === "Operations") updateOperationsPage();
 if(page === "Files") updateFilesPage();
 if(page === "Verification") updateVerificationPage();
}
function failoverPanel(report){
 if(!report || !report.modes) return `<p class="muted">No failover data available.</p>`;
 return `<div class="chart-grid">${Object.entries(report.modes).map(([mode, data]) => `<div class="chart-card">
  <h3><span class="ui-icon">${data.ok ? "&#10003;" : "&#9888;"}</span>${esc(labelize(mode))}</h3>
  <div class="muted">Configured: ${esc((data.configured || []).join(", ") || "none")}</div>
  <div>Primary after failure: <b>${esc(data.primary || "none")}</b></div>
  <div class="${data.ok ? "muted" : "error"}">${esc(data.recommendation || "At least one host remains available.")}</div>
 </div>`).join("")}</div>`;
}
function securityDashboard(model, setup, recovery, settings){
 const mitigations = model.mitigations || [];
 const secretRows = model.secret_health || [];
 return `<div class="dashboard">
  <div class="hero-status">
   <h2><span class="ui-icon">&#128737;</span>Security posture</h2>
   <div class="muted">This page describes what Backuprr can protect directly and what still depends on deployment hygiene.</div>
  </div>
  <div class="stats">
   ${statCard("Web auth", settings.has_web_ui_password ? "Enabled" : "Off", "&#128274;")}
   ${statCard("TOTP", settings.totp_enabled ? "Enabled" : "Off", "&#128273;")}
   ${statCard("Read-only", settings.read_only_mode ? "On" : "Off", "&#128274;")}
   ${statCard("External keys", Number(settings.external_api_key_count || 0), "&#128273;")}
   ${statCard("API rate limit", `${Number(settings.api_rate_limit_per_minute || 0) || "Off"}/min`, "&#9201;")}
   ${statCard("External limit", `${Number(settings.external_api_rate_limit_per_minute || 0) || "Off"}/min`, "&#9201;")}
  </div>
  <h2 class="section-title"><span class="ui-icon">&#10003;</span>Mitigations</h2>
  <div class="chart-grid">${mitigations.map(item => `<div class="chart-card">
   <h3><span class="ui-icon">${item.status === "ok" ? "&#10003;" : "&#9888;"}</span>${esc(item.area)}</h3>
   <div class="muted">${esc(item.detail)}</div>
  </div>`).join("")}</div>
  <h2 class="section-title"><span class="ui-icon">&#128273;</span>Secret health</h2>
  ${table(secretRows, ["name","ok","detail"])}
  ${!settings.has_web_ui_password ? `<div class="hero-status danger-zone"><h2><span class="ui-icon">&#9888;</span>Exposure warning</h2><div>Web UI password is disabled. Keep Backuprr bound to localhost or behind a trusted authenticated proxy.</div></div>` : ""}
  <h2 class="section-title"><span class="ui-icon">&#128221;</span>Assumptions</h2>
  <div class="chart-card">${(model.assumptions || []).map(item => `<div>${esc(item)}</div>`).join("")}</div>
  <h2 class="section-title"><span class="ui-icon">&#9888;</span>Not protected against</h2>
  <div class="chart-card">${(model.not_protected_against || []).map(item => `<div>${esc(item)}</div>`).join("")}</div>
  ${setupHealthPanel(setup)}
  <h2 class="section-title"><span class="ui-icon">&#128737;</span>Recovery readiness</h2>
  <div class="hero-status ${recovery.ok ? "" : "danger-zone"}"><h2>${recovery.ok ? "Recovery inputs look complete" : "Recovery needs attention"}</h2><div>${esc((recovery.issues || []).join(" / ") || "No open recovery issues.")}</div></div>
 </div>`;
}
async function downloadDiagnostics(){
 const data = await api("/api/diagnostics");
 const blob = new Blob([JSON.stringify(data, null, 2)], {type:"application/json"});
 const url = URL.createObjectURL(blob);
 const link = document.createElement("a");
 link.href = url;
 link.download = `backuprr-diagnostics-${new Date().toISOString().replace(/[:.]/g,"-")}.json`;
 document.body.appendChild(link);
 link.click();
 link.remove();
 URL.revokeObjectURL(url);
}
async function downloadManifestExport(){
 const data = await api("/api/manifest/export");
 const blob = new Blob([data.payload || JSON.stringify(data, null, 2)], {type:"application/json"});
 const url = URL.createObjectURL(blob);
 const link = document.createElement("a");
 link.href = url;
 link.download = `backuprr-manifest-${new Date().toISOString().replace(/[:.]/g,"-")}.json`;
 document.body.appendChild(link);
 link.click();
 link.remove();
 URL.revokeObjectURL(url);
}
function speedChart(title, rows){
 const width = 520, height = 170, pad = 28;
 const max = Math.max(1, ...rows.flatMap(row => [Number(row.upload_bps || 0), Number(row.download_bps || 0)]));
 const points = (key) => rows.map((row, index) => {
  const x = rows.length <= 1 ? pad : pad + (index / (rows.length - 1)) * (width - pad * 2);
  const y = height - pad - (Number(row[key] || 0) / max) * (height - pad * 2);
  return `${x.toFixed(1)},${y.toFixed(1)}`;
 }).join(" ");
 const latest = rows[rows.length - 1] || {};
 const maxLabel = formatBytes(max) + "/s";
 return `<div class="chart-card"><h3><span class="ui-icon">&#128200;</span>${esc(title)}</h3>
  <svg viewBox="0 0 ${width} ${height}" width="100%" height="180" role="img" aria-label="Transfer speed over time">
   <line x1="${pad}" y1="${height-pad}" x2="${width-pad}" y2="${height-pad}" stroke="#2b3b3d"/>
   <line x1="${pad}" y1="${pad}" x2="${pad}" y2="${height-pad}" stroke="#2b3b3d"/>
   <text x="${pad + 4}" y="${pad - 7}" font-size="11" fill="#8fa39f">${esc(maxLabel)}</text>
   <text x="${pad}" y="${height - 4}" font-size="11" fill="#8fa39f">30 min ago</text>
   <text x="${width - pad - 22}" y="${height - 4}" font-size="11" fill="#8fa39f">now</text>
   <text x="${width - pad - 112}" y="${pad + 12}" font-size="11" fill="#7dd3c7">upload</text>
   <text x="${width - pad - 62}" y="${pad + 12}" font-size="11" fill="#f59e0b">download</text>
   <polyline points="${points("upload_bps")}" fill="none" stroke="#7dd3c7" stroke-width="3"/>
   <polyline points="${points("download_bps")}" fill="none" stroke="#f59e0b" stroke-width="3"/>
  </svg>
  <div class="muted">Upload ${formatBytes(Number(latest.upload_bps || 0))}/s &middot; Download ${formatBytes(Number(latest.download_bps || 0))}/s</div>
 </div>`;
}
function formatBytes(value){
 const units = ["B","KiB","MiB","GiB"];
 let size = Number(value || 0);
 let index = 0;
 while(size >= 1024 && index < units.length - 1){ size /= 1024; index++; }
 return `${size.toFixed(index ? 1 : 0)} ${units[index]}`;
}
function bytesToGb(value){
 return Math.round(Number(value || 0) / 1073741824);
}
function gbToBytes(value){
 return Math.round(Number(value || 0) * 1073741824);
}
function bytesToKib(value){
 return Math.round(Number(value || 0) / 1024);
}
function kibToBytes(value){
 return Math.round(Number(value || 0) * 1024);
}
function postLimitLabel(gb){
 const value = Number(gb || 0);
 return value <= 0 ? "No limit" : `${value} GB/hour`;
}
function articleSizeLabel(kib){
 const value = Number(kib || 0);
 return value >= 1024 ? `${(value / 1024).toFixed(value % 1024 ? 1 : 0)} MiB` : `${value} KiB`;
}
function countLabel(value, unit){
 return `${Number(value || 0)} ${unit}`;
}
function formatDateTime(value){
 if(!value) return "";
 const date = new Date(value);
 if(Number.isNaN(date.getTime())) return value;
 return new Intl.DateTimeFormat(undefined, { dateStyle:"medium", timeStyle:"medium" }).format(date);
}
function formatCountdownSeconds(seconds){
 if(seconds === null || seconds === undefined || Number.isNaN(Number(seconds))) return "-";
 const total = Math.max(0, Math.round(Number(seconds)));
 const hours = Math.floor(total / 3600);
 const minutes = Math.floor((total % 3600) / 60);
 const secs = total % 60;
 if(hours) return `${hours}h ${minutes}m ${secs}s`;
 if(minutes) return `${minutes}m ${secs}s`;
 return `${secs}s`;
}
function countdownFromIso(value){
 if(!value) return "-";
 const target = new Date(value);
 if(Number.isNaN(target.getTime())) return "-";
 return formatCountdownSeconds((target.getTime() - Date.now()) / 1000);
}
function nextRunSpan(task){
 const nextRunAt = task?.next_run_at || "";
 return `<span class="next-run" data-next-run-at="${esc(nextRunAt)}">${esc(nextRunAt ? countdownFromIso(nextRunAt) : task?.time_until_next_run || "-")}</span>`;
}
function updateNextRunLabels(){
 document.querySelectorAll(".next-run[data-next-run-at]").forEach(item => {
  item.textContent = countdownFromIso(item.dataset.nextRunAt);
 });
}
setInterval(updateNextRunLabels, 1000);
function secondsFromLabel(label){
 const text = String(label || "");
 const h = Number((text.match(/(\d+)h/) || [0,0])[1]);
 const m = Number((text.match(/(\d+)m/) || [0,0])[1]);
 const s = Number((text.match(/(\d+)s/) || [0,0])[1]);
 return h * 3600 + m * 60 + s;
}
function nextRunMillis(task){
 if(task?.next_run_at){
  const target = new Date(task.next_run_at).getTime();
  if(!Number.isNaN(target)) return target;
 }
 return Date.now() + secondsFromLabel(task?.time_until_next_run) * 1000;
}
function toggleLogEventTypeGroup(groupInput){
 const container = groupInput.closest(".dropdown-group");
 if(!container) return;
 container.querySelectorAll(".logEventType").forEach(input => input.checked = groupInput.checked);
 logPage = 1;
 updateLogPage();
}
function updateLogEventTypeGroupStates(){
 document.querySelectorAll(".logEventTypeGroup").forEach(groupInput => {
  const items = Array.from(groupInput.closest(".dropdown-group")?.querySelectorAll(".logEventType") || []);
  const checked = items.filter(input => input.checked).length;
  groupInput.checked = checked > 0 && checked === items.length;
  groupInput.indeterminate = checked > 0 && checked < items.length;
 });
}
function updateLogFilterLabels(){
 const levelOptions = Array.from(document.querySelectorAll(".logLevel"));
 const eventOptions = Array.from(document.querySelectorAll(".logEventType"));
 const levelSummary = document.getElementById("logLevelSummary");
 const eventSummary = document.getElementById("logEventTypeSummary");
 if(levelSummary) levelSummary.textContent = logSelectionSummary("Levels", logLevelSelection, levelOptions.length);
 if(eventSummary) eventSummary.textContent = logSelectionSummary("Event types", logEventTypeSelection, eventOptions.length);
 updateLogEventTypeGroupStates();
}
function logQueryParts(){
 const levels = logLevelSelection.map(level => "level="+encodeURIComponent(level)).join("&");
 const eventTypes = logEventTypeSelection.map(type => "event_type="+encodeURIComponent(type)).join("&");
 return {levels, eventTypes};
}
function currentLogSignature(){
 const sort = tableSorts.log || {};
 return `${logPage}|${logPageSize}|${logTextFilter}|${logLevelSelection.join(",")}|${logEventTypeSelection.join(",")}|${sort.col || "id"}|${sort.dir || "desc"}`;
}
function renderLogRows(result){
 const target = document.getElementById("logRows");
 if(target) target.innerHTML = table(result.rows || [], ["id","ts","level","event_type","message","file_id"], { scope:"log", pageVar:"logPage", updateFn:"updateLogPage" }) + paginationControls(result, "logPage", "updateLogPage", "logPageSize");
}
function canUpdateLogIncrementally(signature){
 const sort = tableSorts.log || {};
 return logPage === 1 && (!sort.col || sort.col === "id") && (!sort.dir || sort.dir === "desc") && signature === logSignature && logResultCache && logNewestId > 0;
}
async function updateLogPage(options={}){
 if(options.renderToken && !isActiveRender(options.renderToken, options.pageName || "Log")) return;
 logLevelSelection = Array.from(document.querySelectorAll(".logLevel:checked")).map(input => input.value);
 logEventTypeSelection = Array.from(document.querySelectorAll(".logEventType:checked")).map(input => input.value);
 logTextFilter = document.getElementById("logSearch")?.value || logTextFilter;
 const {levels, eventTypes} = logQueryParts();
 const signature = currentLogSignature();
 if(options.incremental && canUpdateLogIncrementally(signature)){
  const delta = await api(`/api/log?page=1&page_size=${logPageSize}&after_id=${logNewestId}&q=${encodeURIComponent(logTextFilter)}&${levels}&${eventTypes}`);
  if(options.renderToken && !isActiveRender(options.renderToken, options.pageName || "Log")) return;
  if(delta.rate_limited){
   renderLogRows(logResultCache);
   updateLogFilterLabels();
   return;
  }
  if(delta.incremental && Array.isArray(delta.rows) && delta.rows.length){
   const seen = new Set(logRowsCache.map(row => Number(row.id)));
   const incoming = delta.rows.filter(row => !seen.has(Number(row.id)));
   logRowsCache = [...incoming, ...logRowsCache].slice(0, logPageSize);
   logNewestId = Math.max(logNewestId, ...incoming.map(row => Number(row.id || 0)));
   logResultCache = {...logResultCache, rows:logRowsCache, total:Number(logResultCache.total || 0) + incoming.length};
   renderLogRows(logResultCache);
   updateLogFilterLabels();
   return;
  }
  renderLogRows(logResultCache);
  updateLogFilterLabels();
  return;
 }
 const result = await api(`/api/log?page=${logPage}&page_size=${logPageSize}&q=${encodeURIComponent(logTextFilter)}&${levels}&${eventTypes}${sortQuery("log")}`);
 if(options.renderToken && !isActiveRender(options.renderToken, options.pageName || "Log")) return;
 if(!result.error && Array.isArray(result.rows)){
  logRowsCache = result.rows;
  logResultCache = result;
  logSignature = signature;
  logNewestId = Math.max(0, ...logRowsCache.map(row => Number(row.id || 0)));
  renderLogRows(result);
 } else if(logResultCache) {
  renderLogRows(logResultCache);
 }
 updateLogFilterLabels();
}
async function loadLog(){ await updateLogPage(); }
function fileTree(rows, showDeleted=false){
 const root = { dirs:{}, files:[] };
 for(const row of rows.filter(row => showDeleted || row.state !== "deleted")){
  const parts = String(row.relative_path || row.path || "").split(/[\\/]+/).filter(Boolean);
  let node = root;
  node.total_size = (node.total_size || 0) + Number(row.size || 0);
  for(const part of parts.slice(0, -1)){
   node.dirs[part] = node.dirs[part] || { dirs:{}, files:[], total_size:0 };
   node = node.dirs[part];
   node.total_size = (node.total_size || 0) + Number(row.size || 0);
  }
  node.files.push({...row, display_name: parts[parts.length - 1] || row.path});
 }
 return `<div class="tree"><div class="tree-header"><span><input id="selectAllFiles" type="checkbox" title="Select page" onchange="toggleSelectAllFiles(this.checked)"></span><span></span>${fileSortHeader("relative_path", "Name")}${fileSortHeader("progress", "Progress")}${fileSortHeader("size", "Size")}${fileSortHeader("state", "State")}${fileSortHeader("last_verify_at", "Verification")}<span>Actions</span></div><ul>${treeNode(root, "", showDeleted)}</ul></div>`;
}
function fileSortHeader(col, label){
 const sort = tableSorts.files || {};
 const cls = sort.col === col ? ` sort-${sort.dir === "desc" ? "desc" : "asc"}` : "";
 return `<span class="tree-sort${cls}"><button class="sort-header" type="button" onclick="${esc(`sortFilesBy(${jsString(col)})`)}">${esc(label)}</button></span>`;
}
function treeNode(node, prefix, showDeleted){
 const dirs = Object.keys(node.dirs).sort((a,b)=>a.localeCompare(b));
 const dirHtml = dirs.map(name => {
  const path = prefix ? prefix+"/"+name : name;
  const state = folderState(node.dirs[name]);
  const canRestore = folderChunkCount(node.dirs[name]) > 0;
  const canPrioritize = folderCanPrioritize(node.dirs[name]);
  const ids = collectNodeFiles(node.dirs[name]).map(file => Number(file.id));
  return `<li class="folder"><details data-path="${esc(path)}"><summary class="tree-row folder-row"><input type="checkbox" class="folderSelect" data-file-ids="${esc(ids.join(","))}" onchange="event.stopPropagation();selectFolderFiles(this.dataset.fileIds, this.checked)"><span>&#128193;</span><span class="tree-name">${esc(name)}</span><span></span><span class="tree-meta">${countFiles(node.dirs[name])} files / ${formatBytes(node.dirs[name].total_size || 0)}</span>${statePill(state)}${folderVerifiedPill(node.dirs[name])}<span class="tree-actions">${canPrioritize ? `<button class="icon-btn" title="Increase folder queue priority" onclick="event.preventDefault();boostFolder(${jsString(path)})">&#8593;</button>` : ""}${canRestore ? folderRestoreDropdown(path) : ""}</span></summary><ul>${treeNode(node.dirs[name], path, showDeleted)}</ul></details></li>`;
 }).join("");
 const fileHtml = node.files.sort(compareFileRows).map(file => fileRow(file)).join("");
 return dirHtml + fileHtml;
}
function compareFileRows(a, b){
 const sort = tableSorts.files || { col:"relative_path", dir:"asc" };
 const col = sort.col || "relative_path";
 const av = fileSortValue(a, col);
 const bv = fileSortValue(b, col);
 const an = Number(av);
 const bn = Number(bv);
 let result = !Number.isNaN(an) && !Number.isNaN(bn)
  ? an - bn
  : String(av ?? "").localeCompare(String(bv ?? ""), undefined, { numeric:true, sensitivity:"base" });
 if(result === 0) result = String(a.display_name || a.relative_path || "").localeCompare(String(b.display_name || b.relative_path || ""), undefined, { numeric:true, sensitivity:"base" });
 return sort.dir === "desc" ? -result : result;
}
function fileSortValue(file, col){
 if(col === "progress") return Number(file.progress_chunks || 0);
 if(col === "verification") return file.last_verify_at || "";
 if(col === "name") return file.display_name || file.relative_path || file.path || "";
 return file[col] ?? "";
}
function countFiles(node){
 return node.files.length + Object.values(node.dirs).reduce((total, child) => total + countFiles(child), 0);
}
function folderChunkCount(node){
 return node.files.reduce((total, file) => total + Number(file.chunk_count || 0), 0) + Object.values(node.dirs).reduce((total, child) => total + folderChunkCount(child), 0);
}
function folderState(node){
 const files = collectNodeFiles(node).filter(file => file.state !== "deleted");
 if(!files.length) return "empty";
 if(files.every(file => file.state === "backed_up")) return "backed_up";
 if(files.some(file => ["failed","missing_chunks"].includes(file.state))) return "missing_chunks";
 if(files.some(file => ["queued","posting"].includes(file.state))) return "queued";
 return "discovered";
}
function folderCanPrioritize(node){
 return collectNodeFiles(node).filter(file => file.state !== "deleted").some(file => file.state !== "backed_up");
}
function folderVerifiedPill(node){
 const files = collectNodeFiles(node).filter(file => file.state !== "deleted" && Number(file.chunk_count || 0) > 0);
 if(!files.length) return `<span class="pill warn" title="No chunk records"><span class="ui-icon">&#128230;</span>No chunks</span>`;
 const missing = files.filter(file => Number(file.missing_chunks || 0) > 0).length;
 if(missing) return `<span class="pill bad" title="${missing} file(s) have missing chunks"><span class="ui-icon">&#9888;</span>Missing</span>`;
 const verified = files.filter(file => file.last_verify_at).length;
 if(verified === files.length) return `<span class="pill ok" title="All files in this folder have been verified"><span class="ui-icon">&#10003;</span>Verified</span>`;
 if(verified > 0) return `<span class="pill warn" title="${verified} of ${files.length} restorable files verified"><span class="ui-icon">&#128269;</span>${verified}/${files.length}</span>`;
 return `<span class="pill warn" title="Files have chunks but have not been verified yet"><span class="ui-icon">&#128269;</span>Unverified</span>`;
}
function collectNodeFiles(node){
 return node.files.concat(...Object.values(node.dirs).map(child => collectNodeFiles(child)));
}
function fileRow(file){
 const canQueue = !["backed_up", "deleted", "posting", "queued"].includes(file.state);
 const hasChunks = Number(file.chunk_count || 0) > 0;
 const checked = selectedFiles.has(Number(file.id)) ? "checked" : "";
 const progress = fileProgress(file);
 const displayState = activeOperationFor("download", Number(file.id)) ? "downloading" : activeOperationFor("restore", Number(file.id)) ? "restoring" : file.state;
 return `<li><div class="tree-row file-row">
  <input type="checkbox" class="fileSelect" value="${Number(file.id)}" ${checked} onchange="setFileSelected(${Number(file.id)}, this.checked)">
  <span>&#128196;</span>
  <span class="tree-name">${esc(file.display_name)}</span>
  ${progress}
  ${fileSizeMeta(file)}
  ${statePill(displayState)}
  <span class="feature-pills">${backupFeaturePills(file)}${verifiedPill(file.last_verify_at)}</span>
  <span class="tree-actions">
  ${canQueue ? `<button class="icon-btn" title="Queue file" onclick="queueFile(${Number(file.id)})">&#10133;</button>` : ""}
  ${file.state !== "backed_up" && file.state !== "deleted" ? `<button class="icon-btn" title="Increase queue priority" onclick="boostFile(${Number(file.id)})">&#8593;</button>` : ""}
  ${hasChunks ? restoreDropdown(Number(file.id)) : ""}
  </span>
 </div></li>`;
}
function fileSizeMeta(file){
 const original = Number(file.backup_uncompressed_size || file.size || 0);
 const backup = Number(file.backup_compressed_size || 0);
 if(backup > 0 && backup !== original){
  return `<span class="tree-meta">${formatBytes(original)}<small title="Payload size posted to Usenet">${formatBytes(backup)} posted</small></span>`;
 }
 return `<span class="tree-meta">${formatBytes(file.size || original)}</span>`;
}
function backupFeaturePills(file){
 const pills = [];
 if(Number(file.backup_compressed || 0)){
  pills.push(`<span class="pill tone-compressed" title="This backup payload was compressed before posting"><span class="ui-icon">&#128451;</span>Compressed</span>`);
 }
 if(Number(file.backup_par2 || 0)){
  pills.push(`<span class="pill tone-par2" title="This backup has PAR2 recovery protection"><span class="ui-icon">&#128737;</span>PAR2</span>`);
 }
 return pills.join("");
}
function restoreDropdown(fileId){
 return `<details class="dropdown" onclick="event.stopPropagation()"><summary class="icon-btn" title="Restore or download">&#8635;</summary><div class="dropdown-menu restore-destination"><button onclick="restoreCatalogFileMode(${Number(fileId)}, 'origin')">Restore To Origin</button><button onclick="showRestoreDestination(${Number(fileId)})">Restore To New Destination</button><button onclick="restoreCatalogFileMode(${Number(fileId)}, 'download')">Download In Browser</button><button onclick="restoreRehearsal(${Number(fileId)})">Restore Rehearsal</button><button onclick="showIntegrityReceipt(${Number(fileId)})">Integrity Receipt</button><div id="restoreDest${Number(fileId)}" class="hidden"><input placeholder="Destination path"><button onclick="restoreCatalogFileMode(${Number(fileId)}, 'destination', this.previousElementSibling.value)">Restore</button></div></div></details>`;
}
async function showIntegrityReceipt(fileId){
 closeDropdowns();
 const receipt = await api(`/api/files/receipt?file_id=${Number(fileId)}`);
 setRestoreStatus(`Receipt: ${receipt.chunk_count} chunks / ${receipt.compressed ? "compressed" : "plain"} / ${receipt.par2_protected ? "PAR2" : "no PAR2"} / last verified ${formatDateTime(receipt.last_verify_at) || "never"}`, "ok");
 console.log("Backuprr integrity receipt", receipt);
}
function folderRestoreDropdown(path){
 return `<details class="dropdown" onclick="event.stopPropagation()"><summary class="icon-btn" title="Restore folder">&#8635;</summary><div class="dropdown-menu restore-destination"><button onclick="restoreCatalogFolderMode(${jsString(path)}, 'origin')">Restore To Origin</button><button onclick="showFolderRestoreDestination(this)">Restore To New Destination</button><div class="hidden"><input placeholder="Destination folder"><button onclick="restoreCatalogFolderMode(${jsString(path)}, 'destination', this.previousElementSibling.value)">Restore</button></div></div></details>`;
}
function selectedRestoreDropdown(){
 return `<details class="dropdown" onclick="event.stopPropagation()"><summary><span class="ui-icon">&#8635;</span>Restore selected</summary><div class="dropdown-menu restore-destination"><button onclick="restoreSelectedFilesMode('origin')">Restore To Origin</button><button onclick="showSelectedRestoreDestination(this)">Restore To New Destination</button><button onclick="restoreSelectedFilesMode('download')">Download Zip</button><div class="hidden"><input placeholder="Destination folder"><button onclick="restoreSelectedFilesMode('destination', this.previousElementSibling.value)">Restore</button></div></div></details>`;
}
function showRestoreDestination(fileId){
 const target = document.getElementById(`restoreDest${Number(fileId)}`);
 if(target) target.classList.toggle("hidden");
}
function showFolderRestoreDestination(button){
 const target = button.nextElementSibling;
 if(target) target.classList.toggle("hidden");
}
function showSelectedRestoreDestination(button){
 const target = button.nextElementSibling;
 if(target) target.classList.toggle("hidden");
}
function verifiedPill(timestamp){
 if(!timestamp) return `<span></span>`;
 return `<span class="pill verified tone-verified" title="Verified ${esc(formatDateTime(timestamp))}"><span class="ui-icon">&#10003;</span>Verified</span>`;
}
function operationFor(kind, fileId){
 const matching = operationRowsCache.filter(op => op.kind === kind && Number(op.file_id || 0) === Number(fileId));
 return matching.sort((a,b)=>String(b.updated_at || "").localeCompare(String(a.updated_at || "")))[0] || null;
}
function activeOperationFor(kind, fileId){
 const op = operationFor(kind, fileId);
 return op && op.status === "running" ? op : null;
}
function operationProgressHtml(kind, fileId){
 const op = operationFor(kind, fileId);
 if(!op || op.status !== "running") return "";
 const total = Number(op.total || 0);
 const done = Number(op.done || 0);
 const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
 const detail = Number(op.bytes_done || 0) ? ` - ${formatBytes(op.bytes_done)}` : "";
 const label = `${labelize(kind)} ${total ? `${done}/${total}` : "starting"}${detail}`;
 return `<div class="file-progress"><div class="progress-track"><div class="progress-fill" style="width:${Math.max(3,pct)}%"></div></div><span>${esc(label)}</span></div>`;
}
function fileProgress(file){
 const downloadProgress = operationProgressHtml("download", Number(file.id));
 if(downloadProgress) return downloadProgress;
 const restoreProgress = operationProgressHtml("restore", Number(file.id));
 if(restoreProgress) return restoreProgress;
 const active = file.state === "posting" || file.queue_status === "posting";
 if(!active) return `<span></span>`;
 const expected = Math.max(1, Math.ceil(Number(file.size || 0) / Number(settingsCache?.article_size || 786432)));
 const chunks = Number(file.progress_chunks || 0);
 const bytes = Number(file.progress_bytes || 0);
 const pct = Math.min(100, Math.round((chunks / expected) * 100));
 const label = chunks > 0 ? `${chunks}/${expected} chunks - ${formatBytes(bytes)} posted - ${pct}%` : `posting first chunk - ${formatBytes(bytes)} posted`;
 return `<div class="file-progress"><div class="progress-track"><div class="progress-fill" style="width:${Math.max(3,pct)}%"></div></div><span>${esc(label)}</span></div>`;
}
function setFileSelected(fileId, checked){
 const id = Number(fileId);
 if(checked){
  selectedFiles.add(id);
  const row = fileRowsCache.find(item => Number(item.id) === id);
  if(row) selectedFileData.set(id, row);
 } else {
  selectedFiles.delete(id);
  selectedFileData.delete(id);
 }
 updateFolderCheckboxStates();
 updateFilesSelectionSummary();
}
function selectFolderFiles(idList, checked){
 const ids = String(idList || "").split(",").map(Number).filter(Boolean);
 for(const id of ids){
  if(checked){
   selectedFiles.add(id);
   const row = fileRowsCache.find(item => Number(item.id) === id);
   if(row) selectedFileData.set(id, row);
  } else {
   selectedFiles.delete(id);
   selectedFileData.delete(id);
  }
 }
 updateFilesPage();
}
function toggleSelectAllFiles(checked){
 for(const row of fileRowsCache){
  const id = Number(row.id);
  if(checked){
   selectedFiles.add(id);
   selectedFileData.set(id, row);
  } else {
   selectedFiles.delete(id);
   selectedFileData.delete(id);
  }
 }
 updateFilesPage();
}
function updateFolderCheckboxStates(){
 document.querySelectorAll(".folderSelect").forEach(box => {
  const ids = String(box.dataset.fileIds || "").split(",").map(Number).filter(Boolean);
  const selected = ids.filter(id => selectedFiles.has(id)).length;
  box.checked = ids.length > 0 && selected === ids.length;
  box.indeterminate = selected > 0 && selected < ids.length;
 });
 const selectAll = document.getElementById("selectAllFiles");
 if(selectAll){
  const ids = fileRowsCache.map(row => Number(row.id));
  const selected = ids.filter(id => selectedFiles.has(id)).length;
  selectAll.checked = ids.length > 0 && selected === ids.length;
  selectAll.indeterminate = selected > 0 && selected < ids.length;
 }
}
function updateFilesSelectionSummary(){
 const target = document.getElementById("filesSelectionSummary");
 if(!target) return;
 const selectedRows = Array.from(selectedFileData.values());
 const totalSize = selectedRows.reduce((total, row) => total + Number(row.size || 0), 0);
 const restorable = selectedRows.filter(row => Number(row.chunk_count || 0) > 0).length;
 const unbacked = selectedRows.filter(row => row.state !== "backed_up" && row.state !== "deleted").length;
 const progressRows = selectedRows.filter(row => row.state === "posting" || row.queue_status === "posting" || Number(row.progress_chunks || 0) > 0);
 const progressHtml = progressRows.length ? `<div class="toolbar-options">${progressRows.slice(0, 4).map(row => `<div class="mini-progress"><b>${esc(row.relative_path || row.path)}</b>${fileProgress(row)}</div>`).join("")}</div>` : "";
 target.innerHTML = selectedRows.length
  ? `<b>${selectedRows.length}</b> selected &middot; ${formatBytes(totalSize)} &middot; ${restorable} restorable &middot; ${unbacked} unbacked${progressHtml}`
  : `<span class="muted">No files selected.</span>`;
}
async function queueFile(fileId){
 const out = await post("/api/files/queue", { file_id:fileId });
 if(!out.ok) alert(out.error || "Unable to queue file");
 await updateFilesPage();
}
async function boostFile(fileId){
 const out = await post("/api/files/priority", { file_id:fileId, amount:10 });
 if(!out.ok) alert(out.error || "Unable to prioritize file");
 await updateFilesPage();
}
async function boostFolder(path){
 const out = await post("/api/folders/priority", { path:path, amount:10 });
 if(out.error) alert(out.error);
 await updateFilesPage();
}
async function boostSelectedFiles(){
  const ids = Array.from(selectedFiles);
  if(!ids.length) return alert("Select files first");
  const selectedRows = Array.from(selectedFileData.values()).filter(row => selectedFiles.has(Number(row.id)));
  const totalBytes = selectedRows.reduce((sum,row)=>sum + Number(row.size || 0), 0);
  if(!confirm(`Increase queue priority for ${ids.length} selected item(s) totaling ${formatBytes(totalBytes)}?`)) return;
  const out = await post("/api/files/priority-many", { file_ids:ids, amount:10 });
 if(out.error) alert(out.error);
 await updateFilesPage();
}
async function restoreSelectedFiles(){
 return restoreSelectedFilesMode("origin");
}
function statusProgressHtml(message, pct=0, tone="warn", indeterminate=false){
 const width = Math.max(0, Math.min(100, Number(pct || 0)));
 return `<span class="pill ${tone}"><span class="ui-icon">${tone === "ok" ? "&#10003;" : tone === "bad" ? "&#9888;" : "&#9658;"}</span>${esc(message)}</span><div class="progress-track"><div class="progress-fill ${indeterminate ? "indeterminate" : ""}" style="width:${indeterminate ? 42 : width}%"></div></div>`;
}
function statusMessageHtml(message, tone="warn"){
 return `<span class="pill ${tone}"><span class="ui-icon">${tone === "ok" ? "&#10003;" : tone === "bad" ? "&#9888;" : "&#9658;"}</span>${esc(message)}</span>`;
}
function setRestoreStatus(message, tone="warn", transient=false){
 const target = document.getElementById("restoreStatus");
 if(target){
  target.className = "async-status";
  target.innerHTML = statusMessageHtml(message, tone);
  if(transient) setTimeout(() => {
   if(target.innerHTML === statusMessageHtml(message, tone)) target.innerHTML = "";
  }, 3500);
 }
}
async function restoreSelectedFilesMode(mode, destValue=""){
 const selectedRows = Array.from(selectedFileData.values()).filter(row => Number(row.chunk_count || 0) > 0);
 if(!selectedRows.length){
  setRestoreStatus("Select files with recorded chunks first.", "bad");
  return;
 }
 if(mode === "destination" && !destValue){
  setRestoreStatus("Choose a destination folder first.", "bad");
  return;
 }
 closeDropdowns();
 if(mode === "download"){
  const ids = selectedRows.map(row => `file_id=${encodeURIComponent(row.id)}`).join("&");
  setRestoreStatus(`Preparing restore zip for ${selectedRows.length} files...`, "warn", true);
  window.open(`/api/restore/download-zip?internal_token=${encodeURIComponent(internalApiToken)}&${ids}`, "_blank");
  return;
 }
  const dest = mode === "destination" ? destValue : "";
  const preview = await post("/api/restore/preview", { file_ids:selectedRows.map(row => row.id), dest:dest || "" });
  if(!confirm(`Restore ${preview.files} file(s), ${formatBytes(preview.bytes_total)} total, destination: ${preview.destination}, overwrites: ${preview.overwrite_count}. Continue?`)) return;
  let restored = 0;
 setRestoreStatus(`Starting restore for ${selectedRows.length} files...`, "warn");
 for(const file of selectedRows){
  const preflight = await post("/api/restore/preflight", { path:file.path, dest:dest || "" });
  const warning = preflight.issues?.length ? `${preflight.issues.join("\n")}\nSuggested quarantine: ${preflight.quarantine_path}` : preflight.warning;
  if(warning && !confirm(`${file.relative_path || file.path}\n${warning}\nContinue restore?`)){
   setRestoreStatus(`Skipped ${file.relative_path || file.path}`, "warn", true);
   continue;
  }
  const out = await post("/api/restore/start", { path:file.path, dest:dest || null });
  if(out.error){
   setRestoreStatus(out.error, "bad");
   return;
  }
  restored++;
  setRestoreStatus(`Started ${restored} of ${selectedRows.length} restore jobs.`, "warn");
 }
 setRestoreStatus(`Restore jobs started for ${restored} files.`, "ok", true);
 await updateFilesPage();
}
async function restoreCatalogFile(fileId){
 return restoreCatalogFileMode(fileId, "origin");
}
async function restoreCatalogFileMode(fileId, mode, destValue=""){
 const file = fileRowsCache.find(row => Number(row.id) === Number(fileId));
 if(!file) return;
 if(mode === "download"){
  setRestoreStatus(`Preparing browser download for ${file.relative_path || file.path}...`, "warn", true);
  closeDropdowns();
  window.open(`/api/restore/download?internal_token=${encodeURIComponent(internalApiToken)}&path=${encodeURIComponent(file.path)}`, "_blank");
  return;
 }
 if(mode === "destination" && !destValue){
  setRestoreStatus("Choose a destination path first.", "bad");
  return;
 }
 closeDropdowns();
 setRestoreStatus(`Checking restore confidence for ${file.relative_path || file.path}...`, "warn");
 const preflight = await post("/api/restore/preflight", { path:file.path, dest:mode === "destination" ? destValue : "" });
 const warning = preflight.issues?.length ? `${preflight.issues.join("\n")}\nSuggested quarantine: ${preflight.quarantine_path}` : preflight.warning;
 if(warning && !confirm(`${warning}\nContinue restore?`)) return;
 const dest = mode === "destination" ? destValue : "";
 setRestoreStatus(`Starting restore for ${file.relative_path || file.path}...`, "warn");
 const out = await post("/api/restore/start", { path:file.path, dest:dest || null });
 setRestoreStatus(out.error || `Restore started for ${file.relative_path || file.path}.`, out.error ? "bad" : "warn", !out.error);
 await updateFilesPage();
}
async function restoreRehearsal(fileId){
 const file = fileRowsCache.find(row => Number(row.id) === Number(fileId));
 if(!file) return;
 closeDropdowns();
 setRestoreStatus(`Running restore rehearsal for ${file.relative_path || file.path}...`, "warn", true);
 const out = await post("/api/restore/rehearsal", { path:file.path });
 setRestoreStatus(out.error || `Restore rehearsal read ${formatBytes(out.bytes_checked || 0)} in ${out.elapsed_ms || 0} ms.`, out.error ? "bad" : "ok", true);
}
async function restoreCatalogFolder(path){
 return restoreCatalogFolderMode(path, "origin");
}
async function restoreCatalogFolderMode(path, mode, destValue=""){
 const dest = mode === "destination" ? destValue : "";
 if(mode === "destination" && !dest){
  setRestoreStatus("Choose a destination folder first.", "bad");
  return;
 }
 closeDropdowns();
 setRestoreStatus(`Starting folder restore for ${path}...`, "warn");
 const out = await post("/api/restore/start", { path:path, dest:dest || null, folder:true });
 const count = (out.operation_ids || []).length;
 setRestoreStatus(out.error || `Restore started for ${count} files from ${path}.`, out.error ? "bad" : "warn", !out.error);
 await updateFilesPage();
}
function restoreModePrompt(multiple=false){
 const mode = prompt(`${multiple ? "Selected files" : "File"} restore mode: origin, destination, or download`, "origin");
 if(!mode) return "";
 const normalized = mode.toLowerCase().trim();
 if(normalized.startsWith("orig")) return "origin";
 if(normalized.startsWith("dest") || normalized.startsWith("new")) return "destination";
 if(normalized.startsWith("down")) return "download";
 alert("Use origin, destination, or download");
 return "";
}
async function search(){ document.getElementById("results").innerHTML = table(await api("/api/search?q="+encodeURIComponent(document.getElementById("q").value)), ["id","relative_path","size","state","updated_at"]); }
async function restore(){ const out = await post("/api/restore",{path:restorePath.value,dest:restoreDest.value,folder:restoreFolder.checked}); restoreOut.textContent = JSON.stringify(out,null,2); }
function settingsForm(s){
 return `<div class="settings-header"><div class="tabs">
  ${["General","Usenet","Protection","Schedules","Endpoints","Logging","Security","Cloud"].map((name,index)=>`<button class="${index===0?"primary":""}" onclick="showSettingsTab('${name}', this)">${name}</button>`).join("")}
 </div><div class="toolbar-right"><label class="settings-help-toggle"><input id="showSettingsHelp" data-no-dirty="true" type="checkbox" onchange="toggleSettingsHelp(this.checked)"> Show field descriptions</label><button id="saveSettingsButton" class="primary" onclick="saveSettings()" disabled><span class="ui-icon">&#128190;</span>Save Settings</button><button id="resetSettingsButton" onclick="render()" disabled><span class="ui-icon">&#8635;</span>Reset</button></div></div>
 <div id="tabGeneral" class="tab-panel active"><h2 class="section-title"><span class="ui-icon">&#10003;</span>Basic</h2><div class="form-grid">
  <label class="field"><span><span class="ui-icon">&#127912;</span>UI template</span><select id="setUiTheme" onchange="applyTheme(this.value)">${themeOptions(s.ui_theme || "harbor_light")}</select></label>
  <label><input id="setReducedMotion" type="checkbox" ${s.ui_reduced_motion?"checked":""} onchange="document.documentElement.dataset.reducedMotion=this.checked ? 'true' : 'false'"> <span class="ui-icon">&#128065;</span>Reduce motion</label>
  <label class="field"><span><span class="ui-icon">&#128101;</span>Newsgroup</span><input id="setNewsgroup" value="${esc(s.newsgroup)}"></label>
  <label class="field"><span><span class="ui-icon">&#129513;</span>Article size</span><div class="range-field"><input id="setArticleSizeKib" type="range" min="100" max="5120" step="100" value="${esc(bytesToKib(s.article_size || 786432))}" oninput="setArticleSizeLabel.textContent=articleSizeLabel(this.value)"><span id="setArticleSizeLabel">${esc(articleSizeLabel(bytesToKib(s.article_size || 786432)))}</span></div></label>
  <label class="field"><span><span class="ui-icon">&#128225;</span>NNTP threads</span><div class="range-field"><input id="setNntpThreads" type="range" min="1" max="50" step="1" value="${esc(s.nntp_threads || 4)}" oninput="setNntpThreadsLabel.textContent=countLabel(this.value, 'threads')"><span id="setNntpThreadsLabel">${esc(countLabel(s.nntp_threads || 4, "threads"))}</span></div></label>
  <label class="field"><span><span class="ui-icon">&#9201;</span>Post limit per hour</span><div class="range-field"><input id="setHourlyPostLimitGb" type="range" min="0" max="1000" step="10" value="${esc(bytesToGb(s.hourly_post_limit_bytes || 0))}" oninput="setHourlyPostLimitLabel.textContent=postLimitLabel(this.value)"><span id="setHourlyPostLimitLabel">${esc(postLimitLabel(bytesToGb(s.hourly_post_limit_bytes || 0)))}</span></div></label>
  <label class="field"><span><span class="ui-icon">&#128230;</span>Default queue strategy</span><select id="setQueueStrategy"><option value="older-first" ${s.queue_strategy==="older-first"?"selected":""}>Older First</option><option value="larger-first" ${s.queue_strategy==="larger-first"?"selected":""}>Larger First</option><option value="smaller-first" ${s.queue_strategy==="smaller-first"?"selected":""}>Smaller First</option><option value="folder-first" ${s.queue_strategy==="folder-first"?"selected":""}>Folder First</option></select></label>
  <label class="field"><span><span class="ui-icon">&#8635;</span>NNTP retry attempts</span><input id="setRetryAttempts" type="number" min="1" max="10" value="${esc(s.usenet_retry_attempts || 2)}"></label>
  <label class="field"><span><span class="ui-icon">&#9201;</span>NNTP retry backoff seconds</span><input id="setRetryBackoff" type="number" min="0" max="3600" value="${esc(s.usenet_retry_backoff_seconds || 5)}"></label>
  <h2 class="section-title full"><span class="ui-icon">&#9881;</span>Advanced</h2>
  <label class="field full"><span><span class="ui-icon">&#8635;</span>Retry policy JSON</span><textarea id="setProviderRetryPolicy">${esc(JSON.stringify(s.provider_retry_policy || {}, null, 2))}</textarea></label>
  <label class="field"><span><span class="ui-icon">&#9208;</span>Auto-pause auth failures</span><input id="setAutoPauseAuthFailures" type="number" min="0" max="100" value="${esc(s.auto_pause_auth_failures ?? 3)}"></label>
  <label class="field"><span><span class="ui-icon">&#9208;</span>Auto-pause provider failures</span><input id="setAutoPauseProviderFailures" type="number" min="0" max="1000" value="${esc(s.auto_pause_provider_failures ?? 10)}"></label>
 </div></div>
 <div id="tabSchedules" class="tab-panel"><div class="form-grid">
  <label class="field"><span><span class="ui-icon">&#10003;</span>Verify interval</span><div class="range-field"><input id="setVerifyDays" type="range" min="1" max="180" step="1" value="${esc(s.verification_interval_days)}" oninput="setVerifyDaysLabel.textContent=countLabel(this.value, 'days')"><span id="setVerifyDaysLabel">${esc(countLabel(s.verification_interval_days, "days"))}</span></div></label>
  <label class="field"><span><span class="ui-icon">&#10003;</span>Verification task interval seconds</span><input id="setVerifyTaskInterval" type="number" min="1" value="${esc(s.verification_task_interval_seconds || 3600)}"></label>
  <label class="field"><span><span class="ui-icon">&#128196;</span>Files verified per task run</span><input id="setVerifyFilesPerRun" type="number" min="1" value="${esc(s.verification_files_per_run || 1)}"></label>
  <label class="field"><span><span class="ui-icon">&#128193;</span>Catalog scan interval seconds</span><input id="setScanInterval" type="number" min="1" value="${esc(s.scan_interval_seconds || 300)}"></label>
  <label class="field"><span><span class="ui-icon">&#128230;</span>Backup task interval seconds</span><input id="setBackupInterval" type="number" min="1" value="${esc(s.backup_interval_seconds || 300)}"></label>
  <label class="field"><span><span class="ui-icon">&#9729;</span>Cloud backup interval seconds</span><input id="setCloudBackupInterval" type="number" min="1" value="${esc(s.cloud_backup_interval_seconds || 3600)}"></label>
  <label class="field"><span><span class="ui-icon">&#128736;</span>Maintenance interval seconds</span><input id="setMaintenanceInterval" type="number" min="1" value="${esc(s.maintenance_interval_seconds || 86400)}"></label>
  <label class="field"><span><span class="ui-icon">&#128190;</span>Auto-vacuum after compacted chunk rows</span><input id="setAutoVacuumAfterCompactionRows" type="number" min="0" value="${esc(s.auto_vacuum_after_compaction_rows ?? 100000)}"></label>
  <label class="field"><span><span class="ui-icon">&#8635;</span>Restore drill task interval seconds</span><input id="setRestoreDrillTaskInterval" type="number" min="1" value="${esc(s.restore_drill_task_interval_seconds || 86400)}"></label>
  <label class="field"><span><span class="ui-icon">&#128260;</span>Update check interval seconds</span><input id="setUpdateCheckInterval" type="number" min="3600" value="${esc(s.update_check_interval_seconds || 86400)}"></label>
  <label class="field"><span><span class="ui-icon">&#9202;</span>File stability seconds before posting</span><input id="setFileStabilitySeconds" type="number" min="0" max="86400" value="${esc(s.file_stability_seconds ?? 300)}"></label>
 </div></div>
 <div id="tabProtection" class="tab-panel"><h2 class="section-title"><span class="ui-icon">&#10003;</span>Basic</h2><div class="form-grid">
  <label class="field"><span><span class="ui-icon">&#128274;</span>Encryption passphrase env</span><input id="setPassEnv" value="${esc(s.encryption_passphrase_env)}"></label>
  <label><input id="setCompressFiles" type="checkbox" ${s.compress_files?"checked":""}> <span class="ui-icon">&#128451;</span>Compress files</label>
  <label class="field"><span><span class="ui-icon">&#128300;</span>Compression sample bytes</span><input id="setCompressionSampleBytes" type="number" min="0" max="${64 * 1024 * 1024}" value="${esc(s.compression_sample_bytes ?? 2097152)}"></label>
  <label class="field"><span><span class="ui-icon">&#128200;</span>Minimum compression gain percent</span><input id="setCompressionMinGainPercent" type="number" min="0" max="95" value="${esc(s.compression_min_gain_percent ?? 5)}"></label>
  <label><input id="setEncrypt" type="checkbox" ${s.encrypt_bodies?"checked":""}> <span class="ui-icon">&#128274;</span>Encrypt article bodies</label>
  <label><input id="setPar2" type="checkbox" ${s.par2?.enabled?"checked":""}> <span class="ui-icon">&#128737;</span>Generate PAR2 recovery files</label>
  <label class="field"><span><span class="ui-icon">&#9881;</span>PAR2 command</span><div class="range-field"><input id="setPar2Command" value="${esc(s.par2?.command || "par2")}"><button type="button" onclick="detectPar2Command()"><span class="ui-icon">&#128269;</span>Locate</button></div></label>
  <label class="field"><span><span class="ui-icon">&#128737;</span>PAR2 redundancy</span><div class="range-field"><input id="setPar2Redundancy" type="range" min="1" max="50" step="1" value="${esc(s.par2?.redundancy_percent ?? 10)}" oninput="setPar2RedundancyLabel.textContent=this.value + '%'"><span id="setPar2RedundancyLabel">${esc(s.par2?.redundancy_percent ?? 10)}%</span></div></label>
  <h2 class="section-title full"><span class="ui-icon">&#9881;</span>Advanced</h2>
  <label><input id="setCompactChunkMetadata" type="checkbox" ${s.compact_chunk_metadata === false ? "" : "checked"}> <span class="ui-icon">&#128451;</span>Compact stored chunk metadata</label>
  <label><input id="setCompactChunkRows" type="checkbox" ${s.compact_chunk_rows === false ? "" : "checked"}> <span class="ui-icon">&#129513;</span>Compact completed chunk rows</label>
  <label class="field"><span><span class="ui-icon">&#8635;</span>Restore drill interval days</span><input id="setRestoreDrillDays" type="number" min="1" max="3650" value="${esc(s.restore_drill_interval_days || 30)}"></label>
 <label class="field"><span><span class="ui-icon">&#128207;</span>Restore drill sample bytes</span><input id="setRestoreDrillBytes" type="number" min="1" value="${esc(s.restore_drill_sample_bytes || 1048576)}"></label>
  <label class="field"><span><span class="ui-icon">&#9201;</span>Critical verification interval days</span><input id="setCriticalVerificationDays" type="number" min="1" max="180" value="${esc(s.critical_verification_interval_days || 30)}"></label>
  <label class="field full"><span><span class="ui-icon">&#128278;</span>Retention policy patterns. Format: label:glob:days, for example critical:*.iso:30</span><textarea id="setRetentionPolicyPatterns">${esc((s.retention_policy_patterns || []).join("\n"))}</textarea></label>
  <label><input id="setRestoreSandboxEnabled" type="checkbox" ${s.restore_sandbox_enabled?"checked":""}> <span class="ui-icon">&#128737;</span>Restore to sandbox before replacing origin</label>
  <label class="field full"><span><span class="ui-icon">&#128193;</span>Restore sandbox path</span><input id="setRestoreSandboxPath" value="${esc(s.restore_sandbox_path || "")}" placeholder="optional; defaults beside origin"></label>
 </div></div>
 <div id="tabEndpoints" class="tab-panel"><div class="form-grid">
 <label class="field full"><span><span class="ui-icon">&#128193;</span>Endpoints, one path per line</span><textarea id="setEndpoints">${esc((s.endpoints || []).join("\n"))}</textarea></label>
  <label class="field full"><span><span class="ui-icon">&#128683;</span>Auto-queue exclude patterns, one per line. Examples: MP4, .mp4, *.sample, regex:\\.partial$, /Season \\d+/</span><textarea id="setAutoQueueExcludePatterns">${esc((s.auto_queue_exclude_patterns || []).join("\n"))}</textarea></label>
  <label class="field full"><span><span class="ui-icon">&#9208;</span>Queue pause patterns, one per line. Matching files stay cataloged but are not queued automatically.</span><textarea id="setQueuePausePatterns">${esc((s.queue_pause_patterns || []).join("\n"))}</textarea></label>
 </div></div>
 <div id="tabUsenet" class="tab-panel"><div class="form-grid">
  <div class="toolbar"><button onclick="addHost()"><span class="ui-icon">&#10133;</span>Add Host</button></div>
  <div class="field full"><span><span class="ui-icon">&#128225;</span>Usenet hosts</span><div id="hostList" class="host-list">${hostRows(s.usenet_hosts || [])}</div></div>
 </div></div>
 <div id="tabLogging" class="tab-panel"><div class="form-grid">
  <label class="field"><span><span class="ui-icon">&#128221;</span>Local log retention days</span><input id="setLogRetentionDays" type="number" min="1" max="3650" value="${esc(s.log_retention_days || 30)}"></label>
  <label class="field"><span><span class="ui-icon">&#128269;</span>Verbose log retention days</span><input id="setVerboseLogRetentionDays" type="number" min="1" max="3650" value="${esc(s.verbose_log_retention_days || 7)}"></label>
  <label><input id="setLogWebAccess" type="checkbox" ${s.log_web_access?"checked":""}> <span class="ui-icon">&#128221;</span>Log web access requests</label>
  <label><input id="setLogChunkEvents" type="checkbox" ${s.log_chunk_events?"checked":""}> <span class="ui-icon">&#129513;</span>Log successful per-chunk events</label>
  <div class="toolbar"><button onclick="addLogDestination()"><span class="ui-icon">&#10133;</span>Add Log Destination</button></div>
 <div class="field full"><span><span class="ui-icon">&#128225;</span>Log aggregation destinations</span><div id="logDestinationList" class="host-list">${logDestinationRows(s.log_destinations || [])}</div></div>
 </div></div>
 <div id="tabSecurity" class="tab-panel"><h2 class="section-title"><span class="ui-icon">&#128737;</span>Basic</h2><div class="form-grid">
  <div class="chart-card full"><h3><span class="ui-icon">&#128273;</span>External API</h3><p class="muted">Use <code>/external-api/status</code>, <code>/external-api/files</code>, <code>/external-api/queue</code>, and <code>/external-api/tasks</code> with <code>X-API-Key</code> or <code>Authorization: Bearer ...</code>. Stored keys: ${Number(s.external_api_key_count || 0)}.</p></div>
  <div class="chart-card full"><h3><span class="ui-icon">&#128274;</span>Web UI Auth</h3><p class="muted">Optional Basic Auth protects browser pages and internal AJAX endpoints. Leave the password blank to keep the current value.</p></div>
  <label class="field"><span><span class="ui-icon">&#128100;</span>Web UI username</span><input id="setWebUiUsername" value="${esc(s.web_ui_username || "admin")}"></label>
  <label class="field"><span><span class="ui-icon">&#128274;</span>Web UI role</span><select id="setWebUiRole"><option value="admin" ${s.web_ui_role==="admin"?"selected":""}>Admin</option><option value="operator" ${s.web_ui_role==="operator"?"selected":""}>Operator</option><option value="read_only" ${s.web_ui_role==="read_only"?"selected":""}>Read Only</option></select></label>
  <label class="field"><span><span class="ui-icon">&#128273;</span>Web UI password</span><input id="setWebUiPassword" type="password" value="" autocomplete="new-password" placeholder="${s.has_web_ui_password ? "stored; leave blank to keep" : "optional"}"></label>
  <label><input id="clearWebUiPassword" type="checkbox"> <span class="ui-icon">&#128465;</span>Disable Web UI password</label>
  <label><input id="setReadOnlyMode" type="checkbox" ${s.read_only_mode?"checked":""}> <span class="ui-icon">&#128274;</span>Read-only mode</label>
  ${s.read_only_mode ? `<div class="chart-card full"><h3><span class="ui-icon">&#128274;</span>Read-only safety mode is on</h3><p class="muted">Most write actions are blocked until read-only mode is disabled with this dedicated control.</p><div class="toolbar"><button class="warn" onclick="disableReadOnlyMode()"><span class="ui-icon">&#128275;</span>Disable Read-only Mode</button></div></div>` : ""}
  <label class="field"><span><span class="ui-icon">&#128273;</span>TOTP secret env</span><input id="setWebUiTotpSecretEnv" value="${esc(s.web_ui_totp_secret_env || "BACKUPRR_TOTP_SECRET")}"></label>
  <label class="field full"><span><span class="ui-icon">&#128274;</span>Config secret key environment variable</span><input id="setConfigSecretKeyEnv" value="${esc(s.config_secret_key_env || "BACKUPRR_CONFIG_SECRET")}"></label>
  <label><input id="setAuditMode" type="checkbox" ${s.audit_mode?"checked":""}> <span class="ui-icon">&#128221;</span>Enable signed audit events</label>
  <label class="field"><span><span class="ui-icon">&#128273;</span>Audit secret env</span><input id="setAuditSecretKeyEnv" value="${esc(s.audit_secret_key_env || "BACKUPRR_AUDIT_SECRET")}"></label>
  <label class="field"><span><span class="ui-icon">&#9201;</span>Internal API rate limit per minute</span><input id="setApiRateLimit" type="number" min="0" max="10000" value="${esc(s.api_rate_limit_per_minute ?? 120)}"></label>
  <label class="field"><span><span class="ui-icon">&#9201;</span>External API rate limit per minute</span><input id="setExternalApiRateLimit" type="number" min="0" max="10000" value="${esc(s.external_api_rate_limit_per_minute ?? 60)}"></label>
  <h2 class="section-title full"><span class="ui-icon">&#9881;</span>Advanced</h2>
  <label><input id="setManifestExportEnabled" type="checkbox" ${s.manifest_export_enabled === false ? "" : "checked"}> <span class="ui-icon">&#128230;</span>Enable manifest export</label>
  <label><input id="setManifestExportEncrypt" type="checkbox" ${s.manifest_export_encrypt?"checked":""}> <span class="ui-icon">&#128274;</span>Encrypt manifest export</label>
  <label class="field"><span><span class="ui-icon">&#128273;</span>Manifest export secret env</span><input id="setManifestExportPassphraseEnv" value="${esc(s.manifest_export_passphrase_env || "BACKUPRR_MANIFEST_EXPORT_SECRET")}"></label>
  <label class="field"><span><span class="ui-icon">&#9201;</span>Manifest export interval seconds</span><input id="setManifestExportInterval" type="number" min="3600" value="${esc(s.manifest_export_interval_seconds || 86400)}"></label>
  <label class="field full"><span><span class="ui-icon">&#128273;</span>Replace external API keys, one per line. Leave blank to keep existing keys.</span><textarea id="setExternalApiKeys" placeholder="Paste Home Assistant or automation API keys here"></textarea></label>
 <label class="field full"><span><span class="ui-icon">&#128273;</span>External API key scopes JSON. Keys are full API keys, values are scopes: read, backup, scan, verify, restore, admin.</span><textarea id="setExternalApiKeyScopes">${esc(JSON.stringify(s.external_api_key_scopes || {}, null, 2))}</textarea></label>
 <label><input id="clearExternalApiKeys" type="checkbox"> <span class="ui-icon">&#128465;</span>Clear all stored external API keys</label>
  <div class="chart-card full"><h3><span class="ui-icon">&#128260;</span>Update checks</h3><p class="muted">Backuprr checks GitHub releases on the configured schedule and stores the latest result locally.</p><div class="toolbar"><button onclick="post('/api/update-check/run').then(out=>settingsOut.textContent=JSON.stringify(out,null,2))"><span class="ui-icon">&#128260;</span>Check Now</button></div></div>
  <label><input id="setUpdateCheckEnabled" type="checkbox" ${s.update_check_enabled === false ? "" : "checked"}> <span class="ui-icon">&#128260;</span>Enable GitHub update checks</label>
  <label class="field"><span><span class="ui-icon">&#128279;</span>GitHub repository</span><input id="setUpdateGithubRepo" value="${esc(s.update_github_repo || "kelau/Backuprr")}" placeholder="owner/repo"></label>
  <label class="field"><span><span class="ui-icon">&#128273;</span>GitHub token env</span><input id="setUpdateGithubTokenEnv" value="${esc(s.update_github_token_env || "GITHUB_TOKEN")}" placeholder="GITHUB_TOKEN"></label>
  <label class="field"><span><span class="ui-icon">&#9201;</span>Update check timeout seconds</span><input id="setUpdateCheckTimeout" type="number" min="1" max="60" value="${esc(s.update_check_timeout_seconds || 10)}"></label>
  <div class="chart-card full"><h3><span class="ui-icon">&#128230;</span>Settings profiles</h3><p class="muted">Export a redacted settings profile or import one to quickly clone safe defaults between installs.</p><div class="toolbar"><button onclick="downloadSettingsProfile()"><span class="ui-icon">&#8681;</span>Export profile</button><button onclick="document.getElementById('settingsProfileImport').click()"><span class="ui-icon">&#8679;</span>Import profile</button><input id="settingsProfileImport" type="file" accept="application/json" class="hidden" onchange="importSettingsProfile(this.files[0])"></div></div>
 </div></div>
 <div id="tabCloud" class="tab-panel"><div class="form-grid">
  <div class="toolbar"><button onclick="addCloudTarget()"><span class="ui-icon">&#10133;</span>Add Cloud Target</button><button onclick="post('/api/cloud-backup').then(out=>settingsOut.textContent=JSON.stringify(out,null,2))"><span class="ui-icon">&#9729;</span>Backup Config/DB Now</button></div>
  <div class="field full"><span><span class="ui-icon">&#9729;</span>Cloud backup targets</span><div id="cloudList" class="host-list">${cloudRows(s.cloud_backups || [])}</div></div>
 </div></div>
 <pre id="settingsOut"></pre>`;
}
function showSettingsTab(name, button){
 document.querySelectorAll(".tab-panel").forEach(panel => panel.classList.remove("active"));
 document.getElementById("tab"+name).classList.add("active");
 document.querySelectorAll(".tabs button").forEach(tab => tab.classList.remove("primary"));
 button.classList.add("primary");
}
const settingsHelpDescriptions = {
 "UI template":"Changes the visual style of the Web UI only. Pick the template that is easiest for you to scan during long-running backup and verification work.",
 "Reduce motion":"Disables animations and transitions. Enable this if motion is distracting, if you use remote desktop, or if you prefer the most stable-looking UI.",
 "Newsgroup":"The Usenet group where backup articles are posted. Use the private or agreed group for your archive; changing this affects future posts and lookups.",
 "Article size":"Target size for each posted article chunk. Larger values reduce chunk count and database metadata, but the provider must accept the size; use the provider article-size test and stay below the largest passing value.",
 "NNTP threads":"Maximum parallel NNTP workers used for posting, verification, and restore reads. Increase while throughput rises; reduce if the provider throttles, authentication errors increase, or the server/network feels saturated.",
 "Post limit per hour":"Caps how much data Backuprr may post in a rolling hour. Use this to avoid provider rate limits, noisy WAN usage, or filling monthly quotas; 0 means no cap.",
 "Default queue strategy":"Controls the order automatically queued files are posted. Use Older First for archival safety, Smaller First to clear many small files quickly, Larger First for bulk throughput testing, or Folder First to keep related paths together.",
 "NNTP retry attempts":"Number of retry attempts after a transient NNTP failure. Raise slightly for flaky providers; keep modest so genuinely bad credentials or blocked sockets surface quickly.",
 "NNTP retry backoff seconds":"Delay between NNTP retries. Increase when provider rate limits or temporary network failures occur; lower values make test runs recover faster.",
 "Retry policy JSON":"Advanced per-provider retry overrides. Leave empty unless you need host-specific behavior after observing logs.",
 "Auto-pause auth failures":"Automatically pauses workers after repeated authentication failures. Keep enabled to avoid hammering a provider with bad credentials; use 0 only during deliberate auth testing.",
 "Auto-pause provider failures":"Automatically pauses workers after repeated provider or network failures. Increase for unreliable links; reduce if you want failures to stop workers quickly.",
 "Verify interval":"How often each backed-up file becomes due for chunk verification. Shorter intervals give stronger confidence but more provider reads; longer intervals reduce traffic for stable archives.",
 "Verification task interval seconds":"How often the verification worker wakes up to look for due files. Lower values make manual/test changes visible faster; higher values are quieter on large libraries.",
 "Files verified per task run":"How many due files are verified each worker run. Increase for catch-up runs; keep low to spread verification over time for multi-TB archives.",
 "Catalog scan interval seconds":"How often Backuprr scans endpoint folders. Lower values find new files quickly; higher values reduce disk activity on very large libraries.",
 "Backup task interval seconds":"How often the backup worker wakes up and processes queued work. Lower values react faster; higher values batch work and reduce churn.",
 "Cloud backup interval seconds":"How often Backuprr checks whether config/database backups should be copied to cloud targets. Use shorter intervals while actively changing settings.",
 "Maintenance interval seconds":"How often cleanup, compaction, retention, and database maintenance are considered. Daily is usually enough unless you are doing heavy test posting.",
 "Auto-vacuum after compacted chunk rows":"Runs database vacuum after enough chunk rows are compacted. Higher values vacuum less often; lower values return disk space sooner at the cost of more maintenance work.",
 "Restore drill task interval seconds":"How often the restore-drill scheduler wakes up. Lower values make test drills happen sooner; production systems can keep this infrequent.",
 "Update check interval seconds":"How often Backuprr checks GitHub for a newer version. Daily is a good balance between awareness and network noise.",
 "File stability seconds before posting":"A file must remain unchanged for this long before it can be posted. Increase for large files still being copied; decrease only for controlled test folders.",
 "Encryption passphrase env":"Environment variable containing the encryption passphrase. Use a strong secret managed outside the config file; changing it affects future encrypted posts.",
 "Compress files":"Compresses eligible files before posting when sampling predicts a useful gain. Enable for documents/raw files; many media archives are already compressed and may be skipped automatically.",
 "Compression sample bytes":"Bytes sampled to estimate compression benefit. Larger samples improve decisions on mixed files but add pre-post work.",
 "Minimum compression gain percent":"Minimum expected size reduction before compression is used. Raise to avoid spending CPU on small savings; lower if storage/post volume is more important than CPU.",
 "Encrypt article bodies":"Encrypts posted article payloads with the configured passphrase. Enable for privacy; make sure the passphrase is backed up because restore depends on it.",
 "Generate PAR2 recovery files":"Adds recovery data to tolerate some missing Usenet articles. Enable for important archives once a PAR2 executable is installed and tested.",
 "PAR2 command":"Path or command name for the PAR2-compatible executable. Use Locate to auto-fill; prefer command-line tools such as par2/par2cmdline/MultiPar par2j over GUI-only tools.",
 "PAR2 redundancy":"Recovery data percentage. Higher values survive more missing chunks but post more data; 5-10% is typical, with 15-30% for high-value files.",
 "Compact stored chunk metadata":"Stores completed chunk metadata more compactly. Keep enabled for large libraries because millions of chunks otherwise grow the database quickly.",
 "Compact completed chunk rows":"Removes redundant per-chunk rows after safe manifest compaction. Keep enabled for multi-TB scale unless actively debugging chunk-level posting.",
 "Restore drill interval days":"How often files should be sampled by restore drills. Shorter intervals improve confidence; longer intervals reduce provider reads.",
 "Restore drill sample bytes":"Amount of data read during each restore drill. Larger samples provide stronger proof but use more read bandwidth.",
 "Critical verification interval days":"Verification interval for files matched by critical retention patterns. Use shorter intervals for irreplaceable files.",
 "Retention policy patterns. Format: label:glob:days, for example critical:*.iso:30":"Per-pattern verification policies. Add one line per class of file when some paths or extensions need more frequent checks than the global interval.",
 "Restore to sandbox before replacing origin":"Restores into a sandbox before replacing original files. Enable this for safer restores, especially when restoring over existing files.",
 "Restore sandbox path":"Optional folder for restore sandbox output. Leave empty to place the sandbox near the original file, or set a fast/safe scratch disk.",
 "Endpoints, one path per line":"Root folders Backuprr catalogs recursively. Add only stable library roots; each endpoint is scanned and monitored for changes.",
 "Auto-queue exclude patterns, one per line. Examples: MP4, .mp4, *.sample, regex:\\.partial$, /Season \\d+/":"Catalogs matching files but prevents automatic queueing. Use for temporary, sample, cache, or file types you do not want posted.",
 "Queue pause patterns, one per line. Matching files stay cataloged but are not queued automatically.":"Temporarily holds matching files out of the automatic queue without excluding them from the catalog.",
 "Usenet hosts":"Read and post providers used for backup, verification, and restore. Add separate entries for read and post endpoints when the provider uses different hosts.",
 "Local log retention days":"How long normal local log rows are kept. Longer retention helps troubleshooting but grows the database.",
 "Verbose log retention days":"How long debug/verbose rows are kept. Keep short in production because verbose logs can be high volume.",
 "Log web access requests":"Records Web UI access events. Enable when auditing access; disable to keep logs quieter.",
 "Log successful per-chunk events":"Records successful chunk-level events. Use only for diagnostics because successful posts can create many log rows.",
 "Log aggregation destinations":"External log systems that receive Backuprr events. Use one if you already monitor your home lab with Loki, Seq, Graylog, Elastic, Logstash, or Splunk.",
 "Web UI username":"Username for browser Basic Auth. Use a non-default name if the app is reachable beyond localhost.",
 "Web UI role":"Permission level for the Web UI account. Use Read Only for dashboards, Operator for routine work, and Admin for settings/security changes.",
 "Web UI password":"Password for browser Basic Auth. Leave blank to keep the existing value; set one before exposing the app to a LAN or reverse proxy.",
 "Disable Web UI password":"Removes browser Basic Auth. Use only for local-only testing or when another trusted auth layer protects the app.",
 "Read-only mode":"Blocks write actions such as posting, restore-to-origin, queue changes, and most settings writes. Use during audits or incident response.",
 "TOTP secret env":"Environment variable containing a TOTP secret for admin step-up. Enable when the Web UI is reachable by other users or systems.",
 "Config secret key environment variable":"Environment variable used to encrypt selected secrets in the config file. Set it before storing provider/API credentials long term.",
 "Enable signed audit events":"Signs audit events so important actions can be checked later. Enable when you care about change traceability.",
 "Audit secret env":"Environment variable containing the audit signing secret. Keep it stable and backed up if signed audit history matters.",
 "Internal API rate limit per minute":"Rate limit for browser AJAX calls. Raise only if the UI reports rate limits during normal use.",
 "External API rate limit per minute":"Rate limit for API-key integrations. Tune based on Home Assistant or automation polling frequency.",
 "Enable manifest export":"Allows exporting backup manifests for disaster recovery. Keep enabled so catalog recovery has a second path.",
 "Encrypt manifest export":"Encrypts exported manifests. Enable when exports leave the server or land in shared cloud storage.",
 "Manifest export secret env":"Environment variable containing the manifest export encryption secret. Back it up with your disaster recovery material.",
 "Manifest export interval seconds":"How often manifest exports are considered. Shorter intervals capture catalog changes faster.",
 "Replace external API keys, one per line. Leave blank to keep existing keys.":"Replaces API keys used by automations. Leave blank unless rotating or adding keys.",
 "External API key scopes JSON. Keys are full API keys, values are scopes: read, backup, scan, verify, restore, admin.":"Restricts each external key to specific capabilities. Give automations the smallest scope they need.",
 "Clear all stored external API keys":"Removes every external API key. Use when rotating integrations or after a suspected key leak.",
 "Enable GitHub update checks":"Checks GitHub releases/tags for newer Backuprr versions. Disable only on fully offline installs.",
 "GitHub repository":"Repository used by the update checker. Keep owner/repo pointed at the upstream or your fork.",
 "GitHub token env":"Environment variable containing a GitHub token. Useful for private forks or avoiding unauthenticated rate limits.",
 "Update check timeout seconds":"Network timeout for GitHub checks. Increase on slow links; keep low so a stalled check does not linger.",
 "Cloud backup targets":"Destinations for periodic config/database backups. Add at least one target outside the app directory for disaster recovery.",
 "Name":"Friendly display name. Choose something that identifies the provider, purpose, or destination in logs.",
 "Mode":"Selects whether this entry is used for reading or posting. Use separate entries when providers expose different read/post hosts.",
 "Priority":"Lower numbers are preferred first. Give your fastest or most reliable host the lowest priority.",
 "Server":"NNTP server hostname from the provider.",
 "Port":"NNTP server port. Common values are 563 for implicit TLS, 119 for plain NNTP, and sometimes 119/443/563 for STARTTLS depending on provider.",
 "TLS mode":"Connection security mode. Prefer implicit TLS when available, STARTTLS when required, and plain only on trusted networks/testing.",
 "Username":"Provider username for authentication. Use the provider account created for this service.",
 "Password":"Provider password. Leave blank to keep a stored password when editing an existing host.",
 "Enabled":"Turns this item on or off without deleting it. Disable while testing or temporarily removing a destination.",
 "Platform":"External logging platform type. Pick the system you already run so logs land in the expected format.",
 "URL":"Endpoint URL for the external service. Use the platform-specific ingest URL, not the human dashboard URL.",
 "Minimum level":"Lowest event severity forwarded. Use info for normal operations, warning/error for quieter production forwarding, or debug/verbose while diagnosing.",
 "API token":"Optional API token for the external service. Leave blank to keep a stored token where supported.",
 "Timeout seconds":"HTTP timeout for the integration. Increase for slow remote endpoints; keep short for local collectors.",
 "Provider":"Cloud/sync target type. Pick local/sync folder for OneDrive/Google Drive clients mounted on the server, or command for tools like rclone.",
 "Target path":"Folder where config/database backup archives are written. Put it on synced or remote-backed storage.",
 "Command":"Command template for custom backup/export tools. Use placeholders shown by the target feature, such as {archive}, when supported."
};
const settingsHelpDefaults = {
 "UI template":"harbor_light",
 "Reduce motion":"Off",
 "Newsgroup":"alt.binaries.backup",
 "Article size":"768 KiB",
 "NNTP threads":"4",
 "Post limit per hour":"0 GB, unlimited",
 "Default queue strategy":"Older First",
 "NNTP retry attempts":"2",
 "NNTP retry backoff seconds":"5",
 "Verify interval":"90 days",
 "Verification task interval seconds":"3600",
 "Files verified per task run":"1",
 "Catalog scan interval seconds":"300",
 "Backup task interval seconds":"300",
 "Cloud backup interval seconds":"3600",
 "Maintenance interval seconds":"86400",
 "Restore drill task interval seconds":"86400",
 "Update check interval seconds":"86400",
 "File stability seconds before posting":"300",
 "Compression sample bytes":"2097152",
 "Minimum compression gain percent":"5",
 "PAR2 command":"par2",
 "PAR2 redundancy":"10%",
 "Restore drill interval days":"30",
 "Restore drill sample bytes":"1048576",
 "Critical verification interval days":"30",
 "Local log retention days":"30",
 "Verbose log retention days":"7",
 "Web UI username":"admin",
 "Web UI role":"Admin",
 "TOTP secret env":"BACKUPRR_TOTP_SECRET",
 "Config secret key environment variable":"BACKUPRR_CONFIG_SECRET",
 "Internal API rate limit per minute":"120",
 "External API rate limit per minute":"60",
 "Manifest export interval seconds":"86400",
 "GitHub repository":"kelau/Backuprr",
 "GitHub token env":"GITHUB_TOKEN",
 "Update check timeout seconds":"10",
 "Port":"563 for implicit TLS",
 "TLS mode":"implicit",
 "Minimum level":"info",
 "Timeout seconds":"5",
 "Provider":"local/sync folder"
};
function settingsLabelTitle(label){
 const source = label.querySelector(":scope > span") || label;
 const clone = source.cloneNode(true);
 clone.querySelectorAll(".ui-icon,input,select,textarea,button,small,.settings-help").forEach(node => node.remove());
 return clone.textContent.replace(/\s+/g, " ").trim();
}
function settingsControlDetails(label, title){
 const control = label.querySelector("input:not([type='hidden']), select, textarea");
 if(!control) return "";
 const parts = [];
 if(control.tagName === "SELECT"){
  const options = Array.from(control.options || []).map(option => option.textContent.trim()).filter(Boolean);
  if(options.length) parts.push(`Possible settings: ${options.join(", ")}.`);
 } else if(control.type === "checkbox"){
  parts.push("Possible settings: On or Off.");
 } else if(control.tagName === "TEXTAREA"){
  parts.push("Possible settings: one or more text lines, JSON, or an empty value depending on the field.");
 } else if(control.type === "range" || control.type === "number"){
  const range = [];
  if(control.min !== "") range.push(`min ${control.min}`);
  if(control.max !== "") range.push(`max ${control.max}`);
  if(control.step && control.step !== "any") range.push(`step ${control.step}`);
  if(range.length) parts.push(`Possible settings: numeric value (${range.join(", ")}).`);
 } else {
  parts.push("Possible settings: text value, path, hostname, command, or environment variable name as appropriate for the field.");
 }
 if(settingsHelpDefaults[title]) parts.push(`Default: ${settingsHelpDefaults[title]}.`);
 if(control.placeholder) parts.push(`Example: ${control.placeholder}.`);
 return parts.join(" ");
}
function settingHelpFor(label, labelElement){
 const base = settingsHelpDescriptions[label] || `Controls ${label || "this setting"}. Start with the default, then adjust only when logs, provider limits, or your workflow point to a better value.`;
 const details = settingsControlDetails(labelElement, label);
 return [base, details].filter(Boolean).join(" ");
}
function addSettingsHelpText(root=document.getElementById("content")){
 if(!root) return;
 root.querySelectorAll("label").forEach(label => {
  if(label.querySelector(".settings-help")) return;
  const title = settingsLabelTitle(label);
  if(!title) return;
  label.insertAdjacentHTML("beforeend", `<small class="settings-help">${esc(settingHelpFor(title, label))}</small>`);
 });
}
function toggleSettingsHelp(show){
 localStorage.setItem("backuprr-settings-help", show ? "1" : "0");
 document.getElementById("content")?.classList.toggle("settings-show-help", Boolean(show));
 const checkbox = document.getElementById("showSettingsHelp");
 if(checkbox) checkbox.checked = Boolean(show);
}
function applySettingsHelpPreference(){
 toggleSettingsHelp(localStorage.getItem("backuprr-settings-help") === "1");
}
function setSettingsDirty(value){
 settingsDirty = Boolean(value);
 const save = document.getElementById("saveSettingsButton");
 const reset = document.getElementById("resetSettingsButton");
 if(save) save.disabled = !settingsDirty;
 if(reset) reset.disabled = !settingsDirty;
}
function initSettingsDirtyTracking(){
 setSettingsDirty(false);
 const content = document.getElementById("content");
 if(!content) return;
 content.querySelectorAll("input, textarea, select").forEach(input => {
  if(input.dataset.noDirty === "true") return;
  input.addEventListener("input", () => setSettingsDirty(true));
  input.addEventListener("change", () => setSettingsDirty(true));
 });
}
function hostRows(hosts){
 return hosts.map((host, index) => hostRow(host, index)).join("") || hostRow({ name:"", mode:"read", host:"", port:563, tls:"implicit", username:"", password:"", priority:100 }, 0);
}
function hostRow(host, index){
 return `<div class="host-row" data-host-index="${index}">
  <div class="toolbar"><h3><span class="ui-icon">&#128225;</span>Host ${index + 1}</h3>${authPill(host.auth_state || ((host.username && host.has_password) ? "configured" : (host.username || host.has_password ? "incomplete" : "missing")))}<button class="danger" onclick="removeHost(this)"><span class="ui-icon">&#128465;</span>Remove</button></div>
  <div class="host-grid">
   <label class="field"><span><span class="ui-icon">&#128278;</span>Name</span><input class="hostName" value="${esc(host.name)}" placeholder="eweka-read"></label>
   <label class="field"><span><span class="ui-icon">&#8644;</span>Mode</span><select class="hostMode"><option value="read" ${host.mode==="read"?"selected":""}>read</option><option value="post" ${host.mode==="post"?"selected":""}>post</option></select></label>
   <label class="field"><span><span class="ui-icon">&#8593;</span>Priority</span><input class="hostPriority" type="number" min="0" max="10000" value="${esc(host.priority ?? 100)}"></label>
   <label class="field"><span><span class="ui-icon">&#127760;</span>Server</span><input class="hostServer" value="${esc(host.host)}" placeholder="news.example.com"></label>
   <label class="field"><span><span class="ui-icon">&#128279;</span>Port</span><input class="hostPort" type="number" min="1" value="${esc(host.port || 563)}"></label>
   <label class="field"><span><span class="ui-icon">&#128274;</span>TLS mode</span><select class="hostTls"><option value="implicit" ${host.tls==="implicit"?"selected":""}>implicit</option><option value="starttls" ${host.tls==="starttls"?"selected":""}>starttls</option><option value="plain" ${host.tls==="plain"?"selected":""}>plain</option></select></label>
   <label class="field"><span><span class="ui-icon">&#128100;</span>Username</span><input class="hostUsername" value="${esc(host.username || "")}" autocomplete="off"></label>
   <label class="field"><span><span class="ui-icon">&#128273;</span>Password</span><input class="hostPassword" type="password" value="${esc(host.password || "")}" autocomplete="new-password" placeholder="${host.has_password ? "stored; leave blank to keep" : "enter password"}"></label>
  </div>
 </div>`;
}
function cloudRows(targets){
 return targets.map((target, index) => cloudRow(target, index)).join("") || cloudRow({ name:"", provider:"local", target:"", command:"", enabled:true }, 0);
}
function logDestinationRows(destinations){
 return destinations.map((destination, index) => logDestinationRow(destination, index)).join("") || logDestinationRow({ name:"", platform:"loki", url:"", api_key:"", username:"", password:"", min_level:"info", timeout_seconds:5, enabled:false }, 0);
}
function logDestinationRow(destination, index){
 return `<div class="log-destination-row" data-log-destination-index="${index}">
  <div class="toolbar"><h3><span class="ui-icon">&#128225;</span>Log destination ${index + 1}</h3><button class="danger" onclick="removeLogDestination(this)"><span class="ui-icon">&#128465;</span>Remove</button></div>
  <div class="host-grid">
   <label><input class="logDestinationEnabled" type="checkbox" ${destination.enabled ? "checked" : ""}> Enabled</label>
   <label class="field"><span><span class="ui-icon">&#128278;</span>Name</span><input class="logDestinationName" value="${esc(destination.name || "")}" placeholder="home-loki"></label>
   <label class="field"><span><span class="ui-icon">&#128225;</span>Platform</span><select class="logDestinationPlatform"><option value="loki" ${destination.platform==="loki"?"selected":""}>Grafana Loki</option><option value="seq" ${destination.platform==="seq"?"selected":""}>Seq</option><option value="graylog" ${destination.platform==="graylog"?"selected":""}>Graylog GELF HTTP</option><option value="elastic" ${destination.platform==="elastic"?"selected":""}>Elastic HTTP</option><option value="logstash" ${destination.platform==="logstash"?"selected":""}>Logstash HTTP</option><option value="splunk_hec" ${destination.platform==="splunk_hec"?"selected":""}>Splunk HEC</option></select></label>
   <label class="field"><span><span class="ui-icon">&#127760;</span>URL</span><input class="logDestinationUrl" value="${esc(destination.url || "")}" placeholder="http://server:3100/loki/api/v1/push"></label>
   <label class="field"><span><span class="ui-icon">&#9888;</span>Minimum level</span><select class="logDestinationMinLevel">${["error","warning","info","debug","verbose"].map(level=>`<option value="${level}" ${destination.min_level===level?"selected":""}>${level}</option>`).join("")}</select></label>
   <label class="field"><span><span class="ui-icon">&#128273;</span>API token</span><input class="logDestinationApiKey" type="password" value="${esc(destination.api_key || "")}" autocomplete="new-password" placeholder="${destination.has_api_key ? "stored; leave blank to keep" : "optional"}"></label>
   <label class="field"><span><span class="ui-icon">&#128100;</span>Username</span><input class="logDestinationUsername" value="${esc(destination.username || "")}" autocomplete="off"></label>
   <label class="field"><span><span class="ui-icon">&#128273;</span>Password</span><input class="logDestinationPassword" type="password" value="${esc(destination.password || "")}" autocomplete="new-password" placeholder="${destination.has_password ? "stored; leave blank to keep" : "optional"}"></label>
   <label class="field"><span><span class="ui-icon">&#9201;</span>Timeout seconds</span><input class="logDestinationTimeout" type="number" min="1" max="60" value="${esc(destination.timeout_seconds || 5)}"></label>
  </div>
 </div>`;
}
function cloudRow(target, index){
 return `<div class="cloud-row" data-cloud-index="${index}">
  <div class="toolbar"><h3><span class="ui-icon">&#9729;</span>Cloud target ${index + 1}</h3><button class="danger" onclick="removeCloudTarget(this)"><span class="ui-icon">&#128465;</span>Remove</button></div>
  <div class="host-grid">
   <label><input class="cloudEnabled" type="checkbox" ${target.enabled === false ? "" : "checked"}> Enabled</label>
   <label class="field"><span><span class="ui-icon">&#128278;</span>Name</span><input class="cloudName" value="${esc(target.name || "")}" placeholder="OneDrive sync"></label>
   <label class="field"><span><span class="ui-icon">&#9729;</span>Provider</span><select class="cloudProvider"><option value="local" ${target.provider==="local"?"selected":""}>local/sync folder</option><option value="onedrive" ${target.provider==="onedrive"?"selected":""}>OneDrive folder</option><option value="google_drive" ${target.provider==="google_drive"?"selected":""}>Google Drive folder</option><option value="command" ${target.provider==="command"?"selected":""}>command</option></select></label>
   <label class="field"><span><span class="ui-icon">&#128193;</span>Target path</span><input class="cloudTarget" value="${esc(target.target || "")}" placeholder="/mnt/cloud/backuprr"></label>
   <label class="field full"><span><span class="ui-icon">&#9881;</span>Command</span><input class="cloudCommand" value="${esc(target.command || "")}" placeholder="rclone copy {archive} remote:backuprr"></label>
  </div>
 </div>`;
}
function addHost(){
 const list = document.getElementById("hostList");
 const index = list.querySelectorAll(".host-row").length;
 list.insertAdjacentHTML("beforeend", hostRow({ name:"", mode:"read", host:"", port:563, tls:"implicit", username:"", password:"", priority:100 }, index));
 renumberHosts();
 addSettingsHelpText(list);
 applySettingsHelpPreference();
 initSettingsDirtyTracking();
 setSettingsDirty(true);
}
function addCloudTarget(){
 const list = document.getElementById("cloudList");
 const index = list.querySelectorAll(".cloud-row").length;
 list.insertAdjacentHTML("beforeend", cloudRow({ name:"", provider:"local", target:"", command:"", enabled:true }, index));
 renumberCloudTargets();
 addSettingsHelpText(list);
 applySettingsHelpPreference();
 initSettingsDirtyTracking();
 setSettingsDirty(true);
}
function addLogDestination(){
 const list = document.getElementById("logDestinationList");
 const index = list.querySelectorAll(".log-destination-row").length;
 list.insertAdjacentHTML("beforeend", logDestinationRow({ name:"", platform:"loki", url:"", api_key:"", username:"", password:"", min_level:"info", timeout_seconds:5, enabled:false }, index));
 renumberLogDestinations();
 addSettingsHelpText(list);
 applySettingsHelpPreference();
 initSettingsDirtyTracking();
 setSettingsDirty(true);
}
function removeLogDestination(button){
 button.closest(".log-destination-row").remove();
 if(!document.querySelector(".log-destination-row")) addLogDestination();
 renumberLogDestinations();
 setSettingsDirty(true);
}
function renumberLogDestinations(){
 document.querySelectorAll(".log-destination-row").forEach((row, index) => {
  row.dataset.logDestinationIndex = index;
  row.querySelector("h3").textContent = `Log destination ${index + 1}`;
 });
}
function removeCloudTarget(button){
 button.closest(".cloud-row").remove();
 if(!document.querySelector(".cloud-row")) addCloudTarget();
 renumberCloudTargets();
 setSettingsDirty(true);
}
function renumberCloudTargets(){
 document.querySelectorAll(".cloud-row").forEach((row, index) => {
  row.dataset.cloudIndex = index;
  row.querySelector("h3").textContent = `Cloud target ${index + 1}`;
 });
}
function removeHost(button){
 button.closest(".host-row").remove();
 if(!document.querySelector("#hostList > .host-row")) addHost();
 renumberHosts();
 setSettingsDirty(true);
}
function renumberHosts(){
 document.querySelectorAll("#hostList > .host-row").forEach((row, index) => {
  row.dataset.hostIndex = index;
  row.querySelector("h3").textContent = `Host ${index + 1}`;
 });
}
function collectHosts(){
 return Array.from(document.querySelectorAll("#hostList > .host-row")).map(row => ({
  name: row.querySelector(".hostName").value.trim(),
  mode: row.querySelector(".hostMode").value,
  priority: Number(row.querySelector(".hostPriority").value || 100),
  host: row.querySelector(".hostServer").value.trim(),
  port: Number(row.querySelector(".hostPort").value),
  tls: row.querySelector(".hostTls").value,
  username: row.querySelector(".hostUsername").value.trim() || null,
  password: row.querySelector(".hostPassword").value
 })).filter(host => host.name || host.host);
}
function collectCloudTargets(){
 return Array.from(document.querySelectorAll(".cloud-row")).map(row => ({
  name: row.querySelector(".cloudName").value.trim(),
  provider: row.querySelector(".cloudProvider").value,
  target: row.querySelector(".cloudTarget").value.trim(),
  command: row.querySelector(".cloudCommand").value.trim(),
  enabled: row.querySelector(".cloudEnabled").checked
 })).filter(target => target.name || target.target || target.command);
}
function collectLogDestinations(){
 return Array.from(document.querySelectorAll(".log-destination-row")).map(row => ({
  name: row.querySelector(".logDestinationName").value.trim(),
  platform: row.querySelector(".logDestinationPlatform").value,
  url: row.querySelector(".logDestinationUrl").value.trim(),
  api_key: row.querySelector(".logDestinationApiKey").value,
  username: row.querySelector(".logDestinationUsername").value.trim(),
  password: row.querySelector(".logDestinationPassword").value,
  min_level: row.querySelector(".logDestinationMinLevel").value,
  timeout_seconds: Number(row.querySelector(".logDestinationTimeout").value),
 enabled: row.querySelector(".logDestinationEnabled").checked
 })).filter(destination => destination.name || destination.url || destination.enabled);
}
async function downloadSettingsProfile(){
 const out = await api("/api/settings/profile/export");
 const blob = new Blob([JSON.stringify(out, null, 2)], {type:"application/json"});
 const url = URL.createObjectURL(blob);
 const link = document.createElement("a");
 link.href = url;
 link.download = `backuprr-settings-profile-${new Date().toISOString().replace(/[:.]/g,"-")}.json`;
 link.click();
 URL.revokeObjectURL(url);
}
async function importSettingsProfile(file){
 if(!file) return;
 const text = await file.text();
 const data = JSON.parse(text);
 const out = await post("/api/settings/profile/import", data.profile ? data : { profile:data });
 settingsOut.textContent = JSON.stringify(out, null, 2);
 if(out.ok){
  settingsCache = out.settings;
  render();
 }
}
async function detectPar2Command(){
 const out = await post("/api/settings/par2/discover", {apply:true});
 settingsOut.textContent = JSON.stringify(out, null, 2);
 if(out.found){
  setPar2Command.value = out.command;
  settingsCache = out.settings || settingsCache;
  setSettingsDirty(false);
 } else {
  settingsOut.textContent = `No PAR2-compatible executable found. Checked ${Number(out.checked?.length || 0)} candidate locations.`;
 }
}
async function saveSettings(){
 const payload = {
  newsgroup: setNewsgroup.value,
  article_size: kibToBytes(setArticleSizeKib.value),
  verification_interval_days: Number(setVerifyDays.value),
  verification_task_interval_seconds: Number(setVerifyTaskInterval.value),
  verification_files_per_run: Number(setVerifyFilesPerRun.value),
  scan_interval_seconds: Number(setScanInterval.value),
  backup_interval_seconds: Number(setBackupInterval.value),
  cloud_backup_interval_seconds: Number(setCloudBackupInterval.value),
  maintenance_interval_seconds: Number(setMaintenanceInterval.value),
  auto_vacuum_after_compaction_rows: Number(setAutoVacuumAfterCompactionRows.value),
  restore_drill_task_interval_seconds: Number(setRestoreDrillTaskInterval.value),
  update_check_interval_seconds: Number(setUpdateCheckInterval.value),
  file_stability_seconds: Number(setFileStabilitySeconds.value),
  nntp_threads: Number(setNntpThreads.value),
  hourly_post_limit_bytes: gbToBytes(setHourlyPostLimitGb.value),
  queue_strategy: setQueueStrategy.value,
  auto_pause_auth_failures: Number(setAutoPauseAuthFailures.value),
  auto_pause_provider_failures: Number(setAutoPauseProviderFailures.value),
  usenet_retry_attempts: Number(setRetryAttempts.value),
  usenet_retry_backoff_seconds: Number(setRetryBackoff.value),
  provider_retry_policy: JSON.parse(setProviderRetryPolicy.value || "{}"),
  ui_theme: setUiTheme.value,
  ui_reduced_motion: setReducedMotion.checked,
  update_check_enabled: setUpdateCheckEnabled.checked,
  update_github_repo: setUpdateGithubRepo.value,
  update_github_token_env: setUpdateGithubTokenEnv.value,
  update_check_timeout_seconds: Number(setUpdateCheckTimeout.value),
  web_ui_username: setWebUiUsername.value,
  web_ui_role: setWebUiRole.value,
  web_ui_password: setWebUiPassword.value,
  clear_web_ui_password: !!document.getElementById("clearWebUiPassword")?.checked,
  web_ui_totp_secret_env: setWebUiTotpSecretEnv.value,
  read_only_mode: setReadOnlyMode.checked,
  config_secret_key_env: setConfigSecretKeyEnv.value,
  audit_mode: setAuditMode.checked,
  audit_secret_key_env: setAuditSecretKeyEnv.value,
  api_rate_limit_per_minute: Number(setApiRateLimit.value),
  external_api_rate_limit_per_minute: Number(setExternalApiRateLimit.value),
  manifest_export_enabled: setManifestExportEnabled.checked,
  manifest_export_encrypt: setManifestExportEncrypt.checked,
  manifest_export_passphrase_env: setManifestExportPassphraseEnv.value,
  manifest_export_interval_seconds: Number(setManifestExportInterval.value),
  log_retention_days: Number(setLogRetentionDays.value),
  verbose_log_retention_days: Number(setVerboseLogRetentionDays.value),
  log_web_access: setLogWebAccess.checked,
  log_chunk_events: setLogChunkEvents.checked,
  compact_chunk_metadata: setCompactChunkMetadata.checked,
  compact_chunk_rows: setCompactChunkRows.checked,
  compression_sample_bytes: Number(setCompressionSampleBytes.value),
  compression_min_gain_percent: Number(setCompressionMinGainPercent.value),
  restore_drill_interval_days: Number(setRestoreDrillDays.value),
  restore_drill_sample_bytes: Number(setRestoreDrillBytes.value),
  critical_verification_interval_days: Number(setCriticalVerificationDays.value),
  retention_policy_patterns: setRetentionPolicyPatterns.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean),
  restore_sandbox_enabled: setRestoreSandboxEnabled.checked,
  restore_sandbox_path: setRestoreSandboxPath.value,
  compress_files: setCompressFiles.checked,
  encrypt_bodies: setEncrypt.checked,
  encryption_passphrase_env: setPassEnv.value,
  endpoints: setEndpoints.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean),
  auto_queue_exclude_patterns: setAutoQueueExcludePatterns.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean),
  queue_pause_patterns: setQueuePausePatterns.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean),
  usenet_hosts: collectHosts(),
  cloud_backups: collectCloudTargets(),
  log_destinations: collectLogDestinations(),
  par2: { enabled: setPar2.checked, command: setPar2Command.value, redundancy_percent: Number(setPar2Redundancy.value) }
 };
 const externalKeys = document.getElementById("setExternalApiKeys")?.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean) || [];
 if(externalKeys.length || document.getElementById("clearExternalApiKeys")?.checked){
  payload.external_api_keys = externalKeys;
  payload.clear_external_api_keys = !!document.getElementById("clearExternalApiKeys")?.checked;
 }
 payload.external_api_key_scopes = JSON.parse(setExternalApiKeyScopes.value || "{}");
 let out;
 try{
  const validation = await post("/api/settings/validate", payload);
  if(!validation.ok){
   settingsOut.textContent = JSON.stringify(validation, null, 2);
   return;
  }
  out = await post("/api/settings", payload);
 } catch(error){
  settingsOut.textContent = `Settings validation failed: ${error}`;
  return;
 }
 settingsOut.textContent = JSON.stringify(out, null, 2);
 if(out.ok) settingsCache = out.settings;
 if(out.ok){
  applyTheme(settingsCache.ui_theme);
  setSettingsDirty(false);
 }
}
async function disableReadOnlyMode(){
 const out = await post("/api/settings", { read_only_mode:false });
 settingsOut.textContent = JSON.stringify(out, null, 2);
 if(out.ok){
  settingsCache = out.settings;
  render();
 }
}
render();
</script>
</body>
</html>"""

