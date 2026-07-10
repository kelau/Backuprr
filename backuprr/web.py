import json
import math
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import __version__
from .cloud_backup import backup_config_and_database
from .config import Config, update_config
from .db import Database
from .monitor import BackupMonitor, CatalogMonitor, VerificationMonitor, CloudBackupMonitor
from .queueing import enqueue_unbacked, move, prioritize
from .restore import restore_file, restore_folder


def rowdicts(rows):
    return [dict(row) for row in rows]


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


def thread_usage_summary(posting_rows: list[dict[str, Any]], article_size: int, configured_threads: int) -> dict[str, int]:
    total = max(1, int(configured_threads or 1))
    size = max(1, int(article_size or 1))
    remaining_chunks = 0
    for row in posting_rows:
        expected = max(1, math.ceil(int(row.get("size") or 0) / size))
        posted = int(row.get("posted_chunks") or row.get("progress_chunks") or 0)
        remaining_chunks += max(0, expected - posted)
    return {"in_use": min(total, remaining_chunks), "total": total}


class Handler(BaseHTTPRequestHandler):
    config: Config
    config_path: str
    db: Database
    monitor: CatalogMonitor
    backup_monitor: BackupMonitor
    verification_monitor: VerificationMonitor
    cloud_backup_monitor: CloudBackupMonitor

    def log_message(self, fmt: str, *args: Any) -> None:
        self.db.log("verbose", "web.access", fmt % args)

    def send_json(self, data: Any, status: int = 200) -> None:
        payload = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(INDEX_HTML.encode("utf-8"))
        elif parsed.path == "/api/status":
            self.db.cleanup_completed_queue()
            speed = self.db.speed_samples(5, 10)
            posting_rows = [dict(row) for row in self.db.list_queue(status="posting")]
            self.send_json(
                {
                    "version": __version__,
                    "stats": self.db.stats(),
                    "throughput": throughput_summary(speed),
                    "nntp_threads": thread_usage_summary(posting_rows, self.config.article_size, self.config.nntp_threads),
                    "scan_interval_seconds": self.config.scan_interval_seconds,
                    "backup_interval_seconds": self.config.backup_interval_seconds,
                    "verification_task_interval_seconds": self.config.verification_task_interval_seconds,
                    "verification_files_per_run": self.config.verification_files_per_run,
                    "cloud_backup_interval_seconds": self.config.cloud_backup_interval_seconds,
                }
            )
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
            offset = (page - 1) * page_size
            self.send_json(
                {
                    "rows": rowdicts(self.db.list_files(page_size, offset, search, include_deleted, unbacked_only)),
                    "page": page,
                    "page_size": page_size,
                    "total": self.db.file_count(search, include_deleted, unbacked_only),
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
                }
            )
        elif parsed.path == "/api/verification":
            page = max(1, int(query.get("page", ["1"])[0]))
            page_size = max(1, min(200, int(query.get("page_size", ["25"])[0])))
            offset = (page - 1) * page_size
            self.send_json({"rows": rowdicts(self.db.verification_rows(page_size, offset)), "page": page, "page_size": page_size, "total": self.db.file_count()})
        elif parsed.path == "/api/log":
            levels = query.get("level", [])
            if not levels and query.get("levels"):
                levels = [item for group in query.get("levels", []) for item in group.split(",")]
            event_types = query.get("event_type", [])
            exclude_event_types = query.get("exclude_event_type", [])
            self.send_json(rowdicts(self.db.list_events(levels, int(query.get("limit", ["300"])[0]), event_types, exclude_event_types)))
        elif parsed.path == "/api/log/event-types":
            self.send_json(self.db.event_types())
        elif parsed.path == "/api/queue":
            self.db.cleanup_completed_queue()
            page = max(1, int(query.get("page", ["1"])[0]))
            page_size = max(1, min(100, int(query.get("page_size", ["10"])[0])))
            status = query.get("status", [None])[0]
            offset = (page - 1) * page_size
            rows = [self.queue_row_payload(row) for row in self.db.list_queue(status=status, limit=page_size, offset=offset)]
            self.send_json({"rows": rows, "page": page, "page_size": page_size, "total": self.db.queue_count(status=status)})
        elif parsed.path == "/api/tasks":
            self.send_json(self.all_tasks())
        elif parsed.path == "/api/settings":
            self.send_json(self.config.public_dict())
        else:
            self.send_json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            data = self.read_json()
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
            elif parsed.path == "/api/verify":
                file_ids = [int(file_id) for file_id in data.get("file_ids", [])]
                self.send_json({"verified": self.verification_monitor.verify_once(force=bool(data.get("force")) or bool(file_ids), file_ids=file_ids)})
            elif parsed.path == "/api/cloud-backup":
                results = backup_config_and_database(self.db, self.config)
                self.db.log("info", "cloud.backup", f"Backed up config/database to {len(results)} cloud targets")
                self.send_json({"ok": True, "results": results})
            elif parsed.path == "/api/restore":
                if data.get("folder"):
                    self.send_json({"restored": restore_folder(self.db, self.config, data["path"], data.get("dest"))})
                else:
                    self.send_json({"target": str(restore_file(self.db, self.config, data["path"], data.get("dest")))})
            elif parsed.path == "/api/settings":
                update_config(self.config, data)
                self.config.save(self.config_path)
                for endpoint in self.config.endpoints:
                    self.db.add_endpoint(endpoint)
                self.db.log("info", "settings", "Updated configuration from Web UI")
                self.monitor.trigger()
                self.send_json({"ok": True, "settings": self.config.public_dict()})
            else:
                self.send_json({"error": "not found"}, 404)
        except Exception as exc:
            self.db.log("error", "web.error", f"{parsed.path}: {exc}")
            self.send_json({"error": str(exc)}, 500)

    def queue_row_payload(self, row: Any) -> dict:
        payload = dict(row)
        expected = max(1, (int(payload["size"]) + self.config.article_size - 1) // self.config.article_size)
        posted = int(payload.get("posted_chunks") or 0)
        payload["expected_chunks"] = expected
        payload["progress_percent"] = min(100, int((posted / expected) * 100))
        payload["progress"] = f"{posted}/{expected} chunks ({payload['progress_percent']}%)"
        return payload

    def all_tasks(self) -> list[dict]:
        return self.monitor.tasks() + self.backup_monitor.tasks() + self.verification_monitor.tasks() + self.cloud_backup_monitor.tasks()

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
                token["task_revision"] = sum(int(task.get("revision", 0)) for task in self.all_tasks())
                payload = json.dumps(token, default=str)
                if payload != last_payload:
                    self.wfile.write(f"event: change\ndata: {payload}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    last_payload = payload
                time.sleep(1)
        except (BrokenPipeError, ConnectionError):
            return


def run_web(config: Config, db: Database, host: str, port: int) -> None:
    Handler.config = config
    Handler.config_path = str(config.source_path or (config.base_dir / "config.json"))
    Handler.db = db
    Handler.monitor = CatalogMonitor(db, config)
    Handler.backup_monitor = BackupMonitor(db, config)
    Handler.verification_monitor = VerificationMonitor(db, config)
    Handler.cloud_backup_monitor = CloudBackupMonitor(db, config)
    Handler.monitor.start()
    Handler.backup_monitor.start()
    Handler.verification_monitor.start()
    Handler.cloud_backup_monitor.start()
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Backuprr {__version__} listening on http://{host}:{port}")
    try:
        server.serve_forever()
    finally:
        Handler.monitor.stop()
        Handler.backup_monitor.stop()
        Handler.verification_monitor.stop()
        Handler.cloud_backup_monitor.stop()


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Backuprr</title>
<style>
:root { color-scheme: light; --ink:#172026; --muted:#64717b; --line:#d8dee4; --bg:#f6f7f8; --accent:#0f766e; --warn:#b45309; --bad:#b91c1c; }
* { box-sizing:border-box; }
body { margin:0; font:14px/1.45 system-ui, -apple-system, Segoe UI, sans-serif; color:var(--ink); background:var(--bg); }
header { height:56px; display:flex; align-items:center; justify-content:space-between; padding:0 18px; background:#fff; border-bottom:1px solid var(--line); }
header strong { font-size:18px; }
nav { width:220px; padding:14px; border-right:1px solid var(--line); background:#fff; min-height:calc(100vh - 56px); }
nav button { width:100%; display:flex; align-items:center; gap:8px; margin:3px 0; padding:9px 10px; border:0; background:transparent; color:var(--ink); text-align:left; border-radius:6px; cursor:pointer; }
nav button.active, nav button:hover { background:#e8f3f1; }
.nav-icon, .ui-icon { width:1.2em; display:inline-grid; place-items:center; flex:0 0 auto; }
main { display:flex; }
section { flex:1; padding:18px; min-width:0; }
.toolbar { display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin-bottom:12px; }
button, select, input, textarea { border:1px solid var(--line); background:#fff; color:var(--ink); border-radius:6px; padding:8px 10px; font:inherit; }
button { cursor:pointer; }
button.primary { background:var(--accent); color:#fff; border-color:var(--accent); }
textarea { width:100%; min-height:120px; font-family:ui-monospace, SFMono-Regular, Consolas, monospace; }
label { display:inline-flex; align-items:center; gap:6px; }
table { width:100%; border-collapse:collapse; background:#fff; border:1px solid var(--line); }
th, td { padding:8px 10px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; overflow-wrap:anywhere; }
th { color:var(--muted); font-weight:600; background:#fafbfb; }
.stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:10px; margin-bottom:16px; }
.compact-stats { grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); margin-bottom:0; }
.stat { background:#fff; border:1px solid var(--line); border-radius:8px; padding:12px; }
.stat b { display:block; font-size:24px; }
.compact-stats .stat b { font-size:18px; }
.dashboard { display:grid; gap:14px; }
.hero-status { background:#fff; border:1px solid var(--line); border-radius:8px; padding:14px; display:grid; gap:10px; }
.hero-status h2 { margin:0; font-size:20px; }
.task-strip { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:10px; }
.task-card { background:#fff; border:1px solid var(--line); border-radius:8px; padding:12px; display:grid; gap:6px; }
.task-card h3 { margin:0; font-size:14px; }
.badge { display:inline-flex; align-items:center; width:max-content; padding:3px 7px; border-radius:999px; background:#e8f3f1; color:var(--accent); font-size:12px; font-weight:700; }
.badge.running { background:#fff7ed; color:var(--warn); }
.pill { display:inline-flex; align-items:center; gap:5px; width:max-content; max-width:100%; padding:3px 7px; border-radius:999px; background:#edf1f2; color:var(--muted); font-size:12px; font-weight:700; }
.pill.ok { background:#e8f3f1; color:var(--accent); }
.pill.warn { background:#fff7ed; color:var(--warn); }
.pill.bad { background:#fef2f2; color:var(--bad); }
.pill.info { background:#eff6ff; color:#1d4ed8; }
.pill.debug { background:#f5f3ff; color:#6d28d9; }
.pill.verbose { background:#f8fafc; color:var(--muted); }
.stat span, .section-title, .chart-card h3, .task-card h3 { display:flex; align-items:center; gap:6px; }
.chart-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:12px; }
.chart-card { background:#fff; border:1px solid var(--line); border-radius:8px; padding:12px; }
.chart-card h3 { margin:0 0 10px; font-size:14px; }
.bar-row { display:grid; grid-template-columns:minmax(90px,150px) 1fr minmax(42px,max-content); gap:8px; align-items:center; margin:7px 0; }
.bar-track { height:12px; background:#edf1f2; border-radius:999px; overflow:hidden; }
.bar-fill { height:100%; background:var(--accent); border-radius:999px; min-width:2px; }
.bar-fill.warn { background:var(--warn); }
.bar-fill.bad { background:var(--bad); }
.progress-track { height:16px; background:#edf1f2; border-radius:999px; overflow:hidden; }
.progress-fill { height:100%; background:var(--accent); border-radius:999px; transition:width .2s ease; }
.file-progress { min-width:160px; max-width:220px; display:grid; gap:3px; }
.file-progress .progress-track { height:8px; }
.file-progress span { font-size:12px; color:var(--muted); }
.thread-meter { display:flex; align-items:baseline; gap:8px; margin-bottom:10px; }
.thread-meter b { font-size:32px; }
.refresh-note { margin-left:auto; }
.push-note { margin-left:auto; }
.section-title { margin:16px 0 8px; font-size:16px; }
.pagination { display:flex; gap:8px; align-items:center; margin:8px 0 14px; }
.form-grid { display:grid; grid-template-columns:minmax(0,720px); gap:12px; margin-bottom:12px; align-items:start; }
.field { display:grid; gap:5px; }
.field span { color:var(--muted); font-size:12px; font-weight:600; }
.full { grid-column:1 / -1; }
.host-list { display:grid; gap:12px; }
.host-row, .cloud-row { border:1px solid var(--line); background:#fff; border-radius:8px; padding:12px; }
.host-row h3, .cloud-row h3 { margin:0 0 10px; font-size:14px; }
.host-grid { display:grid; grid-template-columns:minmax(0,1fr); gap:10px; }
.tabs { display:flex; flex-wrap:wrap; gap:6px; margin-bottom:12px; }
.tab-panel { display:none; }
.tab-panel.active { display:block; }
.selection-summary { position:sticky; bottom:0; margin-top:12px; background:#fff; border:1px solid var(--line); border-radius:8px; padding:10px 12px; box-shadow:0 -6px 18px rgba(23,32,38,.06); }
.danger { color:var(--bad); }
.tree { background:#fff; border:1px solid var(--line); border-radius:8px; padding:8px; }
.tree ul { list-style:none; margin:0; padding-left:20px; }
.tree li { margin:2px 0; }
.tree-row { display:flex; align-items:center; gap:8px; min-height:32px; padding:4px 6px; border-radius:6px; }
.tree-row:hover { background:#f2f6f6; }
.tree-name { flex:1; overflow-wrap:anywhere; }
.tree-meta { color:var(--muted); font-size:12px; }
.icon-btn { width:32px; height:32px; display:inline-grid; place-items:center; padding:0; }
.folder > .tree-row { font-weight:600; }
.hidden { display:none; }
.muted { color:var(--muted); }
.error { color:var(--bad); }
pre { white-space:pre-wrap; background:#fff; border:1px solid var(--line); padding:12px; border-radius:8px; }
@media (max-width:760px) { main { display:block; } nav { width:auto; min-height:0; border-right:0; border-bottom:1px solid var(--line); display:grid; grid-template-columns:repeat(2,1fr); } }
</style>
</head>
<body>
<header><strong>Backuprr</strong><span id="version" class="muted"></span></header>
<main>
<nav id="nav"></nav>
<section id="content"></section>
</main>
<script>
const pages = ["Status","Files","Search","Log","Queue","Tasks","Verification","Statistics","Settings","About"];
let page = "Status";
let settingsCache = null;
let fileRowsCache = [];
let logLevelSelection = ["error","warning","info"];
let logEventTypeSelection = [];
let logExcludeWebAccess = true;
let logLimitSelection = "300";
let eventSource = null;
let lastChangeToken = null;
let activeQueuePage = 1;
let completedQueuePage = 1;
let failedQueuePage = 1;
let filesPage = 1;
let verificationPage = 1;
let selectedFiles = new Set();
let selectedFileData = new Map();
let selectedVerificationFiles = new Set();
const queuePageSize = 10;
const filesPageSize = 100;
const api = (url, opts={}) => fetch(url, {headers:{"Content-Type":"application/json"}, ...opts}).then(r => r.json());
const post = (url, body={}) => api(url, {method:"POST", body:JSON.stringify(body)});
function esc(v){ return String(v ?? "").replace(/[&<>"']/g, s => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[s])); }
function jsString(v){ return JSON.stringify(String(v ?? "")).replace(/</g, "\\u003c"); }
function table(rows, cols){
 if(!rows.length) return "<p class='muted'>No rows.</p>";
 return `<table><thead><tr>${cols.map(c=>`<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>`+
 rows.map(r=>`<tr>${cols.map(c=>`<td>${formatCellHtml(c, r[c], r)}</td>`).join("")}</tr>`).join("")+"</tbody></table>";
}
function formatCell(col, value){
 return ["size","size_bytes","files_bytes_total","files_bytes_backed_up","chunks_bytes_total"].includes(col) ? formatBytes(value) : value;
}
function formatCellHtml(col, value, row={}){
 if(["size","size_bytes","files_bytes_total","files_bytes_backed_up","chunks_bytes_total"].includes(col)) return esc(formatBytes(value));
 if(["ts","created_at","updated_at","last_backup_at","last_verify_at","last_chunk_verify_at","posted_at","verified_at","last_run"].includes(col)) return esc(formatDateTime(value));
 if(["state","status"].includes(col)) return statePill(value);
 if(col === "level") return levelPill(value);
 if(col === "kind") return iconText(kindIcon(value), value);
 if(col === "progress") return iconText(iconForProgress(row.progress_percent), value);
 if(col === "last_error" && value) return iconText("&#9888;", value, "error");
 return esc(value);
}
function iconText(icon, text, cls=""){
 return `<span class="${cls}"><span class="ui-icon">${icon}</span>${esc(text)}</span>`;
}
function pageIcon(name){
 return ({Status:"&#128202;",Files:"&#128193;",Search:"&#128269;",Log:"&#128221;",Queue:"&#128230;",Tasks:"&#9881;",Verification:"&#10003;",Statistics:"&#128200;",Settings:"&#128295;",About:"&#8505;"}[name] || "&#8226;");
}
function stateIcon(value){
 return ({backed_up:"&#10003;",queued:"&#9203;",posting:"&#9658;",failed:"&#9888;",deleted:"&#128465;",discovered:"&#128269;",changed:"&#9998;",missing_chunks:"&#9888;",restored:"&#8635;",done:"&#10003;",running:"&#9658;",scheduled:"&#9202;",verified:"&#10003;",missing:"&#9888;"}[String(value || "")] || "&#8226;");
}
function stateTone(value){
 return ({backed_up:"ok",done:"ok",restored:"ok",queued:"warn",posting:"warn",running:"warn",failed:"bad",deleted:"bad",missing_chunks:"bad"}[String(value || "")] || "");
}
function statePill(value){
 const tone = stateTone(value);
 return `<span class="pill ${tone}"><span class="ui-icon">${stateIcon(value)}</span>${esc(value || "-")}</span>`;
}
function levelPill(value){
 const key = String(value || "");
 const tone = ({error:"bad",warning:"warn",info:"info",debug:"debug",verbose:"verbose"}[key] || "");
 const icon = ({error:"&#10060;",warning:"&#9888;",info:"&#8505;",debug:"&#128027;",verbose:"&#128269;"}[key] || "&#8226;");
 return `<span class="pill ${tone}"><span class="ui-icon">${icon}</span>${esc(value || "-")}</span>`;
}
function kindIcon(value){
 return ({catalog:"&#128193;",backup:"&#128230;",verification:"&#10003;",cloud_backup:"&#9729;"}[String(value || "")] || "&#9881;");
}
function iconForProgress(value){
 const pct = Number(value || 0);
 if(pct >= 100) return "&#10003;";
 if(pct > 0) return "&#9658;";
 return "&#9711;";
}
function nav(){
 document.getElementById("nav").innerHTML = pages.map(p=>`<button class="${p===page?"active":""}" onclick="page='${p}';render()"><span class="nav-icon">${pageIcon(p)}</span>${p}</button>`).join("");
}
function connectChanges(){
 if(eventSource) return;
 eventSource = new EventSource("/api/events/stream");
 eventSource.addEventListener("change", event => {
  const token = JSON.parse(event.data);
  const previous = lastChangeToken;
  lastChangeToken = token;
  if(previous) refreshPageForChanges(previous, token);
  else refreshCurrentLivePage();
 });
 eventSource.onerror = () => { document.querySelectorAll(".push-state").forEach(el => el.textContent = "Waiting for change stream"); };
}
function pushLabel(){
 return `<span class="muted push-note push-state"><span class="ui-icon">&#128225;</span>Live updates on change</span>`;
}
async function render(){
 nav();
 connectChanges();
 const c = document.getElementById("content");
 if(page==="Status"){
  c.innerHTML = `<div id="statusPanel"></div>`;
  await updateStatusPage();
 }
 if(page==="Files"){
  c.innerHTML = `<div class="toolbar">
   <input id="filesSearch" placeholder="Search files" oninput="filesPage=1;updateFilesPage()">
   <label><input id="showUnbackedOnly" type="checkbox" onchange="filesPage=1;updateFilesPage()"> <span class="ui-icon">&#9888;</span>Only unbacked</label>
   <label><input id="showDeletedFiles" type="checkbox" onchange="filesPage=1;updateFilesPage()"> <span class="ui-icon">&#128465;</span>Show deleted</label>
   <label><input id="selectAllFiles" type="checkbox" onchange="toggleSelectAllFiles(this.checked)"> Select page</label>
   <button onclick="boostSelectedFiles()"><span class="ui-icon">&#8593;</span>Bump selected</button>
   <button onclick="restoreSelectedFiles()"><span class="ui-icon">&#8635;</span>Restore selected</button>
   ${pushLabel()}
  </div><div id="filesTree"></div><div id="filesSelectionSummary" class="selection-summary"></div>`;
  await updateFilesPage();
 }
 if(page==="Search"){
  c.innerHTML = `<div class="toolbar"><input id="q" placeholder="Search files"><button onclick="search()"><span class="ui-icon">&#128269;</span>Search</button></div><div id="results"></div>`;
 }
 if(page==="Log"){
  const eventTypes = await api("/api/log/event-types");
  const levels = ["error","warning","info","debug","verbose"];
  c.innerHTML = `<div class="toolbar">
   ${levels.map(level=>`<label><input class="logLevel" type="checkbox" value="${level}" ${logLevelSelection.includes(level) ? "checked" : ""}> ${levelPill(level)}</label>`).join("")}
   <select id="logEventType"><option value="">All event types</option>${eventTypes.map(type=>`<option value="${esc(type)}" ${logEventTypeSelection.includes(type) ? "selected" : ""}>${esc(type)}</option>`).join("")}</select>
   <label><input id="hideWebAccess" type="checkbox" ${logExcludeWebAccess ? "checked" : ""}> Hide web.access</label>
   <select id="logLimit"><option ${logLimitSelection==="100"?"selected":""}>100</option><option ${logLimitSelection==="300"?"selected":""}>300</option><option ${logLimitSelection==="1000"?"selected":""}>1000</option></select>
   <button onclick="loadLog()"><span class="ui-icon">&#128269;</span>Apply</button>${pushLabel()}
  </div><div id="logRows"></div>`;
  await updateLogPage();
 }
 if(page==="Queue"){
  c.innerHTML = `<div class="toolbar"><select id="filter"><option>older-first</option><option>larger-first</option><option>smaller-first</option></select><button onclick="post('/api/queue/prioritize',{filter:document.getElementById('filter').value}).then(updateQueuePage)"><span class="ui-icon">&#8593;</span>Apply filter</button><button class="primary" onclick="post('/api/post-next').then(updateQueuePage)"><span class="ui-icon">&#9658;</span>Post next</button>${pushLabel()}</div><h2 class="section-title"><span class="ui-icon">&#9658;</span>Active</h2><div id="activeQueueRows"></div><h2 class="section-title"><span class="ui-icon">&#9888;</span>Failed</h2><div id="failedQueueRows"></div><h2 class="section-title"><span class="ui-icon">&#10003;</span>Completed</h2><div id="completedQueueRows"></div>`;
  await updateQueuePage();
 }
 if(page==="Tasks"){
  c.innerHTML = `<div class="toolbar"><button class="primary" onclick="post('/api/scan').then(updateTasksPage)"><span class="ui-icon">&#128193;</span>Run catalog scan</button>${pushLabel()}</div><div id="taskRows"></div>`;
  await updateTasksPage();
 }
 if(page==="Verification"){
  c.innerHTML = `<div class="toolbar"><label><input id="selectAllVerification" type="checkbox" onchange="toggleSelectAllVerification(this.checked)"> Select page</label><button class="primary" onclick="verifySelectedFiles()"><span class="ui-icon">&#10003;</span>Verify selected</button><button onclick="post('/api/verify',{force:true}).then(updateVerificationPage)"><span class="ui-icon">&#10003;</span>Verify all</button>${pushLabel()}</div><div id="verificationRows"></div>`;
  await updateVerificationPage();
 }
 if(page==="Statistics"){
  c.innerHTML = `<div id="statisticsPanel"></div>`;
  await updateStatisticsPage();
 }
 if(page==="Settings"){ settingsCache = await api("/api/settings"); c.innerHTML = settingsForm(settingsCache); }
 if(page==="About"){ c.innerHTML = `<h1><span class="ui-icon">&#128230;</span>Backuprr</h1><p><span class="ui-icon">&#128278;</span>Version <span id="aboutVersion"></span></p><p><span class="ui-icon">&#128274;</span>Catalog media folders, post obfuscated Usenet backups, verify article availability, and restore files when needed.</p>`; const s=await api("/api/status"); document.getElementById("aboutVersion").textContent=s.version; }
}
async function refreshCurrentLivePage(){
 if(page==="Status") await updateStatusPage();
 if(page==="Files") await updateFilesPage();
 if(page==="Queue") await updateQueuePage();
 if(page==="Tasks") await updateTasksPage();
 if(page==="Verification") await updateVerificationPage();
 if(page==="Statistics") await updateStatisticsPage();
}
async function refreshPageForChanges(previous, token){
 const filesChanged = previous.files_updated !== token.files_updated || previous.files_total !== token.files_total;
 const queueChanged = previous.queue_updated !== token.queue_updated || previous.queue_total !== token.queue_total;
 const eventsChanged = previous.event_id !== token.event_id;
 const transferChanged = previous.transfer_id !== token.transfer_id;
 const chunksChanged = previous.chunks_total !== token.chunks_total;
 const tasksChanged = previous.task_revision !== token.task_revision;
 if(page==="Status" && (filesChanged || queueChanged || chunksChanged || tasksChanged || transferChanged)) await updateStatusPage();
 if(page==="Files" && (filesChanged || queueChanged || transferChanged)) await updateFilesPage();
 if(page==="Log" && eventsChanged) await updateLogPage(false);
 if(page==="Queue" && (queueChanged || filesChanged || transferChanged)) await updateQueuePage();
 if(page==="Tasks" && (eventsChanged || tasksChanged)) await updateTasksPage();
 if(page==="Verification" && (chunksChanged || filesChanged || tasksChanged)) await updateVerificationPage();
 if(page==="Statistics" && (filesChanged || queueChanged || chunksChanged || tasksChanged || eventsChanged || transferChanged)) await updateStatisticsPage();
 document.querySelectorAll(".push-state").forEach(el => el.textContent = "Updated after change");
}
async function updateStatusPage(){
 const s = await api("/api/status");
 const tasks = await api("/api/tasks");
 const speed = await api("/api/speed?minutes=10&bucket=10");
 document.getElementById("version").textContent = "v"+s.version;
 const panel = document.getElementById("statusPanel");
 if(panel) panel.innerHTML = statusDashboard(s, tasks, speed);
}
async function updateFilesPage(){
 const openFolders = new Set(Array.from(document.querySelectorAll("#filesTree details[data-path][open]")).map(item => item.dataset.path));
 const showDeleted = !!document.getElementById("showDeletedFiles")?.checked;
 const unbacked = !!document.getElementById("showUnbackedOnly")?.checked;
 const q = document.getElementById("filesSearch")?.value || "";
 const result = await api(`/api/files?page=${filesPage}&page_size=${filesPageSize}&include_deleted=${showDeleted ? 1 : 0}&unbacked=${unbacked ? 1 : 0}&q=${encodeURIComponent(q)}`);
 fileRowsCache = result.rows || [];
 for(const row of fileRowsCache){
  if(selectedFiles.has(Number(row.id))) selectedFileData.set(Number(row.id), row);
 }
 const target = document.getElementById("filesTree");
 if(target){
  target.innerHTML = fileTree(fileRowsCache, showDeleted) + paginationControls(result, "filesPage", "updateFilesPage");
  target.querySelectorAll("details[data-path]").forEach(details => {
   if(openFolders.has(details.dataset.path)) details.open = true;
  });
  updateFolderCheckboxStates();
  updateFilesSelectionSummary();
 }
}
async function updateQueuePage(){
 const active = await api(`/api/queue?page=${activeQueuePage}&page_size=${queuePageSize}`);
 const failed = await api(`/api/queue?status=failed&page=${failedQueuePage}&page_size=${queuePageSize}`);
 const done = await api(`/api/queue?status=done&page=${completedQueuePage}&page_size=${queuePageSize}`);
 const activeTarget = document.getElementById("activeQueueRows");
 const failedTarget = document.getElementById("failedQueueRows");
 const doneTarget = document.getElementById("completedQueueRows");
 if(activeTarget) activeTarget.innerHTML = pagedTable(active, "activeQueuePage", ["file_id","position","priority","status","reason","path","size","progress","state"]);
 if(failedTarget) failedTarget.innerHTML = pagedTable(failed, "failedQueuePage", ["file_id","position","priority","status","reason","path","size","progress","state"]);
 if(doneTarget) doneTarget.innerHTML = pagedTable(done, "completedQueuePage", ["file_id","position","priority","status","reason","path","size","progress","state"]);
}
function pagedTable(result, pageVar, cols){
 const totalPages = Math.max(1, Math.ceil(Number(result.total || 0) / Number(result.page_size || queuePageSize)));
 const pageNo = Number(result.page || 1);
 return table(result.rows || [], cols) + `<div class="pagination"><button ${pageNo <= 1 ? "disabled" : ""} onclick="${pageVar}=Math.max(1,${pageVar}-1);updateQueuePage()">Previous</button><span class="muted">Page ${pageNo} of ${totalPages} &middot; ${Number(result.total || 0)} rows</span><button ${pageNo >= totalPages ? "disabled" : ""} onclick="${pageVar}=${pageVar}+1;updateQueuePage()">Next</button></div>`;
}
function verificationTable(rows){
 if(!rows.length) return "<p class='muted'>No rows.</p>";
 const cols = ["relative_path","state","chunk_count","verified_chunks","missing_chunks","last_verify_at","last_chunk_verify_at"];
 return `<table><thead><tr><th></th>${cols.map(c=>`<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>`+
 rows.map(row => `<tr><td><input class="verificationSelect" type="checkbox" value="${Number(row.id)}" ${selectedVerificationFiles.has(Number(row.id)) ? "checked" : ""} onchange="setVerificationSelected(${Number(row.id)}, this.checked)"></td>${cols.map(c=>`<td>${formatCellHtml(c, row[c], row)}</td>`).join("")}</tr>`).join("")+
 "</tbody></table>";
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
function updateVerificationSelectionState(rows=[]){
 const ids = rows.length ? rows.map(row => Number(row.id)) : Array.from(document.querySelectorAll(".verificationSelect")).map(box => Number(box.value));
 const selected = ids.filter(id => selectedVerificationFiles.has(id)).length;
 const selectAll = document.getElementById("selectAllVerification");
 if(selectAll){
  selectAll.checked = ids.length > 0 && selected === ids.length;
  selectAll.indeterminate = selected > 0 && selected < ids.length;
 }
}
async function verifySelectedFiles(){
 const ids = Array.from(selectedVerificationFiles);
 if(!ids.length) return alert("Select files to verify first");
 const out = await post("/api/verify", { file_ids:ids });
 if(out.error) alert(out.error);
 await updateVerificationPage();
}
async function updateTasksPage(){
 const rows = await api("/api/tasks");
 const target = document.getElementById("taskRows");
 if(target) target.innerHTML = table(rows, ["name","kind","status","interval_seconds","last_run","last_run_duration","time_until_next_run","runs","last_result","last_error"]);
}
async function updateVerificationPage(){
 const result = await api(`/api/verification?page=${verificationPage}&page_size=25`);
 const target = document.getElementById("verificationRows");
 if(target) target.innerHTML = verificationTable(result.rows || []) + paginationControls(result, "verificationPage", "updateVerificationPage");
 updateVerificationSelectionState(result.rows || []);
}
async function updateStatisticsPage(){
 const data = await api("/api/statistics");
 if(!settingsCache) settingsCache = await api("/api/settings");
 const target = document.getElementById("statisticsPanel");
 if(target) target.innerHTML = statisticsDashboard(data);
}
function paginationControls(result, pageVar, updateFn){
 const totalPages = Math.max(1, Math.ceil(Number(result.total || 0) / Number(result.page_size || 1)));
 const pageNo = Number(result.page || 1);
 return `<div class="pagination"><button ${pageNo <= 1 ? "disabled" : ""} onclick="${pageVar}=Math.max(1,${pageVar}-1);${updateFn}()">Previous</button><span class="muted">Page ${pageNo} of ${totalPages} &middot; ${Number(result.total || 0)} rows</span><button ${pageNo >= totalPages ? "disabled" : ""} onclick="${pageVar}=${pageVar}+1;${updateFn}()">Next</button></div>`;
}
function statusDashboard(status, tasks, speed){
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
 const nntpThreads = status.nntp_threads || {};
 const protectedPct = total ? Math.round((backed / total) * 100) : 0;
 const activeTask = tasks.find(task => task.status === "running");
 const nextTask = tasks
  .filter(task => task.status !== "running" && task.time_until_next_run)
  .sort((a,b) => secondsFromLabel(a.time_until_next_run) - secondsFromLabel(b.time_until_next_run))[0];
 return `<div class="dashboard">
  <div class="toolbar"><button class="primary" onclick="post('/api/scan').then(updateStatusPage)"><span class="ui-icon">&#128193;</span>Scan now</button><button onclick="post('/api/queue/enqueue-unbacked').then(updateStatusPage)"><span class="ui-icon">&#10133;</span>Queue unbacked</button><button onclick="post('/api/verify',{force:true}).then(updateStatusPage)"><span class="ui-icon">&#10003;</span>Verify chunks</button>${pushLabel()}</div>
  <div class="hero-status">
   <h2><span class="ui-icon">${activeTask ? "&#9658;" : "&#10003;"}</span>${esc(activeTask ? `${activeTask.name} is running` : "Backuprr is standing by")}</h2>
   <div class="muted">${esc(activeTask ? activeTask.last_result || "Working through the current task" : nextTask ? `Next: ${nextTask.name} in ${nextTask.time_until_next_run}` : "No scheduled task time reported")}</div>
   <div class="progress-track"><div class="progress-fill" style="width:${protectedPct}%"></div></div>
   <div>${protectedPct}% backed up &middot; ${backed} of ${total} files protected (${formatBytes(backedBytes)} of ${formatBytes(totalBytes)}) &middot; ${queued + posting} waiting or posting (${formatBytes(queuedBytes + postingBytes)}) &middot; ${chunks} chunks posted (${formatBytes(chunkBytes)})</div>
  </div>
  <div class="task-strip">${tasks.map(taskCard).join("")}</div>
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
   ${threadPanel(nntpThreads)}
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
  <span class="badge ${running ? "running" : ""}"><span class="ui-icon">${stateIcon(task.status)}</span>${esc(task.status)}</span>
  <div class="muted"><span class="ui-icon">&#9201;</span>Last run: ${esc(formatDateTime(task.last_run) || "not yet")}</div>
  <div><span class="ui-icon">&#9201;</span>Duration: ${esc(task.last_run_duration || "-")}</div>
  <div><span class="ui-icon">&#9202;</span>Next run: ${esc(task.time_until_next_run || "-")}</div>
  <div class="${task.last_error ? "error" : "muted"}">${esc(task.last_error || task.last_result || "")}</div>
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
  </div>
  <div class="chart-grid">
   ${speedChart("Two hour transfer speed", speed)}
   ${barChart("Engine tasks", tasks.map(task => [task.name, task.runs || 0, task.status === "running" ? "warn" : "ok"]))}
   ${barChart("Recent event types", eventRows.length ? eventRows : [["none", 0, "ok"]])}
  </div>
  <h2 class="section-title"><span class="ui-icon">&#9881;</span>Workers</h2>
  ${table(tasks, ["name","kind","status","interval_seconds","last_run","last_run_duration","time_until_next_run","runs","last_result","last_error"])}
 </div>`;
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
   <line x1="${pad}" y1="${height-pad}" x2="${width-pad}" y2="${height-pad}" stroke="#d8dee4"/>
   <line x1="${pad}" y1="${pad}" x2="${pad}" y2="${height-pad}" stroke="#d8dee4"/>
   <text x="${pad + 4}" y="${pad - 7}" font-size="11" fill="#64717b">${esc(maxLabel)}</text>
   <text x="${pad}" y="${height - 4}" font-size="11" fill="#64717b">30 min ago</text>
   <text x="${width - pad - 22}" y="${height - 4}" font-size="11" fill="#64717b">now</text>
   <text x="${width - pad - 112}" y="${pad + 12}" font-size="11" fill="#0f766e">upload</text>
   <text x="${width - pad - 62}" y="${pad + 12}" font-size="11" fill="#b45309">download</text>
   <polyline points="${points("upload_bps")}" fill="none" stroke="#0f766e" stroke-width="3"/>
   <polyline points="${points("download_bps")}" fill="none" stroke="#b45309" stroke-width="3"/>
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
function formatDateTime(value){
 if(!value) return "";
 const date = new Date(value);
 if(Number.isNaN(date.getTime())) return value;
 return new Intl.DateTimeFormat(undefined, { dateStyle:"medium", timeStyle:"medium" }).format(date);
}
function secondsFromLabel(label){
 const text = String(label || "");
 const h = Number((text.match(/(\d+)h/) || [0,0])[1]);
 const m = Number((text.match(/(\d+)m/) || [0,0])[1]);
 const s = Number((text.match(/(\d+)s/) || [0,0])[1]);
 return h * 3600 + m * 60 + s;
}
async function updateLogPage(saveSelection=true){
 logLevelSelection = Array.from(document.querySelectorAll(".logLevel:checked")).map(input => input.value);
 logEventTypeSelection = Array.from(document.querySelectorAll("#logEventType")).map(input => input.value).filter(Boolean);
 logExcludeWebAccess = !!document.getElementById("hideWebAccess")?.checked;
 logLimitSelection = document.getElementById("logLimit").value;
 const levels = logLevelSelection.map(level => "level="+encodeURIComponent(level)).join("&");
 const eventTypes = logEventTypeSelection.map(type => "event_type="+encodeURIComponent(type)).join("&");
 const exclude = logExcludeWebAccess ? "exclude_event_type=web.access" : "";
 const limit = encodeURIComponent(logLimitSelection);
 document.getElementById("logRows").innerHTML = table(await api(`/api/log?limit=${limit}&${levels}&${eventTypes}&${exclude}`), ["id","ts","level","event_type","message","file_id"]);
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
 return `<div class="tree"><ul>${treeNode(root, "", showDeleted)}</ul></div>`;
}
function treeNode(node, prefix, showDeleted){
 const dirs = Object.keys(node.dirs).sort((a,b)=>a.localeCompare(b));
 const dirHtml = dirs.map(name => {
  const path = prefix ? prefix+"/"+name : name;
  const state = folderState(node.dirs[name]);
  const canRestore = folderChunkCount(node.dirs[name]) > 0;
  const ids = collectNodeFiles(node.dirs[name]).map(file => Number(file.id));
  return `<li class="folder"><details data-path="${esc(path)}"><summary class="tree-row"><input type="checkbox" class="folderSelect" data-file-ids="${esc(ids.join(","))}" onchange="event.stopPropagation();selectFolderFiles(this.dataset.fileIds, this.checked)"><span>&#128193;</span><span class="tree-name">${esc(name)}</span>${statePill(state)}<span class="tree-meta">${countFiles(node.dirs[name])} files &middot; ${formatBytes(node.dirs[name].total_size || 0)}</span><button class="icon-btn" title="Increase folder queue priority" onclick="event.preventDefault();boostFolder(${jsString(path)})">&#8593;</button>${canRestore ? `<button class="icon-btn" title="Restore folder" onclick="event.preventDefault();restoreCatalogFolder(${jsString(path)})">&#8635;</button>` : ""}</summary><ul>${treeNode(node.dirs[name], path, showDeleted)}</ul></details></li>`;
 }).join("");
 const fileHtml = node.files.sort((a,b)=>String(a.display_name).localeCompare(String(b.display_name))).map(file => fileRow(file)).join("");
 return dirHtml + fileHtml;
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
function collectNodeFiles(node){
 return node.files.concat(...Object.values(node.dirs).map(child => collectNodeFiles(child)));
}
function fileRow(file){
 const canQueue = !["backed_up", "deleted", "posting", "queued"].includes(file.state);
 const hasChunks = Number(file.chunk_count || 0) > 0;
 const checked = selectedFiles.has(Number(file.id)) ? "checked" : "";
 const progress = fileProgress(file);
 return `<li><div class="tree-row">
  <input type="checkbox" class="fileSelect" value="${Number(file.id)}" ${checked} onchange="setFileSelected(${Number(file.id)}, this.checked)">
  <span>&#128196;</span>
  <span class="tree-name">${esc(file.display_name)}</span>
  <span class="tree-meta">${formatBytes(file.size)}</span>
  ${statePill(file.state)}
  <span class="tree-meta">${Number(file.chunk_count || 0)} chunks${file.last_verify_at ? ` &middot; verified ${esc(formatDateTime(file.last_verify_at))}` : ""}</span>
  ${progress}
  ${canQueue ? `<button class="icon-btn" title="Queue file" onclick="queueFile(${Number(file.id)})">&#10133;</button>` : ""}
  ${file.state !== "backed_up" && file.state !== "deleted" ? `<button class="icon-btn" title="Increase queue priority" onclick="boostFile(${Number(file.id)})">&#8593;</button>` : ""}
  ${hasChunks ? `<button class="icon-btn" title="Restore file" onclick="restoreCatalogFile(${Number(file.id)})">&#8635;</button>` : ""}
 </div></li>`;
}
function fileProgress(file){
 const active = file.state === "posting" || file.queue_status === "posting";
 if(!active) return "";
 const expected = Math.max(1, Math.ceil(Number(file.size || 0) / Number(settingsCache?.article_size || 786432)));
 const chunks = Number(file.progress_chunks || 0);
 const bytes = Number(file.progress_bytes || 0);
 const pct = Math.min(100, Math.round((chunks / expected) * 100));
 const label = `${chunks}/${expected} chunks · ${formatBytes(bytes)} posted · ${pct}%`;
 return `<div class="file-progress"><div class="progress-track"><div class="progress-fill" style="width:${pct}%"></div></div><span>${esc(label)}</span></div>`;
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
 target.innerHTML = selectedRows.length
  ? `<b>${selectedRows.length}</b> selected &middot; ${formatBytes(totalSize)} &middot; ${restorable} restorable &middot; ${unbacked} unbacked`
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
 const out = await post("/api/files/priority-many", { file_ids:ids, amount:10 });
 if(out.error) alert(out.error);
 await updateFilesPage();
}
async function restoreSelectedFiles(){
 const selectedRows = Array.from(selectedFileData.values()).filter(row => Number(row.chunk_count || 0) > 0);
 if(!selectedRows.length) return alert("Select files with recorded chunks first");
 const dest = prompt("Restore destination folder, blank for original locations", "");
 let restored = 0;
 for(const file of selectedRows){
  const out = await post("/api/restore", { path:file.path, dest:dest || null });
  if(out.error) return alert(out.error);
  restored++;
 }
 alert(`Restored ${restored} files`);
}
async function restoreCatalogFile(fileId){
 const file = fileRowsCache.find(row => Number(row.id) === Number(fileId));
 if(!file) return;
 const dest = prompt("Restore destination, blank for original location", "");
 const out = await post("/api/restore", { path:file.path, dest:dest || null });
 alert(out.error || `Restored to ${out.target}`);
}
async function restoreCatalogFolder(path){
 const dest = prompt("Restore destination for this folder, blank for original locations", "");
 const out = await post("/api/restore", { path:path, dest:dest || null, folder:true });
 alert(out.error || `Restored ${out.restored} files`);
}
async function search(){ document.getElementById("results").innerHTML = table(await api("/api/search?q="+encodeURIComponent(document.getElementById("q").value)), ["id","relative_path","size","state","updated_at"]); }
async function restore(){ const out = await post("/api/restore",{path:restorePath.value,dest:restoreDest.value,folder:restoreFolder.checked}); restoreOut.textContent = JSON.stringify(out,null,2); }
function settingsForm(s){
 return `<div class="tabs">
  ${["General","Usenet","Protection","Schedules","Endpoints","Cloud"].map((name,index)=>`<button class="${index===0?"primary":""}" onclick="showSettingsTab('${name}', this)">${name}</button>`).join("")}
 </div>
 <div id="tabGeneral" class="tab-panel active"><div class="form-grid">
  <label class="field"><span><span class="ui-icon">&#128101;</span>Newsgroup</span><input id="setNewsgroup" value="${esc(s.newsgroup)}"></label>
  <label class="field"><span><span class="ui-icon">&#129513;</span>Article size bytes</span><input id="setArticleSize" type="number" min="1" value="${esc(s.article_size)}"></label>
  <label class="field"><span><span class="ui-icon">&#128225;</span>NNTP threads</span><input id="setNntpThreads" type="number" min="1" max="64" value="${esc(s.nntp_threads || 4)}"></label>
  <label class="field"><span><span class="ui-icon">&#9201;</span>Post limit bytes/hour</span><input id="setHourlyPostLimit" type="number" min="0" value="${esc(s.hourly_post_limit_bytes || 0)}"></label>
 </div></div>
 <div id="tabSchedules" class="tab-panel"><div class="form-grid">
  <label class="field"><span><span class="ui-icon">&#10003;</span>Verify interval days</span><input id="setVerifyDays" type="number" min="1" value="${esc(s.verification_interval_days)}"></label>
  <label class="field"><span><span class="ui-icon">&#10003;</span>Verification task interval seconds</span><input id="setVerifyTaskInterval" type="number" min="1" value="${esc(s.verification_task_interval_seconds || 3600)}"></label>
  <label class="field"><span><span class="ui-icon">&#128196;</span>Files verified per task run</span><input id="setVerifyFilesPerRun" type="number" min="1" value="${esc(s.verification_files_per_run || 1)}"></label>
  <label class="field"><span><span class="ui-icon">&#128193;</span>Catalog scan interval seconds</span><input id="setScanInterval" type="number" min="1" value="${esc(s.scan_interval_seconds || 300)}"></label>
  <label class="field"><span><span class="ui-icon">&#128230;</span>Backup task interval seconds</span><input id="setBackupInterval" type="number" min="1" value="${esc(s.backup_interval_seconds || 300)}"></label>
  <label class="field"><span><span class="ui-icon">&#9729;</span>Cloud backup interval seconds</span><input id="setCloudBackupInterval" type="number" min="1" value="${esc(s.cloud_backup_interval_seconds || 3600)}"></label>
 </div></div>
 <div id="tabProtection" class="tab-panel"><div class="form-grid">
  <label class="field"><span><span class="ui-icon">&#128274;</span>Encryption passphrase env</span><input id="setPassEnv" value="${esc(s.encryption_passphrase_env)}"></label>
  <label><input id="setZip" type="checkbox" ${s.zip_subfolders?"checked":""}> <span class="ui-icon">&#128451;</span>Zip subfolders</label>
  <label><input id="setEncrypt" type="checkbox" ${s.encrypt_bodies?"checked":""}> <span class="ui-icon">&#128274;</span>Encrypt article bodies</label>
  <label><input id="setPar2" type="checkbox" ${s.par2?.enabled?"checked":""}> <span class="ui-icon">&#128737;</span>Generate PAR2 recovery files</label>
  <label class="field"><span><span class="ui-icon">&#9881;</span>PAR2 command</span><input id="setPar2Command" value="${esc(s.par2?.command || "par2")}"></label>
  <label class="field"><span><span class="ui-icon">&#128737;</span>PAR2 redundancy percent</span><input id="setPar2Redundancy" type="number" min="0" value="${esc(s.par2?.redundancy_percent ?? 10)}"></label>
 </div></div>
 <div id="tabEndpoints" class="tab-panel"><div class="form-grid">
 <label class="field full"><span><span class="ui-icon">&#128193;</span>Endpoints, one path per line</span><textarea id="setEndpoints">${esc((s.endpoints || []).join("\n"))}</textarea></label>
  <label class="field full"><span><span class="ui-icon">&#128683;</span>Auto-queue exclude patterns, one per line</span><textarea id="setAutoQueueExcludePatterns">${esc((s.auto_queue_exclude_patterns || []).join("\n"))}</textarea></label>
 </div></div>
 <div id="tabUsenet" class="tab-panel"><div class="form-grid">
  <div class="field full"><span><span class="ui-icon">&#128225;</span>Usenet hosts</span><div id="hostList" class="host-list">${hostRows(s.usenet_hosts || [])}</div></div>
 </div></div>
 <div id="tabCloud" class="tab-panel"><div class="form-grid">
  <div class="field full"><span><span class="ui-icon">&#9729;</span>Cloud backup targets</span><div id="cloudList" class="host-list">${cloudRows(s.cloud_backups || [])}</div></div>
 </div></div>
 <div class="toolbar"><button onclick="addHost()"><span class="ui-icon">&#10133;</span>Add host</button><button onclick="addCloudTarget()"><span class="ui-icon">&#10133;</span>Add cloud target</button><button onclick="post('/api/cloud-backup').then(out=>settingsOut.textContent=JSON.stringify(out,null,2))"><span class="ui-icon">&#9729;</span>Backup config/db now</button><button class="primary" onclick="saveSettings()"><span class="ui-icon">&#128190;</span>Save settings</button><button onclick="render()"><span class="ui-icon">&#8635;</span>Reset</button></div>
 <pre id="settingsOut"></pre>`;
}
function showSettingsTab(name, button){
 document.querySelectorAll(".tab-panel").forEach(panel => panel.classList.remove("active"));
 document.getElementById("tab"+name).classList.add("active");
 document.querySelectorAll(".tabs button").forEach(tab => tab.classList.remove("primary"));
 button.classList.add("primary");
}
function hostRows(hosts){
 return hosts.map((host, index) => hostRow(host, index)).join("") || hostRow({ name:"", mode:"read", host:"", port:563, tls:"implicit", username:"", password:"" }, 0);
}
function hostRow(host, index){
 return `<div class="host-row" data-host-index="${index}">
  <div class="toolbar"><h3><span class="ui-icon">&#128225;</span>Host ${index + 1}</h3><button class="danger" onclick="removeHost(this)"><span class="ui-icon">&#128465;</span>Remove</button></div>
  <div class="host-grid">
   <label class="field"><span><span class="ui-icon">&#128278;</span>Name</span><input class="hostName" value="${esc(host.name)}" placeholder="eweka-read"></label>
   <label class="field"><span><span class="ui-icon">&#8644;</span>Mode</span><select class="hostMode"><option value="read" ${host.mode==="read"?"selected":""}>read</option><option value="post" ${host.mode==="post"?"selected":""}>post</option></select></label>
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
 list.insertAdjacentHTML("beforeend", hostRow({ name:"", mode:"read", host:"", port:563, tls:"implicit", username:"", password:"" }, index));
 renumberHosts();
}
function addCloudTarget(){
 const list = document.getElementById("cloudList");
 const index = list.querySelectorAll(".cloud-row").length;
 list.insertAdjacentHTML("beforeend", cloudRow({ name:"", provider:"local", target:"", command:"", enabled:true }, index));
 renumberCloudTargets();
}
function removeCloudTarget(button){
 button.closest(".cloud-row").remove();
 if(!document.querySelector(".cloud-row")) addCloudTarget();
 renumberCloudTargets();
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
async function saveSettings(){
 const payload = {
  newsgroup: setNewsgroup.value,
  article_size: Number(setArticleSize.value),
  verification_interval_days: Number(setVerifyDays.value),
  verification_task_interval_seconds: Number(setVerifyTaskInterval.value),
  verification_files_per_run: Number(setVerifyFilesPerRun.value),
  scan_interval_seconds: Number(setScanInterval.value),
  backup_interval_seconds: Number(setBackupInterval.value),
  cloud_backup_interval_seconds: Number(setCloudBackupInterval.value),
  nntp_threads: Number(setNntpThreads.value),
  hourly_post_limit_bytes: Number(setHourlyPostLimit.value),
  zip_subfolders: setZip.checked,
  encrypt_bodies: setEncrypt.checked,
  encryption_passphrase_env: setPassEnv.value,
  endpoints: setEndpoints.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean),
  auto_queue_exclude_patterns: setAutoQueueExcludePatterns.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean),
  usenet_hosts: collectHosts(),
  cloud_backups: collectCloudTargets(),
  par2: { enabled: setPar2.checked, command: setPar2Command.value, redundancy_percent: Number(setPar2Redundancy.value) }
 };
 const out = await post("/api/settings", payload);
 settingsOut.textContent = JSON.stringify(out, null, 2);
 if(out.ok) settingsCache = out.settings;
}
render();
</script>
</body>
</html>"""
