import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import __version__
from .backup import verify_due_chunks
from .config import Config, update_config
from .db import Database
from .monitor import BackupMonitor, CatalogMonitor
from .queueing import enqueue_unbacked, move, prioritize
from .restore import restore_file, restore_folder


def rowdicts(rows):
    return [dict(row) for row in rows]


class Handler(BaseHTTPRequestHandler):
    config: Config
    config_path: str
    db: Database
    monitor: CatalogMonitor
    backup_monitor: BackupMonitor

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
            self.send_json(
                {
                    "version": __version__,
                    "stats": self.db.stats(),
                    "scan_interval_seconds": self.config.scan_interval_seconds,
                    "backup_interval_seconds": self.config.backup_interval_seconds,
                }
            )
        elif parsed.path == "/api/files":
            self.send_json(rowdicts(self.db.list_rows("files", int(query.get("limit", ["200"])[0]))))
        elif parsed.path == "/api/search":
            self.send_json(rowdicts(self.db.search_files(query.get("q", [""])[0])))
        elif parsed.path == "/api/log":
            levels = query.get("level", [])
            if not levels and query.get("levels"):
                levels = [item for group in query.get("levels", []) for item in group.split(",")]
            self.send_json(rowdicts(self.db.list_events(levels, int(query.get("limit", ["300"])[0]))))
        elif parsed.path == "/api/queue":
            with self.db.connect() as conn:
                rows = conn.execute(
                    """
                    SELECT q.*, f.path, f.size, f.state FROM queue q
                    JOIN files f ON f.id = q.file_id
                    ORDER BY q.priority ASC, q.position ASC
                    """
                ).fetchall()
            self.send_json(rowdicts(rows))
        elif parsed.path == "/api/tasks":
            self.send_json(self.monitor.tasks() + self.backup_monitor.tasks())
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
                self.send_json({"queued": enqueue_unbacked(self.db)})
            elif parsed.path == "/api/queue/prioritize":
                self.send_json({"changed": prioritize(self.db, data.get("filter", "older-first"))})
            elif parsed.path == "/api/queue/move":
                move(self.db, int(data["file_id"]), int(data["position"]))
                self.send_json({"ok": True})
            elif parsed.path == "/api/files/queue":
                self.db.queue_file(int(data["file_id"]), priority=int(data.get("priority", 100)), reason="manual")
                self.send_json({"ok": True})
            elif parsed.path == "/api/post-next":
                self.send_json({"file_id": self.backup_monitor.post_once()})
            elif parsed.path == "/api/verify":
                self.send_json({"verified": verify_due_chunks(self.db, self.config, force=bool(data.get("force")))})
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


def run_web(config: Config, db: Database, host: str, port: int) -> None:
    Handler.config = config
    Handler.config_path = str(config.source_path or (config.base_dir / "config.json"))
    Handler.db = db
    Handler.monitor = CatalogMonitor(db, config)
    Handler.backup_monitor = BackupMonitor(db, config)
    Handler.monitor.start()
    Handler.backup_monitor.start()
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Backuprr {__version__} listening on http://{host}:{port}")
    try:
        server.serve_forever()
    finally:
        Handler.monitor.stop()
        Handler.backup_monitor.stop()


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
.stat { background:#fff; border:1px solid var(--line); border-radius:8px; padding:12px; }
.stat b { display:block; font-size:24px; }
.dashboard { display:grid; gap:14px; }
.hero-status { background:#fff; border:1px solid var(--line); border-radius:8px; padding:14px; display:grid; gap:10px; }
.hero-status h2 { margin:0; font-size:20px; }
.task-strip { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:10px; }
.task-card { background:#fff; border:1px solid var(--line); border-radius:8px; padding:12px; display:grid; gap:6px; }
.task-card h3 { margin:0; font-size:14px; }
.badge { display:inline-flex; align-items:center; width:max-content; padding:3px 7px; border-radius:999px; background:#e8f3f1; color:var(--accent); font-size:12px; font-weight:700; }
.badge.running { background:#fff7ed; color:var(--warn); }
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
.refresh-note { margin-left:auto; }
.form-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:12px; margin-bottom:12px; }
.field { display:grid; gap:5px; }
.field span { color:var(--muted); font-size:12px; font-weight:600; }
.full { grid-column:1 / -1; }
.host-list { display:grid; gap:12px; }
.host-row { border:1px solid var(--line); background:#fff; border-radius:8px; padding:12px; }
.host-row h3 { margin:0 0 10px; font-size:14px; }
.host-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:10px; }
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
const pages = ["Status","Files","Search","Log","Queue","Tasks","Restore","Settings","About"];
let page = "Status";
let settingsCache = null;
let fileRowsCache = [];
let logLevelSelection = ["error","warning","info","verbose"];
let logLimitSelection = "300";
let refreshTimer = null;
const refreshPages = new Set(["Status","Files","Log","Queue","Tasks"]);
const refreshMs = 5000;
const api = (url, opts={}) => fetch(url, {headers:{"Content-Type":"application/json"}, ...opts}).then(r => r.json());
const post = (url, body={}) => api(url, {method:"POST", body:JSON.stringify(body)});
function esc(v){ return String(v ?? "").replace(/[&<>"']/g, s => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[s])); }
function table(rows, cols){
 if(!rows.length) return "<p class='muted'>No rows.</p>";
 return `<table><thead><tr>${cols.map(c=>`<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>`+
 rows.map(r=>`<tr>${cols.map(c=>`<td>${esc(r[c])}</td>`).join("")}</tr>`).join("")+"</tbody></table>";
}
function nav(){
 document.getElementById("nav").innerHTML = pages.map(p=>`<button class="${p===page?"active":""}" onclick="page='${p}';render()"> ${p}</button>`).join("");
}
function scheduleRefresh(){
 if(refreshTimer) clearInterval(refreshTimer);
 refreshTimer = null;
 if(refreshPages.has(page)){
  refreshTimer = setInterval(() => render({ passive:true }), refreshMs);
 }
}
function refreshLabel(){
 return refreshPages.has(page) ? `<span class="muted refresh-note">Auto-refresh ${Math.round(refreshMs/1000)}s</span>` : "";
}
async function render(){
 nav();
 scheduleRefresh();
 const c = document.getElementById("content");
 if(page==="Status"){
  const s = await api("/api/status");
  const tasks = await api("/api/tasks");
  document.getElementById("version").textContent = "v"+s.version;
  c.innerHTML = statusDashboard(s, tasks);
 }
 if(page==="Files"){
  fileRowsCache = await api("/api/files?limit=5000");
  c.innerHTML = `<div class="toolbar"><button onclick="render()">&#8635;</button><button class="primary" onclick="post('/api/post-next').then(render)">&#9658; Post next</button>${refreshLabel()}</div>${fileTree(fileRowsCache)}`;
 }
 if(page==="Search"){
  c.innerHTML = `<div class="toolbar"><input id="q" placeholder="Search files"><button onclick="search()">Search</button></div><div id="results"></div>`;
 }
 if(page==="Log"){
  const levels = ["error","warning","info","verbose"];
  c.innerHTML = `<div class="toolbar">
   ${levels.map(level=>`<label><input class="logLevel" type="checkbox" value="${level}" ${logLevelSelection.includes(level) ? "checked" : ""}> ${level}</label>`).join("")}
   <select id="logLimit"><option ${logLimitSelection==="100"?"selected":""}>100</option><option ${logLimitSelection==="300"?"selected":""}>300</option><option ${logLimitSelection==="1000"?"selected":""}>1000</option></select>
   <button onclick="loadLog()">Apply</button>${refreshLabel()}
  </div><div id="logRows"></div>`;
  await loadLog();
 }
 if(page==="Queue"){
  const rows = await api("/api/queue");
  c.innerHTML = `<div class="toolbar"><select id="filter"><option>older-first</option><option>larger-first</option><option>smaller-first</option></select><button onclick="post('/api/queue/prioritize',{filter:document.getElementById('filter').value}).then(render)">Apply filter</button><button class="primary" onclick="post('/api/post-next').then(render)">Post next</button>${refreshLabel()}</div>`+
  table(rows, ["file_id","position","priority","status","reason","path","size","state"]);
 }
 if(page==="Tasks"){
 const rows = await api("/api/tasks");
  c.innerHTML = `<div class="toolbar"><button onclick="render()">Refresh</button><button class="primary" onclick="post('/api/scan').then(render)">Run catalog scan</button>${refreshLabel()}</div>`+
  table(rows, ["name","kind","status","interval_seconds","last_run","last_run_duration","time_until_next_run","runs","last_result","last_error"]);
 }
 if(page==="Restore"){
  c.innerHTML = `<div class="toolbar"><input id="restorePath" placeholder="File or folder path"><input id="restoreDest" placeholder="Optional destination"><label><input id="restoreFolder" type="checkbox"> Folder</label><button class="primary" onclick="restore()">Restore</button></div><pre id="restoreOut"></pre>`;
 }
 if(page==="Settings"){ settingsCache = await api("/api/settings"); c.innerHTML = settingsForm(settingsCache); }
 if(page==="About"){ c.innerHTML = `<h1>Backuprr</h1><p>Version <span id="aboutVersion"></span></p><p>Catalog media folders, post obfuscated Usenet backups, verify article availability, and restore files when needed.</p>`; const s=await api("/api/status"); document.getElementById("aboutVersion").textContent=s.version; }
}
function statusDashboard(status, tasks){
 const stats = status.stats || {};
 const total = Number(stats.files_total || 0);
 const backed = Number(stats.files_backed_up || 0);
 const queued = Number(stats.files_queued || 0);
 const posting = Number(stats.files_posting || 0);
 const deleted = Number(stats.files_deleted || 0);
 const chunks = Number(stats.chunks_total || 0);
 const doneQueue = Number(stats.queue_done || 0);
 const queuedQueue = Number(stats.queue_queued || 0);
 const postingQueue = Number(stats.queue_posting || 0);
 const protectedPct = total ? Math.round((backed / total) * 100) : 0;
 const activeTask = tasks.find(task => task.status === "running");
 const nextTask = tasks
  .filter(task => task.status !== "running" && task.time_until_next_run)
  .sort((a,b) => secondsFromLabel(a.time_until_next_run) - secondsFromLabel(b.time_until_next_run))[0];
 return `<div class="dashboard">
  <div class="toolbar"><button class="primary" onclick="post('/api/scan').then(render)">&#8635; Scan now</button><button onclick="post('/api/queue/enqueue-unbacked').then(render)">&#10133; Queue unbacked</button><button onclick="post('/api/verify',{force:true}).then(render)">&#10003; Verify chunks</button>${refreshLabel()}</div>
  <div class="hero-status">
   <h2>${esc(activeTask ? `${activeTask.name} is running` : "Backuprr is standing by")}</h2>
   <div class="muted">${esc(activeTask ? activeTask.last_result || "Working through the current task" : nextTask ? `Next: ${nextTask.name} in ${nextTask.time_until_next_run}` : "No scheduled task time reported")}</div>
   <div class="progress-track"><div class="progress-fill" style="width:${protectedPct}%"></div></div>
   <div>${protectedPct}% backed up · ${backed} of ${total} files protected · ${queued + posting} waiting or posting · ${chunks} chunks posted</div>
  </div>
  <div class="task-strip">${tasks.map(taskCard).join("")}</div>
  <div class="stats">
   ${statCard("Files", total)}
   ${statCard("Backed up", backed)}
   ${statCard("Queued", queued)}
   ${statCard("Posting", posting)}
   ${statCard("Deleted", deleted)}
   ${statCard("Chunks", chunks)}
  </div>
  <div class="chart-grid">
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
  </div>
 </div>`;
}
function statCard(label, value){
 return `<div class="stat"><span>${esc(label)}</span><b>${esc(value)}</b></div>`;
}
function taskCard(task){
 const running = task.status === "running";
 return `<div class="task-card">
  <h3>${esc(task.name)}</h3>
  <span class="badge ${running ? "running" : ""}">${esc(task.status)}</span>
  <div class="muted">Last run: ${esc(task.last_run || "not yet")}</div>
  <div>Duration: ${esc(task.last_run_duration || "-")}</div>
  <div>Next run: ${esc(task.time_until_next_run || "-")}</div>
  <div class="${task.last_error ? "error" : "muted"}">${esc(task.last_error || task.last_result || "")}</div>
 </div>`;
}
function barChart(title, rows){
 const max = Math.max(1, ...rows.map(row => Number(row[1] || 0)));
 return `<div class="chart-card"><h3>${esc(title)}</h3>${rows.map(([label, value, tone]) => {
  const width = Math.max(0, Math.round((Number(value || 0) / max) * 100));
  return `<div class="bar-row"><span>${esc(label)}</span><div class="bar-track"><div class="bar-fill ${tone === "bad" ? "bad" : tone === "warn" ? "warn" : ""}" style="width:${width}%"></div></div><b>${esc(value)}</b></div>`;
 }).join("")}</div>`;
}
function secondsFromLabel(label){
 const text = String(label || "");
 const h = Number((text.match(/(\d+)h/) || [0,0])[1]);
 const m = Number((text.match(/(\d+)m/) || [0,0])[1]);
 const s = Number((text.match(/(\d+)s/) || [0,0])[1]);
 return h * 3600 + m * 60 + s;
}
async function loadLog(){
 logLevelSelection = Array.from(document.querySelectorAll(".logLevel:checked")).map(input => input.value);
 logLimitSelection = document.getElementById("logLimit").value;
 const levels = logLevelSelection.map(level => "level="+encodeURIComponent(level)).join("&");
 const limit = encodeURIComponent(logLimitSelection);
 document.getElementById("logRows").innerHTML = table(await api(`/api/log?limit=${limit}&${levels}`), ["id","ts","level","event_type","message","file_id"]);
}
function fileTree(rows){
 const root = { dirs:{}, files:[] };
 for(const row of rows){
  const parts = String(row.relative_path || row.path || "").split(/[\\/]+/).filter(Boolean);
  let node = root;
  for(const part of parts.slice(0, -1)){
   node.dirs[part] = node.dirs[part] || { dirs:{}, files:[] };
   node = node.dirs[part];
  }
  node.files.push({...row, display_name: parts[parts.length - 1] || row.path});
 }
 return `<div class="tree"><ul>${treeNode(root, "")}</ul></div>`;
}
function treeNode(node, prefix){
 const dirs = Object.keys(node.dirs).sort((a,b)=>a.localeCompare(b));
 const dirHtml = dirs.map(name => `<li class="folder"><div class="tree-row"><span>&#128193;</span><span class="tree-name">${esc(name)}</span><span class="tree-meta">${countFiles(node.dirs[name])} files</span></div><ul>${treeNode(node.dirs[name], prefix ? prefix+"/"+name : name)}</ul></li>`).join("");
 const fileHtml = node.files.sort((a,b)=>String(a.display_name).localeCompare(String(b.display_name))).map(file => fileRow(file)).join("");
 return dirHtml + fileHtml;
}
function countFiles(node){
 return node.files.length + Object.values(node.dirs).reduce((total, child) => total + countFiles(child), 0);
}
function fileRow(file){
 const stateClass = file.state === "deleted" ? "error" : "muted";
 return `<li><div class="tree-row">
  <span>&#128196;</span>
  <span class="tree-name">${esc(file.display_name)}</span>
  <span class="tree-meta">${esc(file.size)} bytes</span>
  <span class="tree-meta ${stateClass}">${esc(file.state)}</span>
  <button class="icon-btn" title="Queue file" onclick="queueFile(${Number(file.id)})">&#10133;</button>
  <button class="icon-btn" title="Restore file" onclick="restoreCatalogFile(${Number(file.id)})">&#8635;</button>
 </div></li>`;
}
async function queueFile(fileId){
 const out = await post("/api/files/queue", { file_id:fileId });
 if(!out.ok) alert(out.error || "Unable to queue file");
 await render();
}
async function restoreCatalogFile(fileId){
 const file = fileRowsCache.find(row => Number(row.id) === Number(fileId));
 if(!file) return;
 const dest = prompt("Restore destination, blank for original location", "");
 const out = await post("/api/restore", { path:file.path, dest:dest || null });
 alert(out.error || `Restored to ${out.target}`);
}
async function search(){ document.getElementById("results").innerHTML = table(await api("/api/search?q="+encodeURIComponent(document.getElementById("q").value)), ["id","relative_path","size","state","updated_at"]); }
async function restore(){ const out = await post("/api/restore",{path:restorePath.value,dest:restoreDest.value,folder:restoreFolder.checked}); restoreOut.textContent = JSON.stringify(out,null,2); }
function settingsForm(s){
 return `<div class="form-grid">
  <label class="field"><span>Newsgroup</span><input id="setNewsgroup" value="${esc(s.newsgroup)}"></label>
  <label class="field"><span>Article size bytes</span><input id="setArticleSize" type="number" min="1" value="${esc(s.article_size)}"></label>
  <label class="field"><span>Verify interval days</span><input id="setVerifyDays" type="number" min="1" value="${esc(s.verification_interval_days)}"></label>
  <label class="field"><span>Catalog scan interval seconds</span><input id="setScanInterval" type="number" min="1" value="${esc(s.scan_interval_seconds || 300)}"></label>
  <label class="field"><span>Backup task interval seconds</span><input id="setBackupInterval" type="number" min="1" value="${esc(s.backup_interval_seconds || 300)}"></label>
  <label class="field"><span>Encryption passphrase env</span><input id="setPassEnv" value="${esc(s.encryption_passphrase_env)}"></label>
  <label><input id="setZip" type="checkbox" ${s.zip_subfolders?"checked":""}> Zip subfolders</label>
  <label><input id="setEncrypt" type="checkbox" ${s.encrypt_bodies?"checked":""}> Encrypt article bodies</label>
  <label><input id="setPar2" type="checkbox" ${s.par2?.enabled?"checked":""}> Generate PAR2 recovery files</label>
  <label class="field"><span>PAR2 command</span><input id="setPar2Command" value="${esc(s.par2?.command || "par2")}"></label>
  <label class="field"><span>PAR2 redundancy percent</span><input id="setPar2Redundancy" type="number" min="0" value="${esc(s.par2?.redundancy_percent ?? 10)}"></label>
  <label class="field full"><span>Endpoints, one path per line</span><textarea id="setEndpoints">${esc((s.endpoints || []).join("\n"))}</textarea></label>
  <div class="field full"><span>Usenet hosts</span><div id="hostList" class="host-list">${hostRows(s.usenet_hosts || [])}</div></div>
 </div>
 <div class="toolbar"><button onclick="addHost()">Add host</button><button class="primary" onclick="saveSettings()">Save settings</button><button onclick="render()">Reset</button></div>
 <pre id="settingsOut"></pre>`;
}
function hostRows(hosts){
 return hosts.map((host, index) => hostRow(host, index)).join("") || hostRow({ name:"", mode:"read", host:"", port:563, tls:"implicit", username:"", password:"" }, 0);
}
function hostRow(host, index){
 return `<div class="host-row" data-host-index="${index}">
  <div class="toolbar"><h3>Host ${index + 1}</h3><button class="danger" onclick="removeHost(this)">Remove</button></div>
  <div class="host-grid">
   <label class="field"><span>Name</span><input class="hostName" value="${esc(host.name)}" placeholder="eweka-read"></label>
   <label class="field"><span>Mode</span><select class="hostMode"><option value="read" ${host.mode==="read"?"selected":""}>read</option><option value="post" ${host.mode==="post"?"selected":""}>post</option></select></label>
   <label class="field"><span>Server</span><input class="hostServer" value="${esc(host.host)}" placeholder="news.example.com"></label>
   <label class="field"><span>Port</span><input class="hostPort" type="number" min="1" value="${esc(host.port || 563)}"></label>
   <label class="field"><span>TLS mode</span><select class="hostTls"><option value="implicit" ${host.tls==="implicit"?"selected":""}>implicit</option><option value="starttls" ${host.tls==="starttls"?"selected":""}>starttls</option><option value="plain" ${host.tls==="plain"?"selected":""}>plain</option></select></label>
   <label class="field"><span>Username</span><input class="hostUsername" value="${esc(host.username || "")}" autocomplete="off"></label>
   <label class="field"><span>Password</span><input class="hostPassword" type="password" value="${esc(host.password || "")}" autocomplete="new-password" placeholder="leave blank to keep existing"></label>
  </div>
 </div>`;
}
function addHost(){
 const list = document.getElementById("hostList");
 const index = list.querySelectorAll(".host-row").length;
 list.insertAdjacentHTML("beforeend", hostRow({ name:"", mode:"read", host:"", port:563, tls:"implicit", username:"", password:"" }, index));
 renumberHosts();
}
function removeHost(button){
 button.closest(".host-row").remove();
 if(!document.querySelector(".host-row")) addHost();
 renumberHosts();
}
function renumberHosts(){
 document.querySelectorAll(".host-row").forEach((row, index) => {
  row.dataset.hostIndex = index;
  row.querySelector("h3").textContent = `Host ${index + 1}`;
 });
}
function collectHosts(){
 return Array.from(document.querySelectorAll(".host-row")).map(row => ({
  name: row.querySelector(".hostName").value.trim(),
  mode: row.querySelector(".hostMode").value,
  host: row.querySelector(".hostServer").value.trim(),
  port: Number(row.querySelector(".hostPort").value),
  tls: row.querySelector(".hostTls").value,
  username: row.querySelector(".hostUsername").value.trim() || null,
  password: row.querySelector(".hostPassword").value || null
 })).filter(host => host.name || host.host);
}
async function saveSettings(){
 const payload = {
  newsgroup: setNewsgroup.value,
  article_size: Number(setArticleSize.value),
  verification_interval_days: Number(setVerifyDays.value),
  scan_interval_seconds: Number(setScanInterval.value),
  backup_interval_seconds: Number(setBackupInterval.value),
  zip_subfolders: setZip.checked,
  encrypt_bodies: setEncrypt.checked,
  encryption_passphrase_env: setPassEnv.value,
  endpoints: setEndpoints.value.split(/\r?\n/).map(v => v.trim()).filter(Boolean),
  usenet_hosts: collectHosts(),
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
