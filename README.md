# Backuprr

Backuprr catalogs movie and series folders and backs them up to Usenet without
keeping permanent local backup archives. It provides the same operations through
a CLI and an AJAX-enabled Web UI.

![Backuprr Status dashboard](docs/screenshots/status-dashboard.png)

## Features

- SQLite catalog of watched endpoints and all files below them.
- Automatic catalog scans on service startup, after endpoint changes, and on a
  configurable interval.
- Automatic queueing of unbacked files and scheduled Usenet backup posting.
- File state tracking: discovered, changed, queued, posting, backed up,
  verifying, missing chunks, failed, and restored.
- Verbose event log persisted in the database.
- Priority queue with manual ordering and filter-based prioritization.
- Multiple Usenet hosts for read and post modes.
- Plain NNTP, STARTTLS, and implicit TLS.
- Obfuscated post subjects.
- Optional body encryption, zip grouping for subfolders, and PAR2 generation
  hooks.
- Periodic chunk existence checks, defaulting to 90 days per file and spread
  across worker runs by each file's last verification or backup time.
- Restore support for individual files and folders to the original location or
  an alternate destination.
- Web pages for Status, Files, Search, Log, Queue, Tasks, Verification,
  Statistics, Settings, and About.
- Live-refreshing operational pages and a Status dashboard with task progress,
  queue/file summaries, and simple charts.
- Operations page and CLI commands for worker pause/resume, provider health
  checks, dry-run planning, database maintenance, and restore drills.
- Backup run history, host health history, maintenance history, and restore
  drill history for production troubleshooting.
- Chunk-level hourly throttling, resumable posts, and retry/failover across
  configured post hosts.
- Volume controls for large catalogs: web access logs and successful per-chunk
  logs are disabled by default, transfer samples are bucketed, and new chunk
  rows omit debug-only subject/body-hash metadata unless explicitly enabled.
- CLI commands matching the Web UI operations.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
cp config.example.json config.json
backuprr init --config config.json
backuprr add-endpoint /srv/media/movies --config config.json
backuprr scan --config config.json
backuprr web --config config.json --host 0.0.0.0 --port 8080
```

On CentOS Stream, run the service behind a firewall or reverse proxy and use a
systemd unit to start `backuprr web`.

## Configuration

Do not commit real credentials. `config.json` is ignored by Git and stores the
direct provider username/password used for NNTP authentication:

```json
{
  "database": "backuprr.sqlite3",
  "article_size": 786432,
  "newsgroup": "alt.binaries.backup",
  "verification_interval_days": 90,
  "verification_task_interval_seconds": 3600,
  "verification_files_per_run": 1,
  "scan_interval_seconds": 300,
  "backup_interval_seconds": 300,
  "usenet_hosts": [
    {
      "name": "eweka-read",
      "mode": "read",
      "host": "news.eweka.nl",
      "port": 563,
      "tls": "implicit",
      "username": "your-user",
      "password": "your-password"
    },
    {
      "name": "eweka-post",
      "mode": "post",
      "host": "post.eweka.nl",
      "port": 563,
      "tls": "implicit",
      "username": "your-user",
      "password": "your-password"
    }
  ],
  "endpoints": []
}
```

## CLI

```bash
backuprr init --config config.json
backuprr add-endpoint /srv/media/series --config config.json
backuprr scan --config config.json
backuprr status --config config.json
backuprr queue list --config config.json
backuprr queue prioritize --filter older-first --config config.json
backuprr post-next --config config.json
backuprr verify --config config.json
backuprr dry-run --config config.json
backuprr health-check --config config.json
backuprr maintenance --vacuum --config config.json
backuprr restore-drill --config config.json
backuprr pause backup --config config.json
backuprr resume backup --config config.json
backuprr restore --path /srv/media/movie/file.mkv --dest /restore-test --config config.json
backuprr web --config config.json
```

## Notes on Usenet posting

Backuprr streams files into article-sized chunks and posts each chunk with an
obfuscated subject. It stores article message IDs and chunk metadata in SQLite.
Temporary zip/PAR2 artifacts are created in the OS temp directory only for the
duration of a run and are deleted afterward.

At multi-terabyte scale, chunk row count is the main durable catalog cost. Use
larger article sizes, such as 2-5 MiB where your provider accepts them, to
reduce chunk rows. Keep compact chunk metadata enabled unless you are debugging
subject/hash generation.

Body encryption uses a passphrase-derived HMAC-SHA256 keystream implemented with
the Python standard library. For high-assurance environments, integrate a
dedicated audited encryption package before storing sensitive data offsite.

PAR2 support is implemented as an external command hook. Configure `par2` in
`config.json` if installed on the CentOS host.

## Development

```bash
python -m unittest discover -s tests
```
