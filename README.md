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
- Automatic post-host article-size probes to learn the largest body size the
  provider accepts before tuning large-scale backup chunking.
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
backuprr --config config.json init
backuprr --config config.json add-endpoint /srv/media/movies
backuprr --config config.json scan
backuprr --config config.json web --host 0.0.0.0 --port 8080
```

On CentOS Stream, run the service behind a firewall or reverse proxy and use a
systemd unit to start `backuprr web`.

## Docker

Build and run the container locally:

```bash
mkdir -p data
cp config.example.json data/config.json
docker compose up -d --build
```

The compose file stores config and the SQLite database in `./data` and mounts
media at `/media` inside the container. Add endpoints in the Web UI using the
container path, for example `/media/movies`, not the host path.

For a direct `docker run` deployment:

```bash
docker build -t backuprr:local .
docker run -d \
  --name backuprr \
  --restart unless-stopped \
  -p 8080:8080 \
  -e BACKUPRR_CONFIG=/data/config.json \
  -v "$(pwd)/data:/data" \
  -v "/srv/media:/media:rw" \
  backuprr:local
```

### Portainer

In Portainer, create a new Stack and paste this compose template. Change the
host media path before deploying:

```yaml
services:
  backuprr:
    image: backuprr:local
    build: .
    container_name: backuprr
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      BACKUPRR_CONFIG: /data/config.json
    volumes:
      - /opt/backuprr/data:/data
      - /srv/media:/media:rw
```

Create `/opt/backuprr/data/config.json` first, or bind a directory containing
your existing `config.json`. Set `"database": "/data/backuprr.sqlite3"` in that
config so the catalog persists across container upgrades.

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
backuprr --config config.json init
backuprr --config config.json add-endpoint /srv/media/series
backuprr --config config.json scan
backuprr --config config.json status
backuprr --config config.json queue list
backuprr --config config.json queue prioritize --filter older-first
backuprr --config config.json post-next
backuprr --config config.json verify
backuprr --config config.json dry-run
backuprr --config config.json health-check
backuprr --config config.json article-size-test
backuprr --config config.json maintenance --vacuum
backuprr --config config.json restore-drill
backuprr --config config.json pause backup
backuprr --config config.json resume backup
backuprr --config config.json restore --path /srv/media/movie/file.mkv --dest /restore-test
backuprr --config config.json web
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

The provider health check automatically posts disposable obfuscated probe
articles to each configured post host and records the largest accepted article
body size. You can run only that probe with `backuprr article-size-test`.

Body encryption uses a passphrase-derived HMAC-SHA256 keystream implemented with
the Python standard library. For high-assurance environments, integrate a
dedicated audited encryption package before storing sensitive data offsite.

PAR2 support is implemented as an external command hook. Configure `par2` in
`config.json` if installed on the CentOS host.

## Development

```bash
python -m unittest discover -s tests
```
