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
- Optional body encryption, compression before posting, and PAR2 generation
  hooks.
- Periodic chunk existence checks, defaulting to 90 days per file and spread
  across worker runs by each file's last verification or backup time.
- Restore support for individual files and folders to the original location or
  an alternate destination.
- Web pages for Status, Files, Search, Log, Queue, Tasks, Verification,
  Statistics, Operations, Security, Settings, and About.
- Live-refreshing operational pages and a Status dashboard with task progress,
  queue/file summaries, and simple charts.
- Operations page and CLI commands for worker pause/resume, provider health
  checks, dry-run planning, database maintenance, and restore drills.
- Scale planning tools for synthetic catalog benchmarks, disaster recovery
  readiness checks, Prometheus metrics, and container health checks.
- Automatic post-host article-size probes to learn the largest body size the
  provider accepts before tuning large-scale backup chunking.
- Backup run history, host health history, maintenance history, and restore
  drill history for production troubleshooting.
- Daily GitHub release checks with Status/Tasks visibility and manual run
  controls.
- Setup health checks, preflight warnings, alert cards, and a redacted
  diagnostics export for easier troubleshooting.
- Optional Web UI Basic Auth plus opt-in config secret protection using
  `BACKUPRR_CONFIG_SECRET` or a configured key environment variable.
- Role-gated Web UI actions, signed audit events, restore sandbox validation,
  integrity receipts, encrypted manifest exports, provider confidence scoring,
  and database growth projections for safer long-term operation.
- Chunk-level hourly throttling, resumable posts, and retry/failover across
  configured post hosts.
- Safety backpressure can pause the backup worker after provider, auth, or tool
  failures so large queues do not churn through repeated errors unattended.
- Volume controls for large catalogs: web access logs and successful per-chunk
  logs are disabled by default, transfer samples are bucketed, and new chunk
  rows omit debug-only subject/body-hash metadata unless explicitly enabled.
- Safety-first chunk row compaction: in-progress posts keep durable per-chunk
  rows for restart recovery, while completed files can compact those rows into
  a compressed per-file manifest to shrink the database at multi-TB scale.
- Production hardening controls: CSRF-protected internal actions, API rate
  limits, operation cancellation, incident mode, provider failover simulation,
  restore rehearsal, queue pause patterns, settings profile import/export, and
  a threat model page for deployment review.
- Operator safety and UX controls: scoped external API keys, optional TOTP
  step-up for admin actions, read-only mode, global health bar, command
  palette, restore preflight warnings, backup readiness scoring, provider
  capability cards, maintenance visibility, reduced-motion mode, and config
  change history.
- CLI commands matching the Web UI operations.

## Application flow

```mermaid
flowchart LR
    A[Watch endpoints] --> B[Catalog files]
    B --> C[Queue unprotected files]
    C --> D[Prepare payload]
    D --> E{Compression enabled?}
    E -->|Yes, file is suitable| F[Stream gzip payload or create temp payload for PAR2]
    E -->|No or already compressed| G[Use original payload]
    F --> H{PAR2 enabled?}
    G --> H
    H -->|Yes| I[Generate recovery data for payload]
    H -->|No| J[Split into articles]
    I --> J
    J --> K[Encrypt body if enabled]
    K --> L[Post obfuscated subjects to Usenet hosts]
    L --> M[Record chunks, sizes, manifests, and progress]
    M --> N[Scheduled per-file verification]
    N -->|Chunks missing| C
    N -->|Chunks present| O[Ready for restore]
    O --> P[Restore to origin, alternate path, or browser download]
```

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
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
sudo chown -R 10001:10001 data
docker compose up -d --build
```

On first start, Backuprr creates `./data/config.json` if it does not already
exist. The compose file stores config and the SQLite database in `./data` and
mounts media at `/media` inside the container. Add endpoints in the Web UI using
the container path, for example `/media/movies`, not the host path.
The container runs as UID `10001`; the `data` directory must be writable by
that UID so SQLite can create and update `/data/backuprr.sqlite3`.

For large catalog testing, bind a generated media tree into `/media` and keep
the database on a persistent volume. Backuprr is designed to scan incrementally,
avoid rehashing unchanged files, and spread verification work across files based
on each file's last confirmed chunk state.

Both the Dockerfile and compose stack include a `/healthz` health check. The
Web UI also exposes Prometheus text metrics at `/metrics`.

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

### Docker Compose From Scratch

These instructions assume a fresh Linux host or VM where Docker will run
Backuprr directly. Replace `/srv/media` with the folder that contains the media
tree you want Backuprr to catalog, and replace `/opt/backuprr` if you prefer a
different application directory.

1. Install Docker and the Compose plugin.

   Debian/Ubuntu:

   ```bash
   sudo apt-get update
   sudo apt-get install -y docker.io docker-compose-plugin
   sudo systemctl enable --now docker
   ```

   CentOS Stream/RHEL-compatible hosts:

   ```bash
   sudo dnf install -y docker
   sudo systemctl enable --now docker
   ```

2. Create the deployment and media folders.

   ```bash
   sudo mkdir -p /opt/backuprr /srv/media
   sudo chown -R "$USER:$USER" /opt/backuprr
   cd /opt/backuprr
   mkdir -p data
   ```

3. Create `docker-compose.yml`.

   This Compose file keeps deployment settings minimal and builds the image from
   GitHub's HTTPS source archive. That avoids Docker Git build contexts, which
   are not available in every stack manager. Use the `main.zip` URL for the
   latest `main` branch, or replace it with a tag or commit archive URL when you
   want repeatable upgrades.

   If the GitHub repository is private, the Docker builder cannot download the
   archive anonymously and GitHub will return `404`. Create a fine-grained
   GitHub token with read-only Contents access to this repository, then define
   `GITHUB_TOKEN` in Dockhand/Portainer/the shell before deploying. If the
   repository is public, you can remove the `args` line and use the unauthenticated
   archive URL in the `RUN` command.

```yaml
services:
  backuprr:
    image: backuprr:github
    build:
      context: .
      args:
        GITHUB_TOKEN: ${GITHUB_TOKEN:?GitHub token with read access is required while this repository is private}
      dockerfile_inline: |
        FROM python:3.12-slim
        ARG GITHUB_TOKEN
        ENV PYTHONDONTWRITEBYTECODE=1 \
            PYTHONUNBUFFERED=1
        RUN pip install --no-cache-dir "https://x-access-token:$${GITHUB_TOKEN}@github.com/kelau/Backuprr/archive/refs/heads/main.zip" \
            && useradd --system --uid 10001 --home-dir /app backuprr \
            && mkdir -p /app /data /media \
            && chown -R backuprr:backuprr /app /data /media
        USER backuprr
        WORKDIR /app
        VOLUME ["/data", "/media"]
        EXPOSE 8080
        CMD ["sh", "-c", "backuprr --config /data/config.json init && backuprr --config /data/config.json add-endpoint /media && backuprr --config /data/config.json web --host 0.0.0.0 --port 8080"]
    container_name: backuprr
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - /opt/backuprr/data:/data
      - /srv/media:/media:rw
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).read()"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 20s
```

4. Make the data directory writable by the container user and start the service.

   The image runs as UID `10001`; this user must be able to write the config,
   SQLite database, and temporary catalog state in `/data`.

   ```bash
   sudo chown -R 10001:10001 /opt/backuprr/data
   docker compose up -d --build
   ```

   If `/opt/backuprr/data/config.json` does not exist, Backuprr creates it with
   defaults during startup. In this container layout, the default relative
   database path resolves to `/data/backuprr.sqlite3`, so the catalog persists in
   `/opt/backuprr/data`. The startup command also registers `/media` as a
   catalog endpoint so files mounted from `/srv/media` can be discovered
   immediately; narrow this endpoint later in Settings if you only want selected
   subfolders.

5. Verify the deployment.

   ```bash
   docker compose ps
   curl -fsS http://127.0.0.1:8080/healthz
   docker compose logs -f backuprr
   ```

   Open `http://SERVER-IP:8080/` in a browser. In Settings, confirm each Usenet
   host shows `Configured` authentication, then use Status or Tasks to run a
   catalog scan and backup worker.

6. Configure Backuprr.

   Use the Settings page to add endpoints and Usenet hosts. Endpoints must use
   the container path, for example `/media` or `/media/movies`, not the host path
   `/srv/media`. Set a Web UI password before exposing the app outside a trusted
   local network.

   You can also edit `/opt/backuprr/data/config.json` directly. Restart the
   container after manual edits:

   ```bash
   docker compose restart backuprr
   ```

7. Upgrade later without losing state.

   ```bash
   cd /opt/backuprr
   docker compose up -d --build
   ```

   Compose fetches the GitHub build context again during the rebuild. The config
   and catalog remain in `/opt/backuprr/data`. Back up this directory before
   major upgrades or host maintenance.

For Portainer, use the same compose file in a Stack and create
`/opt/backuprr/data` with UID `10001` ownership before deploying. Backuprr will
generate `/data/config.json` on first start if it is missing.

## Updates

Backuprr can check GitHub Releases once per day by default and stores the last
result in the local database. The Status page shows whether the running version
is current, whether a newer release is available, or whether the update check
failed. The Tasks page includes the scheduled update checker and a manual
`Check now` action.

Configure the release source in Settings or `config.json`:

```json
{
  "update_check_enabled": true,
  "update_check_interval_seconds": 86400,
  "update_github_repo": "kelau/Backuprr",
  "update_check_timeout_seconds": 10
}
```

The same check is available from the CLI:

```bash
backuprr --config config.json update-check
```

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
  "web_ui_username": "admin",
  "web_ui_password": "",
  "web_ui_role": "admin",
  "config_secret_key_env": "BACKUPRR_CONFIG_SECRET",
  "restore_sandbox_enabled": false,
  "audit_mode": false,
  "manifest_export_enabled": true,
  "manifest_export_encrypt": false,
  "auto_vacuum_after_compaction_rows": 100000,
  "backup_interval_seconds": 300,
  "update_check_interval_seconds": 86400,
  "update_check_enabled": true,
  "update_github_repo": "kelau/Backuprr",
  "update_check_timeout_seconds": 10,
  "external_api_keys": ["change-this-long-random-token"],
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
backuprr --config config.json benchmark --files 50000 --size 1073741824
backuprr --config config.json disaster-recovery
backuprr --config config.json metrics
backuprr --config config.json health-check
backuprr --config config.json article-size-test
backuprr --config config.json maintenance --vacuum
backuprr --config config.json restore-drill
backuprr --config config.json update-check
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

Use `backuprr benchmark` before scaling up to estimate chunk-row volume and
database growth for synthetic catalogs, and use `backuprr disaster-recovery` to
confirm the config, database, chunk metadata, cloud targets, and API keys needed
to rebuild the service after a host loss.

Body encryption uses a passphrase-derived HMAC-SHA256 keystream implemented with
the Python standard library. For high-assurance environments, integrate a
dedicated audited encryption package before storing sensitive data offsite.

PAR2 support is implemented as a command hook. Backuprr resolves the configured
command from `PATH` and also checks for bundled executables in `backuprr/bin`
or `./bin`, so distribution packages can include platform-specific PAR2
binaries. If compression is enabled, Backuprr creates a temporary compressed
payload before invoking PAR2 because PAR2 tools need a complete file path and
write sidecar recovery files. If compression is disabled, Backuprr still works
in a temporary directory to avoid leaving `.par2` files beside your media.

## APIs

The Web UI uses `/api/*` as an internal API and sends per-process internal and
CSRF tokens that are embedded into the served app page. Direct calls to `/api/*`
without those tokens are rejected. Internal and external API rate limits are
configurable in Settings.

Integrations such as Home Assistant should use `/external-api/*` with either
`X-API-Key: <key>` or `Authorization: Bearer <key>`. Configure keys in Settings
or in `config.json` under `external_api_keys`.

For private GitHub repositories, update checks need a token in the app process
environment. Set the configured token environment variable, defaulting to
`GITHUB_TOKEN`, or `GH_TOKEN` before starting Backuprr.

Available integration endpoints:

- `GET /external-api/status`
- `GET /external-api/files?page=1&page_size=100&q=&unbacked=0`
- `GET /external-api/queue`
- `GET /external-api/tasks`
- `POST /external-api/backup/run`
- `POST /external-api/scan`
- `POST /external-api/verify/start`

## Development

```bash
python -m unittest discover -s tests
```
