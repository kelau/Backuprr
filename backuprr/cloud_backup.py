import shutil
import subprocess
import tempfile
import zipfile
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from .config import Config
from .db import Database


def cloud_backup_fingerprint(db: Database, config: Config) -> str:
    source = config.source_path
    config_stat = source.stat() if source and source.exists() else None
    token = db.change_token()
    relevant = {
        "config_path": str(source or ""),
        "config_mtime_ns": getattr(config_stat, "st_mtime_ns", 0),
        "config_size": getattr(config_stat, "st_size", 0),
        "files_updated": token.get("files_updated", ""),
        "queue_updated": token.get("queue_updated", ""),
        "chunks_total": token.get("chunks_total", 0),
        "files_total": token.get("files_total", 0),
        "queue_total": token.get("queue_total", 0),
    }
    return json.dumps(relevant, sort_keys=True, separators=(",", ":"))


def backup_config_and_database_if_changed(db: Database, config: Config) -> List[Dict[str, str]]:
    fingerprint = cloud_backup_fingerprint(db, config)
    if db.get_meta("cloud_backup_fingerprint") == fingerprint:
        return []
    results = backup_config_and_database(db, config)
    if results:
        db.set_meta("cloud_backup_fingerprint", fingerprint)
    return results


def backup_config_and_database(db: Database, config: Config) -> List[Dict[str, str]]:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results: List[Dict[str, str]] = []
    with tempfile.TemporaryDirectory(prefix="backuprr-cloud-") as temp:
        archive = Path(temp) / f"backuprr-backup-{timestamp}.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            if config.source_path and config.source_path.exists():
                bundle.write(config.source_path, "config.json")
            if db.path.exists():
                bundle.write(db.path, "backuprr.sqlite3")
        for target in config.cloud_backups:
            if not target.enabled:
                continue
            if target.provider == "command":
                command = target.command.replace("{archive}", str(archive))
                subprocess.run(command, shell=True, check=True)
                results.append({"name": target.name, "provider": target.provider, "target": "command"})
                continue
            destination_dir = Path(target.target)
            destination_dir.mkdir(parents=True, exist_ok=True)
            destination = destination_dir / archive.name
            shutil.copy2(archive, destination)
            results.append({"name": target.name, "provider": target.provider, "target": str(destination)})
    return results
