import shutil
import subprocess
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from .config import Config
from .db import Database


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
