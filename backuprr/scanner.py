import hashlib
from pathlib import Path
from typing import List

from .db import Database


def sha256_file(path: Path, block_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(block_size), b""):
            digest.update(block)
    return digest.hexdigest()


def scan_endpoint(db: Database, endpoint_id: int, endpoint_path: str) -> int:
    root = Path(endpoint_path).resolve()
    seen: List[str] = []
    count = 0
    if not root.exists():
        db.log("error", "scan", f"Endpoint does not exist: {root}")
        return 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        stat = path.stat()
        resolved = str(path.resolve())
        seen.append(resolved)
        file_id = db.upsert_file(
            {
                "endpoint_id": endpoint_id,
                "path": resolved,
                "relative_path": str(path.resolve().relative_to(root)),
                "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
                "sha256": sha256_file(path),
                "state": "discovered",
            }
        )
        db.log("verbose", "scan.file", f"Cataloged {resolved}", file_id=file_id)
        count += 1
    missing = db.mark_missing_files(seen, endpoint_id)
    reconciled = db.reconcile_moved_duplicates(endpoint_id)
    db.log("info", "scan", f"Scanned {root}: {count} files, {missing} missing, {reconciled} moved")
    return count


def scan_all(db: Database) -> int:
    total = 0
    for endpoint in db.endpoints():
        total += scan_endpoint(db, int(endpoint["id"]), endpoint["path"])
    return total
