import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .db import Database


def update_scan_progress(
    db: Database,
    root: Path,
    phase: str,
    files_seen: int,
    hashed: int,
    unchanged: int,
    current_path: str = "",
    finished: bool = False,
) -> None:
    db.set_meta(
        "scan.progress",
        json.dumps(
            {
                "root": str(root),
                "phase": phase,
                "files_seen": files_seen,
                "hashed": hashed,
                "unchanged": unchanged,
                "current_path": current_path,
                "finished": finished,
                "updated_at": time.time(),
            }
        ),
    )


def sha256_file(path: Path, block_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(block_size), b""):
            digest.update(block)
    return digest.hexdigest()


def ensure_readable(path: Path) -> None:
    with path.open("rb") as handle:
        handle.read(1)


def scan_endpoint(db: Database, endpoint_id: int, endpoint_path: str) -> int:
    root = Path(endpoint_path).resolve()
    seen: List[str] = []
    count = 0
    hashed = 0
    unchanged = 0
    moved_by_metadata = 0
    if not root.exists():
        db.log("error", "scan", f"Endpoint does not exist: {root}")
        return 0
    update_scan_progress(db, root, "starting", 0, 0, 0)
    last_progress_at = 0.0
    snapshot = db.endpoint_file_snapshot(endpoint_id)
    metadata_index: Dict[tuple[int, int], List[Dict[str, Any]]] = {}
    for row in snapshot.values():
        if row["state"] != "deleted":
            metadata_index.setdefault((int(row["size"]), int(row["mtime_ns"])), []).append(row)

    def move_candidate(size: int, mtime_ns: int, new_path: str) -> Optional[Dict[str, Any]]:
        candidates = [
            row
            for row in metadata_index.get((size, mtime_ns), [])
            if row["path"] != new_path
            and row["path"] not in seen
            and not Path(row["path"]).exists()
        ]
        return candidates[0] if len(candidates) == 1 else None

    for path in root.rglob("*"):
        try:
            is_file = path.is_file()
        except OSError as exc:
            try:
                resolved = str(path.resolve())
            except OSError:
                resolved = str(path)
            db.log("warning", "scan.file_error", f"Skipped unreadable file metadata {resolved}: {exc}")
            db.mark_file_unreadable(resolved, str(exc))
            seen.append(resolved)
            continue
        if not is_file:
            continue
        resolved = str(path.resolve())
        now = time.monotonic()
        if now - last_progress_at >= 1.0:
            update_scan_progress(db, root, "scanning", count, hashed, unchanged, resolved)
            last_progress_at = now
        try:
            stat = path.stat()
        except OSError as exc:
            db.log("warning", "scan.file_error", f"Skipped unreadable file metadata {resolved}: {exc}")
            continue
        seen.append(resolved)
        existing = snapshot.get(resolved)
        if existing and existing["state"] != "deleted" and existing["size"] == stat.st_size and existing["mtime_ns"] == stat.st_mtime_ns:
            if existing["state"] == "queued":
                try:
                    ensure_readable(path)
                except OSError as exc:
                    db.log("warning", "scan.file_error", f"Skipped unreadable queued file {resolved}: {exc}")
                    db.mark_file_unreadable(resolved, str(exc))
                    continue
            unchanged += 1
            count += 1
            continue
        candidate = None if existing else move_candidate(stat.st_size, stat.st_mtime_ns, resolved)
        if candidate:
            digest = candidate["sha256"]
        else:
            try:
                update_scan_progress(db, root, "hashing", count, hashed, unchanged, resolved)
                digest = sha256_file(path)
            except OSError as exc:
                db.log("warning", "scan.file_error", f"Skipped unreadable file content {resolved}: {exc}")
                db.mark_file_unreadable(resolved, str(exc))
                continue
        hashed += 0 if candidate else 1
        file_id = db.upsert_file(
            {
                "endpoint_id": endpoint_id,
                "path": resolved,
                "relative_path": str(path.resolve().relative_to(root)),
                "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
                "sha256": digest,
                "state": "discovered",
            }
        )
        if candidate:
            moved_by_metadata += 1
        db.log("verbose", "scan.file", f"Updated catalog record for {resolved}", file_id=file_id)
        count += 1
    missing = db.mark_missing_files(seen, endpoint_id)
    reconciled = db.reconcile_moved_duplicates(endpoint_id)
    moved = moved_by_metadata + reconciled
    db.log(
        "info" if missing or moved else "debug",
        "scan",
        f"Scanned {root}: {count} files, {unchanged} unchanged, {hashed} hashed, {missing} missing, {moved} moved",
    )
    update_scan_progress(db, root, "finished", count, hashed, unchanged, finished=True)
    return count


def scan_all(db: Database) -> int:
    total = 0
    for endpoint in db.endpoints():
        total += scan_endpoint(db, int(endpoint["id"]), endpoint["path"])
    return total
