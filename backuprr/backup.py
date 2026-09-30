import copy
import hashlib
import math
import nntplib
import os
import platform
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import zlib
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional

from . import __version__
from .config import Config
from .crypto import xor_crypt
from .db import Database, utcnow
from .usenet import UsenetClient, obfuscated_subject, select_host


NETWORK_BLOCKED_RETRY_SECONDS = 300
VERIFY_RETRYABLE_PATTERNS = (
    "rate",
    "limit",
    "too many",
    "temporar",
    "try again",
    "timeout",
    "timed out",
    "busy",
    "unavailable",
    "connection reset",
    "connection aborted",
)
COMPRESSED_EXTENSIONS = {
    ".7z",
    ".avi",
    ".br",
    ".bz2",
    ".flac",
    ".gz",
    ".iso",
    ".jpeg",
    ".jpg",
    ".m4v",
    ".mkv",
    ".mov",
    ".mp3",
    ".mp4",
    ".ogg",
    ".png",
    ".rar",
    ".webm",
    ".xz",
    ".zip",
    ".zst",
}
PAYLOAD_PREFETCH_LIMIT = 2
PAYLOAD_PREFETCH_MAX_AGE_SECONDS = 6 * 60 * 60
_payload_prefetch_lock = threading.Lock()
_payload_prefetch_executor: ThreadPoolExecutor | None = None
_payload_prefetches: dict[int, dict[str, Any]] = {}


class PostNetworkBlockedError(RuntimeError):
    pass


def is_socket_permission_error(exc: Exception) -> bool:
    text = str(exc)
    return isinstance(exc, OSError) and (
        getattr(exc, "winerror", None) == 10013
        or getattr(exc, "errno", None) == 10013
        or "WinError 10013" in text
        or "forbidden by its access permissions" in text
    )


def is_retryable_verification_error(exc: Exception) -> bool:
    if is_socket_permission_error(exc):
        return True
    if isinstance(exc, (nntplib.NNTPTemporaryError, TimeoutError, socket.timeout, ConnectionError)):
        return True
    text = str(exc).lower()
    return any(pattern in text for pattern in VERIFY_RETRYABLE_PATTERNS)


def iter_chunks(path: Path, size: int) -> Iterator[bytes]:
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(size), b""):
            yield block


def sha256_file(path: Path, block_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(block_size), b""):
            digest.update(block)
    return digest.hexdigest()


def file_is_already_compressed(path: Path) -> bool:
    suffixes = [suffix.lower() for suffix in path.suffixes]
    return any(suffix in COMPRESSED_EXTENSIONS for suffix in suffixes)


def sample_compression_gain(path: Path, sample_bytes: int) -> float:
    sample_bytes = max(0, int(sample_bytes or 0))
    if sample_bytes <= 0:
        return 100.0
    with path.open("rb") as handle:
        data = handle.read(sample_bytes)
    if not data:
        return 0.0
    compressed = zlib.compress(data, level=6)
    return max(0.0, ((len(data) - len(compressed)) / len(data)) * 100)


def compression_enabled_for(path: Path, config: Config) -> bool:
    if not bool(getattr(config, "compress_files", False)) or file_is_already_compressed(path):
        return False
    minimum_gain = float(getattr(config, "compression_min_gain_percent", 0) or 0)
    if minimum_gain <= 0:
        return True
    return sample_compression_gain(path, int(getattr(config, "compression_sample_bytes", 0) or 0)) >= minimum_gain


def auto_pause_after_failure(db: Database, config: Config, exc: Exception, host_name: str = "") -> None:
    text = str(exc)
    auth_threshold = int(getattr(config, "auto_pause_auth_failures", 0) or 0)
    provider_threshold = int(getattr(config, "auto_pause_provider_failures", 0) or 0)
    auth_failure = any(code in text for code in ("480 Authentication Required", "502 Authentication Failed"))
    recent_auth_failures = db.recent_host_failure_count(host_name, "post", auth_threshold, "Authentication") if host_name and auth_threshold else 0
    recent_provider_failures = db.recent_host_failure_count(host_name, "post", provider_threshold) if host_name and provider_threshold else 0
    if auth_threshold and auth_failure and (not host_name or recent_auth_failures >= auth_threshold):
        db.set_paused("backup", True)
        db.log("error", "worker.autopause", f"Paused backup worker after {auth_threshold} authentication failure(s){f' on {host_name}' if host_name else ''}: {text}")
    elif provider_threshold and ("All post hosts failed" in text or "PAR2 command not found" in text or recent_provider_failures >= provider_threshold):
        db.set_paused("backup", True)
        db.log("error", "worker.autopause", f"Paused backup worker after provider/tool failure threshold: {text}")


def chunk_buffered(parts: Iterable[bytes], size: int) -> Iterator[bytes]:
    buffer = bytearray()
    for part in parts:
        if not part:
            continue
        buffer.extend(part)
        while len(buffer) >= size:
            yield bytes(buffer[:size])
            del buffer[:size]
    if buffer:
        yield bytes(buffer)


def iter_compressed_chunks(path: Path, size: int) -> Iterator[bytes]:
    compressor = zlib.compressobj(level=6, wbits=31)

    def parts() -> Iterator[bytes]:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                yield compressor.compress(block)
        yield compressor.flush()

    yield from chunk_buffered(parts(), size)


def create_compressed_payload(path: Path) -> Path:
    tempdir = Path(tempfile.mkdtemp(prefix="backuprr-"))
    gzip_path = tempdir / f"{path.name}.gz"
    compressor = zlib.compressobj(level=6, wbits=31)
    with path.open("rb") as source, gzip_path.open("wb") as target:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            target.write(compressor.compress(block))
        target.write(compressor.flush())
    return gzip_path


def bundled_par2_candidates(config: Config) -> list[Path]:
    names = ["par2.exe", "par2"] if platform.system().lower() == "windows" else ["par2", "par2cmdline"]
    roots = [
        Path(__file__).resolve().parent / "bin",
        Path(__file__).resolve().parent.parent / "bin",
        Path(getattr(config, "base_dir", Path.cwd())) / "bin",
    ]
    return [root / name for root in roots for name in names]


def par2_search_candidates(config: Config) -> list[tuple[str, Path]]:
    """Return likely PAR2-compatible executables in priority order."""
    candidates = [(f"bundled {path.name}", path) for path in bundled_par2_candidates(config)]
    names = ["par2", "par2cmdline"]
    if platform.system().lower() == "windows":
        names.extend(["par2.exe", "par2j64.exe", "par2j.exe", "MultiPar.exe", "QuickPar.exe"])
        program_roots = [
            os.environ.get("ProgramFiles"),
            os.environ.get("ProgramFiles(x86)"),
            os.environ.get("LOCALAPPDATA"),
        ]
        relative_paths = [
            ("MultiPar par2j64", Path("MultiPar") / "par2j64.exe"),
            ("MultiPar par2j", Path("MultiPar") / "par2j.exe"),
            ("MultiPar GUI", Path("MultiPar") / "MultiPar.exe"),
            ("QuickPar", Path("QuickPar") / "QuickPar.exe"),
            ("PAR2", Path("par2") / "par2.exe"),
            ("PAR2cmdline", Path("par2cmdline") / "par2.exe"),
        ]
        for root in [Path(item) for item in program_roots if item]:
            for label, relpath in relative_paths:
                candidates.append((label, root / relpath))
    else:
        names.extend(["par2create"])
        for root in [Path("/usr/bin"), Path("/usr/local/bin"), Path("/opt/homebrew/bin"), Path("/opt/local/bin")]:
            for name in names:
                candidates.append((name, root / name))
    path_candidates = []
    for name in names:
        found = shutil.which(name)
        if found:
            path_candidates.append((f"PATH {name}", Path(found)))
    candidates = path_candidates + candidates
    seen: set[str] = set()
    unique = []
    for label, path in candidates:
        key = str(path).lower()
        if key not in seen:
            seen.add(key)
            unique.append((label, path))
    return unique


def discover_par2_command(config: Config) -> dict[str, Any]:
    """Find the best available PAR2-compatible executable for Settings auto-fill."""
    checked = []
    for label, candidate in par2_search_candidates(config):
        exists = candidate.exists()
        checked.append({"label": label, "path": str(candidate), "exists": exists})
        if exists:
            return {"found": True, "command": str(candidate), "label": label, "checked": checked}
    return {"found": False, "command": "", "label": "", "checked": checked}


def par2_command_status(command: str, config: Config) -> dict[str, Any]:
    resolved = resolve_par2_command(command, config)
    return {
        "configured": str(command or "par2").strip() or "par2",
        "found": bool(resolved),
        "resolved": resolved or "",
        "args_preview": par2_create_args(resolved, Path("payload.bin"), str((config.par2 or {}).get("redundancy_percent", 10))) if resolved else [],
    }


def resolve_par2_command(command: str, config: Config) -> str | None:
    raw = str(command or "par2").strip() or "par2"
    candidate = Path(raw)
    if candidate.is_absolute() or any(sep in raw for sep in ("/", "\\")):
        return str(candidate) if candidate.exists() else None
    found = shutil.which(raw)
    if found:
        return found
    if raw in {"par2", "par2cmdline"}:
        discovered = discover_par2_command(config)
        if discovered["found"]:
            return str(discovered["command"])
    return None


def par2_create_args(command: str, payload: Path, redundancy: str) -> list[str]:
    exe = Path(command).name.lower()
    par_file = payload.with_name(f"{payload.name}.par2")
    if exe in {"par2j.exe", "par2j64.exe"}:
        return [command, "c", f"/rr{redundancy}", "/uo", str(par_file), str(payload)]
    if exe in {"par2create", "par2create.exe"}:
        return [command, f"-r{redundancy}", str(par_file), str(payload)]
    return [command, "create", f"-r{redundancy}", str(par_file), str(payload)]


def parse_par2_progress_line(line: str) -> int | None:
    matches = re.findall(r"(\d+(?:\.\d+)?)\s*%", line or "")
    if not matches:
        return None
    return max(0, min(100, int(float(matches[-1]))))


def run_par2_create(command: str, payload: Path, redundancy: str, progress: Optional[Callable[[int], None]] = None) -> None:
    args = par2_create_args(command, payload, redundancy)
    if progress is None:
        result = subprocess.run(
            args,
            cwd=str(payload.parent),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part and part.strip())
    else:
        process = subprocess.Popen(
            args,
            cwd=str(payload.parent),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        output_parts: list[str] = []
        assert process.stdout is not None
        for line in process.stdout:
            stripped = line.strip()
            if stripped:
                output_parts.append(stripped)
            percent = parse_par2_progress_line(line)
            if percent is not None:
                progress(percent)
        returncode = process.wait()
        result = subprocess.CompletedProcess(args, returncode)
        output = "\n".join(output_parts)
    if result.returncode != 0:
        raise RuntimeError(
            f"PAR2 command failed with exit code {result.returncode}: {args}. "
            f"Output: {output or '(no output)'}"
        )
    recovery_files = [
        child
        for child in payload.parent.iterdir()
        if child.is_file() and child.name.startswith(payload.name) and child.name.lower().endswith(".par2")
    ]
    if progress is not None:
        progress(100)
    if not recovery_files:
        raise RuntimeError(f"PAR2 command completed but did not create recovery files for {payload.name}. Output: {output or '(no output)'}")


def prepare_payload(path: Path, config: Config, progress: Optional[Callable[[int], None]] = None) -> Path:
    if not config.par2.get("enabled"):
        return path
    payload = create_compressed_payload(path) if compression_enabled_for(path, config) else path
    if payload == path:
        tempdir = Path(tempfile.mkdtemp(prefix="backuprr-"))
        copied_path = tempdir / path.name
        shutil.copy2(path, copied_path)
        payload = copied_path
    if config.par2.get("enabled"):
        command = config.par2.get("command", "par2")
        redundancy = str(config.par2.get("redundancy_percent", 10))
        resolved_command = resolve_par2_command(command, config)
        if resolved_command is None:
            raise RuntimeError(
                f"PAR2 command not found: {command}. Install PAR2, place a bundled par2 executable in backuprr/bin or ./bin, "
                "or disable PAR2 recovery files in Settings."
            )
        run_par2_create(resolved_command, payload, redundancy, progress=progress)
    return payload


def payload_preparation_enabled(config: Config) -> bool:
    return bool((config.par2 or {}).get("enabled"))


def preparation_status(config: Config) -> str:
    return "preparing_par2" if payload_preparation_enabled(config) else "queued"


def payload_preparation_key(path: Path, size: int, mtime_ns: int, config: Config) -> tuple[Any, ...]:
    par2 = dict(config.par2 or {})
    return (
        str(path),
        int(size),
        int(mtime_ns),
        bool(par2.get("enabled")),
        str(par2.get("command", "par2")),
        int(par2.get("redundancy_percent", 10)),
        bool(getattr(config, "compress_files", False)),
        int(getattr(config, "compression_sample_bytes", 0) or 0),
        int(getattr(config, "compression_min_gain_percent", 0) or 0),
    )


def payload_prefetch_executor() -> ThreadPoolExecutor:
    global _payload_prefetch_executor
    with _payload_prefetch_lock:
        if _payload_prefetch_executor is None:
            _payload_prefetch_executor = ThreadPoolExecutor(max_workers=PAYLOAD_PREFETCH_LIMIT, thread_name_prefix="backuprr-prepare")
        return _payload_prefetch_executor


def cleanup_stale_payload_prefetches(max_age_seconds: int = PAYLOAD_PREFETCH_MAX_AGE_SECONDS) -> None:
    now = time.time()
    expired: list[dict[str, Any]] = []
    with _payload_prefetch_lock:
        for file_id, entry in list(_payload_prefetches.items()):
            future: Future[Path] = entry["future"]
            if future.done() and future.exception() is not None:
                expired.append(_payload_prefetches.pop(file_id))
            elif now - float(entry.get("created_at", now)) > max_age_seconds:
                expired.append(_payload_prefetches.pop(file_id))
    for entry in expired:
        future = entry["future"]
        if future.done() and future.exception() is None:
            cleanup_payload(future.result(), entry["original"])


def take_prefetched_payload(file_id: int, original: Path, size: int, mtime_ns: int, config: Config) -> Path | None:
    key = payload_preparation_key(original, size, mtime_ns, config)
    with _payload_prefetch_lock:
        entry = _payload_prefetches.get(file_id)
        if not entry:
            return None
        if entry.get("key") != key:
            future: Future[Path] = entry["future"]
            if not future.done():
                return None
            entry = _payload_prefetches.pop(file_id)
        else:
            future: Future[Path] = entry["future"]
            if not future.done():
                return None
            _payload_prefetches.pop(file_id, None)
    future = entry["future"]
    if not future.done() or future.cancelled():
        return None
    try:
        payload = future.result()
    except Exception:
        return None
    if entry.get("key") != key:
        cleanup_payload(payload, original)
        return None
    return payload


def reconcile_payload_preparation(db: Database, file_id: int, original: Path, config: Config) -> str:
    with _payload_prefetch_lock:
        entry = _payload_prefetches.get(file_id)
        if not entry:
            db.requeue_file(file_id, "interrupted-payload-prepare")
            db.log("warning", "post.prepare", f"Recovered interrupted PAR2 preparation for {original}; it will be prepared again", file_id)
            return "requeued"
        future: Future[Path] = entry["future"]
        if not future.done():
            return "waiting"
        _payload_prefetches.pop(file_id, None)
    try:
        payload = future.result()
    except Exception as exc:
        db.requeue_file(file_id, "payload-prepare-failed")
        db.log("warning", "post.prepare", f"Background PAR2 preparation failed for {original}: {exc}", file_id)
        return "failed"
    db.complete_queue_preparation(file_id)
    db.log("debug", "post.prepare", f"Background PAR2 preparation completed for {original}", file_id)
    with _payload_prefetch_lock:
        _payload_prefetches[file_id] = {
            "future": future,
            "key": payload_preparation_key(original, int(original.stat().st_size), int(original.stat().st_mtime_ns), config),
            "original": original,
            "created_at": time.time(),
        }
    if not payload.exists():
        db.requeue_file(file_id, "payload-prepare-failed")
        return "failed"
    return "ready"


def schedule_payload_prefetches(db: Database, config: Config, current_file_id: int) -> int:
    if not payload_preparation_enabled(config):
        return 0
    cleanup_stale_payload_prefetches()
    with db.connect() as conn:
        rows = conn.execute(
            """
            SELECT q.file_id, f.path, f.size, f.mtime_ns
            FROM queue q
            JOIN files f ON f.id = q.file_id
            WHERE q.status='queued'
              AND q.file_id != ?
              AND f.state NOT IN ('backed_up', 'deleted', 'posting', 'unreadable')
            ORDER BY q.priority ASC, q.position ASC
            LIMIT ?
            """,
            (current_file_id, PAYLOAD_PREFETCH_LIMIT),
        ).fetchall()
    scheduled = 0
    for row in rows:
        file_id = int(row["file_id"])
        original = Path(row["path"])
        key = payload_preparation_key(original, int(row["size"]), int(row["mtime_ns"]), config)
        executor = payload_prefetch_executor()
        with _payload_prefetch_lock:
            existing = _payload_prefetches.get(file_id)
            if existing and existing.get("key") == key:
                continue
            if existing:
                future = existing["future"]
                if not future.done():
                    continue
                if future.done() and future.exception() is None:
                    cleanup_payload(future.result(), existing["original"])
            db.set_queue_status(file_id, preparation_status(config))
            db.set_queue_preparation_progress(file_id, 0)
            config_snapshot = copy.deepcopy(config)
            def prefetch_progress(percent: int, queued_file_id: int = file_id) -> None:
                db.set_queue_preparation_progress(queued_file_id, percent)

            future = executor.submit(prepare_payload, original, config_snapshot, prefetch_progress)
            _payload_prefetches[file_id] = {"future": future, "key": key, "original": original, "created_at": time.time()}
            future.add_done_callback(
                lambda done, queued_file_id=file_id: db.complete_queue_preparation(
                    queued_file_id,
                    "payload-prepare-failed" if done.exception() is not None else "prepared-payload",
                )
            )
            scheduled += 1
    return scheduled


def cleanup_payload(payload: Path, original: Path) -> None:
    if payload == original:
        return
    tempdir = payload.parent
    for child in tempdir.glob("*"):
        child.unlink(missing_ok=True)
    tempdir.rmdir()


def encode_chunk(chunk: bytes, config: Config, salt: bytes) -> bytes:
    if not config.encrypt_bodies:
        return chunk
    passphrase = config.encryption_passphrase()
    if not passphrase:
        raise RuntimeError("Encryption enabled but no passphrase is configured")
    return b"BACKUPRR-ENC1" + salt + xor_crypt(chunk, passphrase, salt)


def decode_chunk(chunk: bytes, passphrase: Optional[str]) -> bytes:
    prefix = b"BACKUPRR-ENC1"
    if not chunk.startswith(prefix):
        return chunk
    if not passphrase:
        raise RuntimeError("Encrypted chunk requires a passphrase")
    salt_start = len(prefix)
    salt = chunk[salt_start : salt_start + 16]
    return xor_crypt(chunk[salt_start + 16 :], passphrase, salt)


def estimated_body_size(chunk: bytes, config: Config) -> int:
    return len(chunk) + (len(b"BACKUPRR-ENC1") + 16 if config.encrypt_bodies else 0)


def queued_file_is_stable(item: Any, path: Path, stability_seconds: int) -> bool:
    if stability_seconds <= 0:
        return True
    try:
        stat = path.stat()
    except OSError:
        return False
    if stat.st_size != int(item["size"]) or stat.st_mtime_ns != int(item["mtime_ns"]):
        return False
    age_seconds = max(0.0, time.time() - (stat.st_mtime_ns / 1_000_000_000))
    return age_seconds >= stability_seconds


def network_blocked_retry_due(item: Any, retry_seconds: int = NETWORK_BLOCKED_RETRY_SECONDS) -> bool:
    if str(item["reason"] or "") != "network-blocked":
        return True
    try:
        updated_at = datetime.fromisoformat(str(item["updated_at"]))
    except (TypeError, ValueError):
        return True
    if updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - updated_at >= timedelta(seconds=retry_seconds)


def post_next(db: Database, config: Config) -> Optional[int]:
    item = db.next_queue_item()
    if not item:
        return None
    file_id = int(item["file_id"])
    original = Path(item["path"])
    if str(item["status"] or "") == "preparing_par2":
        state = reconcile_payload_preparation(db, file_id, original, config)
        if state == "waiting":
            db.log("debug", "post.prepare", f"Waiting for PAR2 preparation before posting: {original}", file_id)
        return None
    hourly_limit = int(getattr(config, "hourly_post_limit_bytes", 0) or 0)
    if hourly_limit > 0:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(microsecond=0).isoformat()
        used = db.transfer_bytes_since("upload", cutoff)
        if used >= hourly_limit:
            db.log("debug", "post.throttle", f"Hourly post limit reached: {used} of {hourly_limit} bytes used")
            return None
    if not original.exists():
        db.update_file_state(file_id, "failed")
        db.set_queue_status(file_id, "failed")
        db.log("error", "post", f"Queued file no longer exists: {original}", file_id)
        return file_id
    if not network_blocked_retry_due(item):
        db.log("debug", "post.network", f"Waiting before retrying network-blocked post for {original}", file_id)
        return None
    stability_seconds = int(getattr(config, "file_stability_seconds", 0) or 0)
    if stability_seconds and not queued_file_is_stable(item, original, stability_seconds):
        db.requeue_file(file_id, "file-changing")
        db.log("debug", "post.stability", f"Waiting for stable file before posting: {original}", file_id)
        return None
    file_sha256 = str(item["sha256"] or "")
    if not file_sha256:
        try:
            before_hash = original.stat()
            db.log("debug", "post.hash", f"Hashing {original} before posting", file_id)
            file_sha256 = sha256_file(original)
            after_hash = original.stat()
        except OSError as exc:
            db.mark_file_unreadable(str(original), str(exc))
            db.log("warning", "post.hash", f"Unable to hash queued file before posting: {original}: {exc}", file_id)
            return None
        if before_hash.st_size != after_hash.st_size or before_hash.st_mtime_ns != after_hash.st_mtime_ns:
            db.requeue_file(file_id, "file-changing")
            db.log("warning", "post.stability", f"File changed while hashing; waiting before posting: {original}", file_id)
            return None
        db.update_file_hash(file_id, int(after_hash.st_size), int(after_hash.st_mtime_ns), file_sha256)
    payload = original
    run_id: Optional[int] = None
    streaming_compressed = False
    payload_size = int(original.stat().st_size)
    uncompressed_size = int(original.stat().st_size)
    try:
        article_size = max(1, int(config.article_size))
        streaming_compressed = compression_enabled_for(original, config) and not config.par2.get("enabled")
        if streaming_compressed:
            payload = original
        else:
            prefetched_payload = take_prefetched_payload(file_id, original, int(item["size"]), int(item["mtime_ns"]), config)
            if prefetched_payload is None:
                db.set_queue_status(file_id, preparation_status(config))
                db.set_queue_preparation_progress(file_id, 0)
                db.log("debug", "post.prepare", f"Preparing payload before posting: {original}", file_id)
                payload = prepare_payload(original, config, progress=lambda percent: db.set_queue_preparation_progress(file_id, percent))
            else:
                payload = prefetched_payload
                db.log("debug", "post.prepare", f"Using prefetched payload for posting: {original}", file_id)
        payload_size = int(payload.stat().st_size)
        db.set_queue_payload_size(file_id, payload_size)
        db.set_queue_status(file_id, "posting")
        db.update_file_state(file_id, "posting")
        prefetched = schedule_payload_prefetches(db, config, file_id)
        if prefetched:
            db.log("debug", "post.prepare", f"Started background payload preparation for {prefetched} queued file(s)", file_id)
        expected_chunks = max(1, math.ceil(payload_size / article_size))
        run_id = db.start_backup_run(file_id, str(original), expected_chunks, payload_size, str(item["reason"] or ""))
        can_reuse_chunks = payload == original and str(item["reason"] or "") in {
            "startup-posting-retry",
            "stale-posting-retry",
            "missing-chunks",
            "hourly-limit",
        } and not streaming_compressed
        reusable_chunks = db.reusable_chunk_indexes(file_id, article_size) if can_reuse_chunks else {}
        reusable_chunks = {index: size for index, size in reusable_chunks.items() if 0 <= index < expected_chunks}
        posted_count = len(reusable_chunks)
        posted_bytes = sum(reusable_chunks.values())
        db.set_queue_progress(file_id, posted_count, posted_bytes)
        db.update_backup_run(run_id, posted_count, posted_bytes)
        if reusable_chunks:
            db.log("info", "post.resume", f"Resuming {original}: {posted_count}/{expected_chunks} chunks already cataloged", file_id)

        def post_chunk(chunk_index: int, chunk: bytes) -> tuple[int, str, int, str, str, str]:
            salt = os.urandom(16)
            body = encode_chunk(chunk, config, salt)
            digest = hashlib.sha256(body).hexdigest()
            subject = obfuscated_subject(file_id, chunk_index, digest)
            attempts = max(1, int(getattr(config, "usenet_retry_attempts", 1)))
            backoff = max(0, int(getattr(config, "usenet_retry_backoff_seconds", 0)))
            hosts = config.hosts_for_mode("post")
            if not hosts:
                hosts = [select_host(config, "post")]
            last_error: Optional[Exception] = None
            for attempt in range(attempts):
                for host in hosts:
                    try:
                        with UsenetClient(host) as client:
                            message_id = client.post(config.newsgroup, subject, body)
                        return chunk_index, message_id, len(body), digest, subject, host.name
                    except Exception as exc:
                        last_error = exc
                        db.record_host_check(host.name, host.mode, "failed", str(exc))
                        if is_socket_permission_error(exc):
                            raise PostNetworkBlockedError(f"NNTP socket access is blocked by the OS or sandbox ({exc})") from exc
                        auto_pause_after_failure(db, config, exc, host.name)
                        db.log("warning", "post.retry", f"Post attempt {attempt + 1}/{attempts} failed on {host.name}: {exc}", file_id)
                if attempt + 1 < attempts and backoff:
                    time.sleep(backoff)
            raise RuntimeError(f"All post hosts failed: {last_error}")

        max_workers = max(1, int(config.nntp_threads))
        futures = []
        throttled_by_hourly_limit = False
        remaining_hourly_budget = 0
        source_bytes_total = 0
        if hourly_limit > 0:
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(microsecond=0).isoformat()
            remaining_hourly_budget = max(0, hourly_limit - db.transfer_bytes_since("upload", cutoff))
        submitted_bytes = 0
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="backuprr-post") as executor:
            source_chunks = iter_compressed_chunks(original, article_size) if streaming_compressed else iter_chunks(payload, article_size)
            for chunk_index, chunk in enumerate(source_chunks):
                source_bytes_total += len(chunk)
                if chunk_index in reusable_chunks:
                    continue
                if hourly_limit > 0:
                    estimate = estimated_body_size(chunk, config)
                    if submitted_bytes + estimate > remaining_hourly_budget:
                        throttled_by_hourly_limit = True
                        break
                    submitted_bytes += estimate
                futures.append(executor.submit(post_chunk, chunk_index, chunk))
            if not futures and throttled_by_hourly_limit:
                db.requeue_file(file_id, "hourly-limit")
                db.log(
                    "debug",
                    "post.throttle",
                    f"Hourly post limit reached before posting next chunk for {original}: {remaining_hourly_budget} bytes remaining",
                    file_id,
                )
                return None
            last_progress_flush_at = time.monotonic()
            last_progress_flush_chunks = posted_count
            last_progress_host = ""

            def flush_post_progress(force: bool = False, host: str = "") -> None:
                nonlocal last_progress_flush_at, last_progress_flush_chunks, last_progress_host
                if host:
                    last_progress_host = host
                now_monotonic = time.monotonic()
                if (
                    not force
                    and posted_count < expected_chunks
                    and posted_count - last_progress_flush_chunks < 25
                    and now_monotonic - last_progress_flush_at < 3.0
                ):
                    return
                db.set_queue_progress(file_id, posted_count, posted_bytes)
                if run_id is not None:
                    db.update_backup_run(run_id, posted_count, posted_bytes, last_progress_host)
                last_progress_flush_at = now_monotonic
                last_progress_flush_chunks = posted_count

            for future in as_completed(futures):
                chunk_index, message_id, body_size, digest, subject, host_name = future.result()
                stored_digest = "" if getattr(config, "compact_chunk_metadata", True) else digest
                stored_subject = "" if getattr(config, "compact_chunk_metadata", True) else subject
                db.add_chunk(file_id, chunk_index, message_id, body_size, stored_digest, stored_subject, article_size=article_size)
                posted_count += 1
                posted_bytes += body_size
                flush_post_progress(host=host_name)
                if getattr(config, "log_chunk_events", False):
                    db.log("debug", "post.chunk", f"Posted chunk {chunk_index} for {original}", file_id)
            flush_post_progress(force=True)
        final_chunks = db.chunk_count_for_file(file_id)
        if streaming_compressed:
            expected_chunks = max(1, final_chunks)
            payload_size = source_bytes_total
            if run_id is not None:
                db.update_backup_run_totals(run_id, expected_chunks, payload_size)
        if throttled_by_hourly_limit and final_chunks < expected_chunks:
            if payload != original:
                raise RuntimeError("Hourly post limit interrupted a temporary payload; increase the hourly limit or disable compression/PAR2 for resumable throttling")
            db.set_queue_progress(file_id, final_chunks, posted_bytes)
            db.requeue_file(file_id, "hourly-limit")
            if run_id is not None:
                db.finish_backup_run(run_id, "paused", "hourly-limit")
            db.log(
                "info",
                "post.throttle",
                f"Paused posting {original} at {final_chunks}/{expected_chunks} chunks due to hourly post limit",
                file_id,
            )
            return None
        if final_chunks < expected_chunks:
            raise RuntimeError(f"Only {final_chunks} of {expected_chunks} chunks are cataloged")
        if stability_seconds and not queued_file_is_stable(item, original, stability_seconds):
            db.requeue_file(file_id, "file-changing")
            if run_id is not None:
                db.finish_backup_run(run_id, "paused", "file-changing")
            db.log("warning", "post.stability", f"File changed while posting; waiting before retrying: {original}", file_id)
            return None
        trimmed = db.trim_chunks(file_id, expected_chunks)
        final_chunks = db.chunk_count_for_file(file_id)
        db.set_queue_progress(file_id, final_chunks, posted_bytes)
        db.log("debug", "post.retry", f"Chunk catalog has {final_chunks} chunks for {original}, {trimmed} stale chunk rows trimmed", file_id)
        with db.connect() as conn:
            conn.execute("UPDATE files SET state='backed_up', last_backup_at=?, updated_at=? WHERE id=?", (utcnow(), utcnow(), file_id))
            conn.execute("UPDATE queue SET status='done', updated_at=? WHERE file_id=?", (utcnow(), file_id))
        if run_id is not None:
            db.finish_backup_run(run_id, "done")
        flags = []
        if config.encrypt_bodies:
            flags.append("encrypted")
        if streaming_compressed or (payload != original and compression_enabled_for(original, config)):
            flags.append("compressed")
        if config.par2.get("enabled"):
            flags.append("par2")
        db.set_file_backup_features(
            file_id,
            uncompressed_size,
            payload_size,
            "compressed" in flags,
            "par2" in flags,
        )
        db.record_backup_manifest(
            file_id,
            run_id,
            {
                "app_version": __version__,
                "path": str(original),
                "file_sha256": file_sha256,
                "article_size": article_size,
                "chunk_count": final_chunks,
                "bytes_total": payload_size,
                "flags": flags,
                "newsgroup": config.newsgroup,
                "host_mode": "post",
                "created_at": utcnow(),
            },
        )
        if getattr(config, "compact_chunk_rows", True):
            compacted = db.compact_chunks_to_manifest(file_id)
            db.log("debug", "post.compact", f"Compacted {compacted} chunk rows into manifest for {original}", file_id)
            threshold = int(getattr(config, "auto_vacuum_after_compaction_rows", 0) or 0)
            if threshold and compacted >= threshold:
                db.vacuum_analyze()
                db.log("info", "maintenance", f"Vacuumed database after compacting {compacted} chunk rows", file_id)
        db.log("info", "post", f"Posted backup for {original}", file_id)
        return file_id
    except PostNetworkBlockedError as exc:
        final_chunks = db.chunk_count_for_file(file_id)
        db.set_queue_progress(file_id, final_chunks, int(locals().get("posted_bytes", 0)))
        db.requeue_file(file_id, "network-blocked")
        if run_id is not None:
            db.finish_backup_run(run_id, "paused", str(exc))
        db.log("warning", "post.network", f"Posting skipped for {original}: {exc}", file_id)
        return None
    except Exception as exc:
        db.update_file_state(file_id, "failed")
        db.set_queue_status(file_id, "failed")
        auto_pause_after_failure(db, config, exc)
        if run_id is not None:
            db.finish_backup_run(run_id, "failed", str(exc))
        db.log("error", "post", f"Failed posting {original}: {exc}", file_id)
        raise
    finally:
        cleanup_payload(payload, original)


def verify_chunks(db: Database, config: Config, chunks: Iterable[Any], progress: Optional[Callable[[int, int], None]] = None) -> int:
    chunks = list(chunks)
    if not chunks:
        return 0
    host = select_host(config, "read")

    def verify_chunk(chunk) -> tuple[int, int, str, Optional[bool], str]:
        try:
            with UsenetClient(host) as client:
                exists = client.article_exists(chunk["message_id"])
            return chunk["id"], int(chunk["file_id"]), chunk["message_id"], exists, ""
        except Exception as exc:
            if is_retryable_verification_error(exc):
                return chunk["id"], int(chunk["file_id"]), chunk["message_id"], None, str(exc)
            raise

    count = 0
    completed = 0
    max_workers = max(1, int(config.nntp_threads))
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="backuprr-verify") as executor:
        futures = [executor.submit(verify_chunk, chunk) for chunk in chunks]
        for future in as_completed(futures):
            chunk_id, file_id, message_id, exists, retry_reason = future.result()
            if exists is None:
                db.log("warning", "verify.retry", f"Verification deferred for {message_id}: {retry_reason}", file_id)
            else:
                db.mark_chunk_verified(chunk_id, exists)
                if exists:
                    db.record_transfer_sample("download", 1)
                if not exists or getattr(config, "log_chunk_events", False):
                    db.log("debug" if exists else "warning", "verify.chunk", f"Chunk {message_id} exists={exists}", file_id)
                count += 1
            completed += 1
            if progress:
                progress(completed, len(chunks))
    return count


def verify_due_chunks(db: Database, config: Config, force: bool = False, progress: Optional[Callable[[int, int], None]] = None) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=config.verification_interval_days)
    older_than = datetime.max.replace(tzinfo=timezone.utc).isoformat() if force else cutoff.replace(microsecond=0).isoformat()
    chunks = (
        db.chunks_due_for_verification(older_than, include_missing=force)
        if force
        else db.chunks_due_for_file_verification(older_than, config.verification_files_per_run)
    )
    return verify_chunks(db, config, chunks, progress=progress)


def verify_file_chunks(
    db: Database,
    config: Config,
    file_ids: Iterable[int],
    progress: Optional[Callable[[int, int], None]] = None,
) -> int:
    return verify_chunks(db, config, db.chunks_for_file_ids(file_ids, include_missing=True), progress=progress)
