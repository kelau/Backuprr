import hashlib
import math
import os
import shutil
import subprocess
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from . import __version__
from .config import Config
from .crypto import xor_crypt
from .db import Database, utcnow
from .usenet import UsenetClient, obfuscated_subject, select_host


NETWORK_BLOCKED_RETRY_SECONDS = 300


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


def iter_chunks(path: Path, size: int) -> Iterator[bytes]:
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(size), b""):
            yield block


def prepare_payload(path: Path, config: Config) -> Path:
    if not config.zip_subfolders and not config.par2.get("enabled"):
        return path
    tempdir = Path(tempfile.mkdtemp(prefix="backuprr-"))
    zip_path = tempdir / f"{path.name}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(path, arcname=path.name)
    if config.par2.get("enabled"):
        command = config.par2.get("command", "par2")
        redundancy = str(config.par2.get("redundancy_percent", 10))
        if shutil.which(command) is None:
            raise RuntimeError(f"PAR2 command not found: {command}. Install PAR2 or disable PAR2 recovery files in Settings.")
        subprocess.run([command, "create", f"-r{redundancy}", str(zip_path)], check=True, cwd=str(tempdir))
    return zip_path


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
        raise RuntimeError("Encryption enabled but passphrase env var is not set")
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
    db.set_queue_status(file_id, "posting")
    db.update_file_state(file_id, "posting")
    payload = original
    run_id: Optional[int] = None
    try:
        payload = prepare_payload(original, config)
        article_size = max(1, int(config.article_size))
        expected_chunks = max(1, math.ceil(payload.stat().st_size / article_size))
        run_id = db.start_backup_run(file_id, str(original), expected_chunks, int(payload.stat().st_size), str(item["reason"] or ""))
        can_reuse_chunks = payload == original and str(item["reason"] or "") in {
            "startup-posting-retry",
            "stale-posting-retry",
            "missing-chunks",
            "hourly-limit",
        }
        reusable_chunks = db.reusable_chunk_indexes(file_id, article_size) if can_reuse_chunks else {}
        reusable_chunks = {index: size for index, size in reusable_chunks.items() if 0 <= index < expected_chunks}
        posted_count = len(reusable_chunks)
        posted_bytes = sum(reusable_chunks.values())
        db.set_queue_progress(file_id, posted_count, posted_bytes)
        db.update_backup_run(run_id, posted_count, posted_bytes)
        if reusable_chunks:
            db.log("info", "post.resume", f"Resuming {original}: {posted_count}/{expected_chunks} chunks already cataloged", file_id)

        def post_chunk(chunk_index: int, chunk: bytes) -> tuple[int, str, int, str, str]:
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
                        if run_id is not None:
                            db.update_backup_run(run_id, posted_count, posted_bytes, host.name)
                        return chunk_index, message_id, len(body), digest, subject
                    except Exception as exc:
                        last_error = exc
                        db.record_host_check(host.name, host.mode, "failed", str(exc))
                        if is_socket_permission_error(exc):
                            raise PostNetworkBlockedError(f"NNTP socket access is blocked by the OS or sandbox ({exc})") from exc
                        db.log("warning", "post.retry", f"Post attempt {attempt + 1}/{attempts} failed on {host.name}: {exc}", file_id)
                if attempt + 1 < attempts and backoff:
                    time.sleep(backoff)
            raise RuntimeError(f"All post hosts failed: {last_error}")

        max_workers = max(1, int(config.nntp_threads))
        futures = []
        throttled_by_hourly_limit = False
        remaining_hourly_budget = 0
        if hourly_limit > 0:
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).replace(microsecond=0).isoformat()
            remaining_hourly_budget = max(0, hourly_limit - db.transfer_bytes_since("upload", cutoff))
        submitted_bytes = 0
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="backuprr-post") as executor:
            for chunk_index, chunk in enumerate(iter_chunks(payload, article_size)):
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
            for future in as_completed(futures):
                chunk_index, message_id, body_size, digest, subject = future.result()
                stored_digest = "" if getattr(config, "compact_chunk_metadata", True) else digest
                stored_subject = "" if getattr(config, "compact_chunk_metadata", True) else subject
                db.add_chunk(file_id, chunk_index, message_id, body_size, stored_digest, stored_subject, article_size=article_size)
                posted_count += 1
                posted_bytes += body_size
                db.set_queue_progress(file_id, posted_count, posted_bytes)
                if run_id is not None:
                    db.update_backup_run(run_id, posted_count, posted_bytes)
                if getattr(config, "log_chunk_events", False):
                    db.log("debug", "post.chunk", f"Posted chunk {chunk_index} for {original}", file_id)
        final_chunks = db.chunk_count_for_file(file_id)
        if throttled_by_hourly_limit and final_chunks < expected_chunks:
            if payload != original:
                raise RuntimeError("Hourly post limit interrupted a temporary payload; increase the hourly limit or disable zip/par2 for resumable throttling")
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
        if config.zip_subfolders:
            flags.append("zip")
        if config.par2.get("enabled"):
            flags.append("par2")
        db.record_backup_manifest(
            file_id,
            run_id,
            {
                "app_version": __version__,
                "path": str(original),
                "file_sha256": str(item["sha256"] or ""),
                "article_size": article_size,
                "chunk_count": final_chunks,
                "bytes_total": int(payload.stat().st_size),
                "flags": flags,
                "newsgroup": config.newsgroup,
                "host_mode": "post",
                "created_at": utcnow(),
            },
        )
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
        if run_id is not None:
            db.finish_backup_run(run_id, "failed", str(exc))
        db.log("error", "post", f"Failed posting {original}: {exc}", file_id)
        raise
    finally:
        cleanup_payload(payload, original)


def verify_chunks(db: Database, config: Config, chunks: Iterable[Any]) -> int:
    chunks = list(chunks)
    if not chunks:
        return 0
    host = select_host(config, "read")

    def verify_chunk(chunk) -> tuple[int, int, str, bool]:
        with UsenetClient(host) as client:
            exists = client.article_exists(chunk["message_id"])
        return int(chunk["id"]), int(chunk["file_id"]), chunk["message_id"], exists

    count = 0
    max_workers = max(1, int(config.nntp_threads))
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="backuprr-verify") as executor:
        futures = [executor.submit(verify_chunk, chunk) for chunk in chunks]
        for future in as_completed(futures):
            chunk_id, file_id, message_id, exists = future.result()
            db.mark_chunk_verified(chunk_id, exists)
            if exists:
                db.record_transfer_sample("download", 1)
            if not exists or getattr(config, "log_chunk_events", False):
                db.log("debug" if exists else "warning", "verify.chunk", f"Chunk {message_id} exists={exists}", file_id)
            count += 1
    return count


def verify_due_chunks(db: Database, config: Config, force: bool = False) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=config.verification_interval_days)
    older_than = datetime.max.replace(tzinfo=timezone.utc).isoformat() if force else cutoff.replace(microsecond=0).isoformat()
    chunks = (
        db.chunks_due_for_verification(older_than)
        if force
        else db.chunks_due_for_file_verification(older_than, config.verification_files_per_run)
    )
    return verify_chunks(db, config, chunks)


def verify_file_chunks(db: Database, config: Config, file_ids: Iterable[int]) -> int:
    return verify_chunks(db, config, db.chunks_for_file_ids(file_ids))
