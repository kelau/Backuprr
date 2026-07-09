import hashlib
import os
import subprocess
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Optional

from .config import Config
from .crypto import xor_crypt
from .db import Database, utcnow
from .usenet import UsenetClient, obfuscated_subject, select_host


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


def post_next(db: Database, config: Config) -> Optional[int]:
    item = db.next_queue_item()
    if not item:
        return None
    file_id = int(item["file_id"])
    original = Path(item["path"])
    if not original.exists():
        db.update_file_state(file_id, "failed")
        db.set_queue_status(file_id, "failed")
        db.log("error", "post", f"Queued file no longer exists: {original}", file_id)
        return file_id
    host = select_host(config, "post")
    db.set_queue_status(file_id, "posting")
    db.update_file_state(file_id, "posting")
    cleared = db.clear_chunks(file_id)
    if cleared:
        db.log("debug", "post.retry", f"Cleared {cleared} partial chunk records before retrying {original}", file_id)
    payload = prepare_payload(original, config)
    try:
        def post_chunk(chunk_index: int, chunk: bytes) -> tuple[int, str, int, str, str]:
            salt = os.urandom(16)
            body = encode_chunk(chunk, config, salt)
            digest = hashlib.sha256(body).hexdigest()
            subject = obfuscated_subject(file_id, chunk_index, digest)
            with UsenetClient(host) as client:
                message_id = client.post(config.newsgroup, subject, body)
            return chunk_index, message_id, len(body), digest, subject

        max_workers = max(1, int(config.nntp_threads))
        futures = []
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="backuprr-post") as executor:
            for chunk_index, chunk in enumerate(iter_chunks(payload, config.article_size)):
                futures.append(executor.submit(post_chunk, chunk_index, chunk))
            for future in as_completed(futures):
                chunk_index, message_id, body_size, digest, subject = future.result()
                db.add_chunk(file_id, chunk_index, message_id, body_size, digest, subject)
                db.log("debug", "post.chunk", f"Posted chunk {chunk_index} for {original}", file_id)
        with db.connect() as conn:
            conn.execute("UPDATE files SET state='backed_up', last_backup_at=?, updated_at=? WHERE id=?", (utcnow(), utcnow(), file_id))
            conn.execute("UPDATE queue SET status='done', updated_at=? WHERE file_id=?", (utcnow(), file_id))
        db.log("info", "post", f"Posted backup for {original}", file_id)
        return file_id
    except Exception as exc:
        db.update_file_state(file_id, "failed")
        db.set_queue_status(file_id, "failed")
        db.log("error", "post", f"Failed posting {original}: {exc}", file_id)
        raise
    finally:
        cleanup_payload(payload, original)


def verify_due_chunks(db: Database, config: Config, force: bool = False) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=config.verification_interval_days)
    older_than = datetime.max.replace(tzinfo=timezone.utc).isoformat() if force else cutoff.replace(microsecond=0).isoformat()
    chunks = db.chunks_due_for_verification(older_than)
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
            db.log("debug" if exists else "warning", "verify.chunk", f"Chunk {message_id} exists={exists}", file_id)
            count += 1
    return count
