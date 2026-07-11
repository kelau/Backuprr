import email
import hashlib
from pathlib import Path
from typing import Any, Iterator, Optional

from .backup import decode_chunk
from .config import Config
from .db import Database
from .usenet import UsenetClient, select_host


def article_lines(article_response: Any) -> list[bytes]:
    if len(article_response) == 3:
        return list(article_response[2])
    if len(article_response) == 2:
        info = article_response[1]
        if hasattr(info, "lines"):
            return list(info.lines)
    raise RuntimeError("Unexpected NNTP article response format")


def sha256_file(path: Path, block_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(block_size), b""):
            digest.update(block)
    return digest.hexdigest()


def restore_file(db: Database, config: Config, source_path: str, dest: Optional[str] = None) -> Path:
    file_row, chunks = restore_source(db, source_path)
    target = Path(dest) if dest else Path(file_row["path"])
    if target.exists() and target.is_dir():
        target = target / Path(file_row["path"]).name
    target.parent.mkdir(parents=True, exist_ok=True)
    host = select_host(config, "read")
    passphrase = config.encryption_passphrase()
    with UsenetClient(host) as client, target.open("wb") as output:
        if not client.conn:
            raise RuntimeError("NNTP connection not open")
        for chunk in chunks:
            raw = b"\n".join(article_lines(client.conn.article(chunk["message_id"])))
            msg = email.message_from_bytes(raw)
            payload = msg.get_payload(decode=True) or b""
            db.record_transfer_sample("download", len(payload))
            output.write(decode_chunk(payload, passphrase))
    if target.resolve() == Path(file_row["path"]).resolve():
        stat = target.stat()
        db.mark_restored_backed_up(int(file_row["id"]), stat.st_size, stat.st_mtime_ns, sha256_file(target))
    db.log("info", "restore", f"Restored {source_path} to {target}", int(file_row["id"]))
    return target


def restore_source(db: Database, source_path: str) -> tuple[Any, list[Any]]:
    with db.connect() as conn:
        file_row = conn.execute("SELECT * FROM files WHERE path=? OR relative_path=?", (source_path, source_path)).fetchone()
        if not file_row:
            raise FileNotFoundError(f"No cataloged file matches {source_path}")
        chunks = conn.execute("SELECT * FROM chunks WHERE file_id=? ORDER BY chunk_index", (file_row["id"],)).fetchall()
    if not chunks:
        raise RuntimeError(f"No Usenet chunks recorded for {source_path}")
    return file_row, chunks


def restored_payloads(db: Database, config: Config, source_path: str) -> tuple[Any, Iterator[bytes]]:
    file_row, chunks = restore_source(db, source_path)

    def iterator() -> Iterator[bytes]:
        host = select_host(config, "read")
        passphrase = config.encryption_passphrase()
        with UsenetClient(host) as client:
            if not client.conn:
                raise RuntimeError("NNTP connection not open")
            for chunk in chunks:
                raw = b"\n".join(article_lines(client.conn.article(chunk["message_id"])))
                msg = email.message_from_bytes(raw)
                payload = msg.get_payload(decode=True) or b""
                db.record_transfer_sample("download", len(payload))
                yield decode_chunk(payload, passphrase)

    return file_row, iterator()


def restore_sample(db: Database, config: Config, source_path: str, max_bytes: int) -> bytes:
    with db.connect() as conn:
        file_row = conn.execute("SELECT * FROM files WHERE path=? OR relative_path=?", (source_path, source_path)).fetchone()
        if not file_row:
            raise FileNotFoundError(f"No cataloged file matches {source_path}")
        chunks = conn.execute("SELECT * FROM chunks WHERE file_id=? ORDER BY chunk_index LIMIT 2", (file_row["id"],)).fetchall()
    if not chunks:
        raise RuntimeError(f"No Usenet chunks recorded for {source_path}")
    host = select_host(config, "read")
    passphrase = config.encryption_passphrase()
    restored = bytearray()
    with UsenetClient(host) as client:
        if not client.conn:
            raise RuntimeError("NNTP connection not open")
        for chunk in chunks:
            raw = b"\n".join(article_lines(client.conn.article(chunk["message_id"])))
            msg = email.message_from_bytes(raw)
            payload = msg.get_payload(decode=True) or b""
            db.record_transfer_sample("download", len(payload))
            restored.extend(decode_chunk(payload, passphrase))
            if len(restored) >= max_bytes:
                break
    sample = bytes(restored[:max_bytes])
    db.log("info", "restore.sample", f"Restored {len(sample)} sample bytes for {source_path}", int(file_row["id"]))
    return sample


def restore_folder(db: Database, config: Config, folder_path: str, dest: Optional[str] = None) -> int:
    restored = 0
    raw_folder = str(folder_path).rstrip("\\/")
    alt_folder = raw_folder.replace("/", "\\")
    folder = str(Path(folder_path).resolve()) if Path(folder_path).is_absolute() else raw_folder
    with db.connect() as conn:
        rows = conn.execute(
            """
            SELECT path, relative_path FROM files
            WHERE id IN (SELECT DISTINCT file_id FROM chunks)
              AND (path LIKE ? OR relative_path = ? OR relative_path LIKE ? OR relative_path = ? OR relative_path LIKE ?)
            ORDER BY relative_path
            """,
            (
                folder + "%",
                raw_folder,
                raw_folder + "/%",
                alt_folder,
                alt_folder + "\\%",
            ),
        ).fetchall()
    for row in rows:
        source = row["path"]
        target = None
        if dest:
            if Path(folder).is_absolute():
                relative = Path(source).relative_to(folder)
            else:
                relative_text = str(row["relative_path"]).replace("\\", "/")
                relative = Path(relative_text).relative_to(raw_folder.replace("\\", "/"))
            target = str(Path(dest) / relative)
        restore_file(db, config, source, target)
        restored += 1
    return restored
