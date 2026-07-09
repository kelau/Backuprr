import email
from pathlib import Path
from typing import Optional

from .backup import decode_chunk
from .config import Config
from .db import Database
from .usenet import UsenetClient, select_host


def restore_file(db: Database, config: Config, source_path: str, dest: Optional[str] = None) -> Path:
    with db.connect() as conn:
        file_row = conn.execute("SELECT * FROM files WHERE path=? OR relative_path=?", (source_path, source_path)).fetchone()
        if not file_row:
            raise FileNotFoundError(f"No cataloged file matches {source_path}")
        chunks = conn.execute("SELECT * FROM chunks WHERE file_id=? ORDER BY chunk_index", (file_row["id"],)).fetchall()
    if not chunks:
        raise RuntimeError(f"No Usenet chunks recorded for {source_path}")
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
            _resp, _info, article_lines = client.conn.article(chunk["message_id"])
            raw = b"\n".join(article_lines)
            msg = email.message_from_bytes(raw)
            payload = msg.get_payload(decode=True) or b""
            output.write(decode_chunk(payload, passphrase))
    db.update_file_state(int(file_row["id"]), "restored")
    db.log("info", "restore", f"Restored {source_path} to {target}", int(file_row["id"]))
    return target


def restore_folder(db: Database, config: Config, folder_path: str, dest: Optional[str] = None) -> int:
    restored = 0
    folder = str(Path(folder_path).resolve())
    with db.connect() as conn:
        rows = conn.execute("SELECT path FROM files WHERE path LIKE ? ORDER BY path", (folder + "%",)).fetchall()
    for row in rows:
        source = row["path"]
        target = None
        if dest:
            relative = Path(source).relative_to(folder)
            target = str(Path(dest) / relative)
        restore_file(db, config, source, target)
        restored += 1
    return restored

