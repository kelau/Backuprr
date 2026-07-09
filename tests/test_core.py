import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backuprr.backup import decode_chunk, encode_chunk, post_next
from backuprr.config import Config, UsenetHost
from backuprr.crypto import xor_crypt
from backuprr.db import Database
from backuprr.queueing import enqueue_unbacked, prioritize
from backuprr.scanner import scan_all


class FakePostClient:
    def __init__(self, host):
        self.host = host

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def post(self, newsgroup, subject, body):
        return f"<{subject.strip('[] ()').replace(' ', '-')}@example.test>"


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = Database(self.root / "test.sqlite3")
        self.db.init()
        self.config = Config(
            database=str(self.root / "test.sqlite3"),
            article_size=8,
            newsgroup="alt.binaries.backup",
            usenet_hosts=[UsenetHost(name="post", mode="post", host="example.test", port=563, tls="implicit")],
            base_dir=self.root,
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_scan_catalogs_files_and_enqueue_unbacked(self):
        media = self.root / "media"
        media.mkdir()
        (media / "movie.mkv").write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        self.assertEqual(scan_all(self.db), 1)
        self.assertEqual(enqueue_unbacked(self.db), 1)
        stats = self.db.stats()
        self.assertEqual(stats["files_total"], 1)
        self.assertEqual(stats["queue_queued"], 1)

    def test_prioritize_older_first(self):
        media = self.root / "media"
        media.mkdir()
        old = media / "old.mkv"
        new = media / "new.mkv"
        old.write_bytes(b"old")
        new.write_bytes(b"new")
        os.utime(old, (100, 100))
        os.utime(new, (200, 200))
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        self.assertEqual(prioritize(self.db, "older-first"), 2)
        with self.db.connect() as conn:
            first = conn.execute(
                """
                SELECT f.path FROM queue q
                JOIN files f ON f.id=q.file_id
                ORDER BY q.position ASC
                LIMIT 1
                """
            ).fetchone()
        self.assertTrue(first["path"].endswith("old.mkv"))

    def test_post_next_records_chunks_and_obfuscated_subjects(self):
        media = self.root / "media"
        media.mkdir()
        (media / "movie.mkv").write_bytes(b"0123456789abcdef")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        with patch("backuprr.backup.UsenetClient", FakePostClient):
            self.assertIsNotNone(post_next(self.db, self.config))
        with self.db.connect() as conn:
            chunks = conn.execute("SELECT * FROM chunks ORDER BY chunk_index").fetchall()
            file_row = conn.execute("SELECT state FROM files LIMIT 1").fetchone()
        self.assertEqual(len(chunks), 2)
        self.assertEqual(file_row["state"], "backed_up")
        self.assertNotIn("movie.mkv", chunks[0]["subject"])

    def test_encryption_round_trip(self):
        salt = b"1234567890abcdef"
        encrypted = xor_crypt(b"payload", "secret", salt)
        self.assertEqual(xor_crypt(encrypted, "secret", salt), b"payload")
        self.config.encrypt_bodies = True
        self.config.encryption_passphrase_env = "BACKUPRR_TEST_SECRET"
        os.environ["BACKUPRR_TEST_SECRET"] = "secret"
        body = encode_chunk(b"payload", self.config, salt)
        self.assertEqual(decode_chunk(body, "secret"), b"payload")

    def test_missing_chunk_marks_file_and_requeues(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
        self.db.add_chunk(file_id, 0, "<missing@example.test>", 3, "abc", "[hidden]")
        with self.db.connect() as conn:
            chunk_id = conn.execute("SELECT id FROM chunks").fetchone()["id"]
        self.db.mark_chunk_verified(chunk_id, exists=False)
        with self.db.connect() as conn:
            file_row = conn.execute("SELECT state FROM files WHERE id=?", (file_id,)).fetchone()
            queue_row = conn.execute("SELECT status, reason FROM queue WHERE file_id=?", (file_id,)).fetchone()
        self.assertEqual(file_row["state"], "queued")
        self.assertEqual(queue_row["status"], "queued")
        self.assertEqual(queue_row["reason"], "missing-chunks")


if __name__ == "__main__":
    unittest.main()

