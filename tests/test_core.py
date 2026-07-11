import io
import os
import email.message
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from backuprr import __version__
from backuprr.backup import decode_chunk, encode_chunk, post_next, verify_due_chunks, verify_file_chunks
from backuprr.cloud_backup import backup_config_and_database, backup_config_and_database_if_changed
from backuprr.config import Config, LogDestination, UsenetHost, update_config
from backuprr.crypto import xor_crypt
from backuprr.db import Database
from backuprr.log_forwarding import build_payload
from backuprr.monitor import BackupMonitor, CatalogMonitor, VerificationMonitor, CloudBackupMonitor, format_duration
from backuprr.operations import check_usenet_hosts, dry_run_plan, restore_confidence, restore_plan, run_maintenance, run_restore_drill, test_post_host_article_size
from backuprr.queueing import enqueue_unbacked, excluded_by_auto_queue_filter, prioritize
from backuprr.restore import restore_file, restore_sample
from backuprr.scanner import scan_all
from backuprr.web import ResponseZipWriter, hourly_post_budget, thread_usage_summary, throughput_summary


class FakePostClient:
    def __init__(self, host):
        self.host = host

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def post(self, newsgroup, subject, body):
        return f"<{subject.strip('[] ()').replace(' ', '-')}@example.test>"


class CountingPostClient(FakePostClient):
    posts = []

    def post(self, newsgroup, subject, body):
        self.__class__.posts.append((subject, body))
        return super().post(newsgroup, subject, body)


class LimitedPostClient(FakePostClient):
    max_size = 300 * 1024
    attempts = []

    def post(self, newsgroup, subject, body):
        self.__class__.attempts.append(len(body))
        if len(body) > self.__class__.max_size:
            raise RuntimeError("article too large")
        return super().post(newsgroup, subject, body)


class FakeReadClient:
    def __init__(self, host):
        self.host = host

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def article_exists(self, message_id):
        return True


class FakeSocketPermissionError(OSError):
    @property
    def winerror(self):
        return 10013


class FakeArticleInfo:
    def __init__(self, lines):
        self.lines = lines


class FakeRestoreConn:
    def __init__(self, body: bytes):
        msg = email.message.EmailMessage()
        msg["Subject"] = "restore"
        msg.set_content(body, maintype="application", subtype="octet-stream", cte="base64")
        self.lines = msg.as_bytes().splitlines()

    def article(self, message_id):
        return "220 0 article retrieved", FakeArticleInfo(self.lines)


class FakeRestoreClient:
    def __init__(self, host):
        self.host = host
        self.conn = FakeRestoreConn(b"restored payload")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = Database(self.root / "test.sqlite3")
        self.db.init()
        self.config = Config(
            database=str(self.root / "test.sqlite3"),
            article_size=8,
            file_stability_seconds=0,
            newsgroup="alt.binaries.backup",
            usenet_hosts=[UsenetHost(name="post", mode="post", host="example.test", port=563, tls="implicit")],
            base_dir=self.root,
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_version_is_incremented_for_changes(self):
        self.assertEqual(__version__, "0.2.46")

    def test_response_zip_writer_supports_streamed_zip_downloads(self):
        buffer = io.BytesIO()
        writer = ResponseZipWriter(buffer)
        with zipfile.ZipFile(writer, "w") as archive:
            archive.writestr("sample.txt", b"payload")

        with zipfile.ZipFile(io.BytesIO(buffer.getvalue()), "r") as archive:
            self.assertEqual(archive.read("sample.txt"), b"payload")

    def test_queue_schema_tracks_live_posting_progress(self):
        with self.db.connect() as conn:
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(queue)").fetchall()}
        self.assertIn("progress_chunks", columns)
        self.assertIn("progress_bytes", columns)

    def test_chunk_schema_tracks_article_size_for_resume(self):
        with self.db.connect() as conn:
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(chunks)").fetchall()}
        self.assertIn("article_size", columns)

    def test_operational_tables_exist(self):
        with self.db.connect() as conn:
            tables = {
                row["name"]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }
        self.assertIn("backup_runs", tables)
        self.assertIn("backup_manifests", tables)
        self.assertIn("host_stats", tables)
        self.assertIn("maintenance_runs", tables)
        self.assertIn("restore_drills", tables)

    def test_article_size_probe_records_largest_supported_size(self):
        LimitedPostClient.max_size = 300 * 1024
        LimitedPostClient.attempts = []
        with patch("backuprr.operations.UsenetClient", LimitedPostClient):
            size = test_post_host_article_size(
                self.db,
                self.config,
                "post",
                min_bytes=100 * 1024,
                max_bytes=500 * 1024,
                step_bytes=100 * 1024,
            )
        self.assertEqual(size, 300 * 1024)
        self.assertIn(300 * 1024, LimitedPostClient.attempts)
        health = self.db.host_health_rows()
        self.assertEqual(health[0]["status"], "article_size")
        self.assertEqual(health[0]["article_size_bytes"], 300 * 1024)

    def test_health_check_runs_article_size_probe_for_post_hosts(self):
        LimitedPostClient.max_size = 200 * 1024
        LimitedPostClient.attempts = []
        with patch("backuprr.operations.UsenetClient", LimitedPostClient):
            results = check_usenet_hosts(self.db, self.config)
        self.assertEqual(results[0]["status"], "ok")
        self.assertEqual(results[0]["article_size_bytes"], 200 * 1024)
        self.assertIn("max article size", results[0]["message"])

    def test_provider_profiles_and_table_stats_are_available(self):
        self.db.record_host_check("post", "post", "ok", "ok", latency_ms=10, article_size_bytes=1024)
        self.db.record_host_check("post", "post", "failed", "nope", latency_ms=30)
        profiles = self.db.provider_profiles()
        self.assertEqual(profiles[0]["host_name"], "post")
        self.assertEqual(profiles[0]["checks"], 2)
        self.assertEqual(profiles[0]["failures"], 1)
        self.assertEqual(profiles[0]["max_article_size_bytes"], 1024)
        table_stats = {row["table"]: row for row in self.db.table_stats()}
        self.assertIn("backup_manifests", table_stats)
        self.assertIn("estimated_bytes", table_stats["files"])

    def test_verification_rows_can_be_split_by_verification_state(self):
        media = self.root / "media"
        media.mkdir()
        for name in ["verified.mkv", "unverified.mkv", "missing.mkv", "no-chunks.mkv"]:
            (media / name).write_bytes(name.encode("utf-8"))
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            ids = {row["relative_path"]: row["id"] for row in conn.execute("SELECT id, relative_path FROM files").fetchall()}
            conn.execute("UPDATE files SET state='backed_up'")
        self.db.add_chunk(ids["verified.mkv"], 0, "<verified@example.test>", 8, "sha", "")
        self.db.add_chunk(ids["unverified.mkv"], 0, "<unverified@example.test>", 8, "sha", "")
        self.db.add_chunk(ids["missing.mkv"], 0, "<missing@example.test>", 8, "sha", "")
        with self.db.connect() as conn:
            verified_chunk_id = conn.execute("SELECT id FROM chunks WHERE file_id=?", (ids["verified.mkv"],)).fetchone()["id"]
            missing_chunk_id = conn.execute("SELECT id FROM chunks WHERE file_id=?", (ids["missing.mkv"],)).fetchone()["id"]
        self.db.mark_chunk_verified(verified_chunk_id, True)
        self.db.mark_chunk_verified(missing_chunk_id, False)

        self.assertEqual(self.db.verification_count("verified"), 1)
        self.assertEqual(self.db.verification_count("unverified"), 1)
        self.assertEqual(self.db.verification_count("missing"), 1)
        self.assertEqual(self.db.verification_count("no_chunks"), 1)
        rows = self.db.verification_rows(10, 0, "missing")
        self.assertEqual(rows[0]["relative_path"], "missing.mkv")
        self.assertEqual(rows[0]["verification_state"], "missing")

    def test_verification_rows_can_be_filtered_by_text(self):
        media = self.root / "media"
        media.mkdir()
        (media / "proxmox.iso").write_bytes(b"iso")
        (media / "ubuntu.iso").write_bytes(b"iso")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            file_ids = [row["id"] for row in conn.execute("SELECT id FROM files").fetchall()]
        for file_id in file_ids:
            self.db.add_chunk(file_id, 0, f"<{file_id}@example.test>", 3, "sha", "")
        rows = self.db.verification_rows(10, 0, "unverified", "proxmox")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["relative_path"], "proxmox.iso")
        self.assertEqual(self.db.verification_count("unverified", "proxmox"), 1)

    def test_event_log_supports_text_filter_count_and_pagination(self):
        self.db.log("info", "backup.task", "Posting proxmox iso")
        self.db.log("warning", "verify.chunk", "Missing ubuntu chunk")
        self.db.log("debug", "backup.task", "Posting proxmox chunk")
        rows = self.db.list_events(["info", "debug"], limit=1, offset=0, search="proxmox")
        self.assertEqual(len(rows), 1)
        self.assertIn("proxmox", rows[0]["message"])
        self.assertEqual(self.db.event_count(["info", "debug"], search="proxmox"), 2)
        second = self.db.list_events(["info", "debug"], limit=1, offset=1, search="proxmox")
        self.assertEqual(len(second), 1)
        self.assertNotEqual(rows[0]["id"], second[0]["id"])

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

    def test_auto_queue_exclude_patterns_skip_matching_files(self):
        media = self.root / "media"
        media.mkdir()
        (media / "movie.mkv").write_bytes(b"abc")
        (media / "sample.tmp").write_bytes(b"tmp")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        self.config.auto_queue_exclude_patterns = ["*.tmp"]
        self.assertEqual(enqueue_unbacked(self.db, self.config), 1)
        with self.db.connect() as conn:
            queued = conn.execute(
                """
                SELECT f.relative_path FROM queue q
                JOIN files f ON f.id=q.file_id
                ORDER BY f.relative_path
                """
            ).fetchall()
        self.assertEqual([row["relative_path"] for row in queued], ["movie.mkv"])

    def test_auto_queue_exclude_patterns_accept_extension_shorthand_and_regex(self):
        self.assertTrue(excluded_by_auto_queue_filter("C:/media/trailer.mp4", "trailer.mp4", ["MP4"]))
        self.assertTrue(excluded_by_auto_queue_filter("C:/media/trailer.MP4", "trailer.MP4", [".mp4"]))
        self.assertTrue(excluded_by_auto_queue_filter("C:/media/trailer.mp4", "trailer.mp4", ["*.mp4"]))
        self.assertTrue(excluded_by_auto_queue_filter("C:/media/Season 01/trailer.mkv", "Season 01/trailer.mkv", [r"regex:Season \d+"]))
        self.assertTrue(excluded_by_auto_queue_filter("C:/media/sample-trailer.mkv", "sample-trailer.mkv", [r"/sample-.+\.mkv$/"]))
        self.assertFalse(excluded_by_auto_queue_filter("C:/media/movie.mkv", "movie.mkv", ["MP4", r"regex:sample"]))
        self.assertFalse(excluded_by_auto_queue_filter("C:/media/movie.mkv", "movie.mkv", ["regex:["]))

    def test_stats_exclude_deleted_from_active_total(self):
        media = self.root / "media"
        media.mkdir()
        deleted = media / "deleted.mkv"
        active = media / "active.mkv"
        deleted.write_bytes(b"deleted")
        active.write_bytes(b"active")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        deleted.unlink()
        scan_all(self.db)
        stats = self.db.stats()
        self.assertEqual(stats["files_total"], 1)
        self.assertEqual(stats["files_all_total"], 2)
        self.assertEqual(stats["files_deleted"], 1)

    def test_scan_updates_relative_path_for_moved_file(self):
        media = self.root / "media"
        media.mkdir()
        original = media / "movie.mkv"
        original.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        self.assertEqual(scan_all(self.db), 1)
        subfolder = media / "subfolder"
        subfolder.mkdir()
        moved = subfolder / "movie.mkv"
        original.rename(moved)
        self.assertEqual(scan_all(self.db), 1)
        with self.db.connect() as conn:
            rows = conn.execute("SELECT path, relative_path, state FROM files").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["path"], str(moved.resolve()))
        self.assertEqual(rows[0]["relative_path"], str(Path("subfolder") / "movie.mkv"))
        self.assertNotEqual(rows[0]["state"], "deleted")

    def test_scan_skips_hashing_unchanged_files(self):
        media = self.root / "media"
        media.mkdir()
        movie = media / "movie.mkv"
        movie.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        self.assertEqual(scan_all(self.db), 1)
        with patch("backuprr.scanner.sha256_file", side_effect=AssertionError("unchanged file should not be rehashed")):
            self.assertEqual(scan_all(self.db), 1)

    def test_scan_preserves_backed_up_state_when_only_mtime_changes(self):
        media = self.root / "media"
        media.mkdir()
        movie = media / "movie.mkv"
        movie.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db, self.config)
        with patch("backuprr.backup.UsenetClient", FakePostClient):
            self.assertIsNotNone(post_next(self.db, self.config))
        os.utime(movie, (movie.stat().st_atime + 10, movie.stat().st_mtime + 10))
        self.assertEqual(scan_all(self.db), 1)
        self.assertEqual(enqueue_unbacked(self.db, self.config), 0)
        with self.db.connect() as conn:
            row = conn.execute("SELECT state, sha256 FROM files WHERE path=?", (str(movie.resolve()),)).fetchone()
            queue_row = conn.execute("SELECT status FROM queue").fetchone()
        self.assertEqual(row["state"], "backed_up")
        self.assertEqual(queue_row["status"], "done")

    def test_scan_revives_deleted_file_at_same_path(self):
        media = self.root / "media"
        media.mkdir()
        movie = media / "movie.mkv"
        movie.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        self.assertEqual(scan_all(self.db), 1)
        with self.db.connect() as conn:
            conn.execute("UPDATE files SET state='deleted' WHERE path=?", (str(movie.resolve()),))
        self.assertEqual(scan_all(self.db), 1)
        with self.db.connect() as conn:
            row = conn.execute("SELECT state FROM files WHERE path=?", (str(movie.resolve()),)).fetchone()
        self.assertEqual(row["state"], "discovered")
        with patch("backuprr.scanner.sha256_file", side_effect=AssertionError("revived unchanged file should not be rehashed")):
            self.assertEqual(scan_all(self.db), 1)

    def test_auto_queue_waits_for_file_stability_window(self):
        media = self.root / "media"
        media.mkdir()
        movie = media / "movie.mkv"
        movie.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        self.assertEqual(scan_all(self.db), 1)
        self.config.file_stability_seconds = 3600
        self.assertEqual(enqueue_unbacked(self.db, self.config), 0)
        self.config.file_stability_seconds = 0
        self.assertEqual(enqueue_unbacked(self.db, self.config), 1)

    def test_scan_skips_unreadable_file_content(self):
        media = self.root / "media"
        media.mkdir()
        movie = media / "locked.iso"
        movie.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        with patch("backuprr.scanner.sha256_file", side_effect=PermissionError("locked")):
            self.assertEqual(scan_all(self.db), 0)
        rows = self.db.list_events(["warning"], event_types=["scan.file_error"])
        self.assertEqual(len(rows), 1)
        self.assertIn("Skipped unreadable file content", rows[0]["message"])

    def test_scan_holds_queued_file_when_content_becomes_unreadable(self):
        media = self.root / "media"
        media.mkdir()
        movie = media / "locked.iso"
        movie.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        self.assertEqual(scan_all(self.db), 1)
        self.assertEqual(enqueue_unbacked(self.db), 1)
        movie.write_bytes(b"abcd")
        with patch("backuprr.scanner.sha256_file", side_effect=PermissionError("locked")):
            self.assertEqual(scan_all(self.db), 0)
        with self.db.connect() as conn:
            file_row = conn.execute("SELECT id, state FROM files WHERE path=?", (str(movie.resolve()),)).fetchone()
            queue_row = conn.execute("SELECT status, reason FROM queue WHERE file_id=?", (file_row["id"],)).fetchone()
        self.assertEqual(file_row["state"], "unreadable")
        self.assertEqual(queue_row["status"], "failed")
        self.assertEqual(queue_row["reason"], "file-unreadable")
        self.assertEqual(self.db.next_queue_item(), None)

    def test_scan_holds_unchanged_queued_file_when_read_probe_fails(self):
        media = self.root / "media"
        media.mkdir()
        movie = media / "locked.iso"
        movie.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        with patch("backuprr.scanner.ensure_readable", side_effect=PermissionError("locked")):
            self.assertEqual(scan_all(self.db), 0)
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT f.state, q.status, q.reason
                FROM files f
                JOIN queue q ON q.file_id = f.id
                WHERE f.path=?
                """,
                (str(movie.resolve()),),
            ).fetchone()
        self.assertEqual(row["state"], "unreadable")
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["reason"], "file-unreadable")

    def test_scan_holds_queued_file_when_is_file_check_fails(self):
        media = self.root / "media"
        media.mkdir()
        movie = media / "locked.iso"
        movie.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        original_is_file = Path.is_file

        def fail_locked(path):
            if path.name == "locked.iso":
                raise PermissionError("locked")
            return original_is_file(path)

        with patch.object(Path, "is_file", autospec=True, side_effect=fail_locked):
            self.assertEqual(scan_all(self.db), 0)
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT f.state, q.status, q.reason
                FROM files f
                JOIN queue q ON q.file_id = f.id
                WHERE f.path=?
                """,
                (str(movie.resolve()),),
            ).fetchone()
        self.assertEqual(row["state"], "unreadable")
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["reason"], "file-unreadable")

    def test_scan_revives_unreadable_file_after_successful_read(self):
        media = self.root / "media"
        media.mkdir()
        movie = media / "locked.iso"
        movie.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        movie.write_bytes(b"abcd")
        with patch("backuprr.scanner.sha256_file", side_effect=PermissionError("locked")):
            scan_all(self.db)
        self.assertEqual(scan_all(self.db), 1)
        self.assertEqual(enqueue_unbacked(self.db), 1)
        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT f.state, q.status, q.reason
                FROM files f
                JOIN queue q ON q.file_id = f.id
                WHERE f.path=?
                """,
                (str(movie.resolve()),),
            ).fetchone()
        self.assertEqual(row["state"], "queued")
        self.assertEqual(row["status"], "queued")
        self.assertEqual(row["reason"], "unbacked")

    def test_scan_updates_moved_file_without_rehash_when_metadata_matches(self):
        media = self.root / "media"
        media.mkdir()
        original = media / "movie.mkv"
        original.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        self.assertEqual(scan_all(self.db), 1)
        subfolder = media / "season"
        subfolder.mkdir()
        moved = subfolder / "movie.mkv"
        original.rename(moved)
        with patch("backuprr.scanner.sha256_file", side_effect=AssertionError("metadata-matched move should not be rehashed")):
            self.assertEqual(scan_all(self.db), 1)
        with self.db.connect() as conn:
            row = conn.execute("SELECT path, relative_path FROM files").fetchone()
        self.assertEqual(row["path"], str(moved.resolve()))
        self.assertEqual(row["relative_path"], str(Path("season") / "movie.mkv"))

    def test_scan_reconciles_existing_deleted_and_discovered_move_split(self):
        media = self.root / "media"
        media.mkdir()
        original = media / "movie.mkv"
        original.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        subfolder = media / "subfolder"
        subfolder.mkdir()
        moved = subfolder / "movie.mkv"
        original.rename(moved)
        with self.db.connect() as conn:
            old = conn.execute("SELECT * FROM files WHERE relative_path='movie.mkv'").fetchone()
            conn.execute("UPDATE files SET state='deleted' WHERE id=?", (old["id"],))
            conn.execute(
                """
                INSERT INTO files(endpoint_id, path, relative_path, size, mtime_ns, sha256, state, created_at, updated_at)
                VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    old["endpoint_id"],
                    str(moved.resolve()),
                    str(Path("subfolder") / "movie.mkv"),
                    old["size"],
                    moved.stat().st_mtime_ns,
                    old["sha256"],
                    "discovered",
                    old["created_at"],
                    old["updated_at"],
                ),
            )
        scan_all(self.db)
        with self.db.connect() as conn:
            rows = conn.execute("SELECT path, relative_path, state FROM files").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["path"], str(moved.resolve()))
        self.assertEqual(rows[0]["relative_path"], str(Path("subfolder") / "movie.mkv"))
        self.assertEqual(rows[0]["state"], "discovered")

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
        self.assertEqual(chunks[0]["subject"], "")
        self.assertEqual(chunks[0]["sha256"], "")
        runs = self.db.backup_run_rows()
        self.assertEqual(runs[0]["status"], "done")
        self.assertEqual(runs[0]["chunks_done"], 2)
        manifests = self.db.backup_manifest_rows()
        self.assertEqual(manifests[0]["file_id"], int(chunks[0]["file_id"]))
        self.assertEqual(manifests[0]["article_size"], 8)
        self.assertEqual(manifests[0]["chunk_count"], 2)
        self.assertEqual(self.db.list_events(["debug"], event_types=["post.chunk"]), [])

    def test_chunk_event_logging_can_be_enabled(self):
        media = self.root / "media"
        media.mkdir()
        (media / "movie.mkv").write_bytes(b"0123456789abcdef")
        self.config.log_chunk_events = True
        self.config.compact_chunk_metadata = False
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        with patch("backuprr.backup.UsenetClient", FakePostClient):
            self.assertIsNotNone(post_next(self.db, self.config))
        self.assertGreater(len(self.db.list_events(["debug"], event_types=["post.chunk"])), 0)
        with self.db.connect() as conn:
            chunk = conn.execute("SELECT sha256, subject FROM chunks ORDER BY chunk_index LIMIT 1").fetchone()
        self.assertTrue(chunk["sha256"])
        self.assertTrue(chunk["subject"])

    def test_post_next_honors_hourly_post_limit(self):
        media = self.root / "media"
        media.mkdir()
        (media / "movie.mkv").write_bytes(b"0123456789abcdef")
        self.config.article_size = 8
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        self.config.hourly_post_limit_bytes = 4
        self.db.record_transfer_sample("upload", 4)
        with patch("backuprr.backup.UsenetClient", FakePostClient):
            self.assertIsNone(post_next(self.db, self.config))
        with self.db.connect() as conn:
            queue_row = conn.execute("SELECT status FROM queue").fetchone()
        self.assertEqual(queue_row["status"], "queued")

    def test_post_next_waits_for_queued_file_stability(self):
        media = self.root / "media"
        media.mkdir()
        (media / "movie.mkv").write_bytes(b"0123456789abcdef")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        self.config.file_stability_seconds = 3600
        with patch("backuprr.backup.UsenetClient", side_effect=AssertionError("unstable file should not post")):
            self.assertIsNone(post_next(self.db, self.config))
        with self.db.connect() as conn:
            queue_row = conn.execute("SELECT status, reason FROM queue").fetchone()
        self.assertEqual(queue_row["status"], "queued")
        self.assertEqual(queue_row["reason"], "file-changing")

    def test_post_next_pauses_large_file_at_hourly_limit_and_resumes(self):
        media = self.root / "media"
        media.mkdir()
        (media / "movie.mkv").write_bytes(b"0123456789abcdef")
        self.config.article_size = 8
        self.config.hourly_post_limit_bytes = 12
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        CountingPostClient.posts = []
        with patch("backuprr.backup.UsenetClient", CountingPostClient):
            self.assertIsNone(post_next(self.db, self.config))
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
            queue_row = conn.execute("SELECT status, reason, progress_chunks FROM queue WHERE file_id=?", (file_id,)).fetchone()
            chunks = conn.execute("SELECT chunk_index, article_size FROM chunks WHERE file_id=?", (file_id,)).fetchall()
            conn.execute("DELETE FROM transfer_samples")
        self.assertEqual(queue_row["status"], "queued")
        self.assertEqual(queue_row["reason"], "hourly-limit")
        self.assertEqual(queue_row["progress_chunks"], 1)
        self.assertEqual([(row["chunk_index"], row["article_size"]) for row in chunks], [(0, 8)])
        self.assertEqual(len(CountingPostClient.posts), 1)

        self.config.hourly_post_limit_bytes = 100
        CountingPostClient.posts = []
        with patch("backuprr.backup.UsenetClient", CountingPostClient):
            self.assertIsNotNone(post_next(self.db, self.config))
        with self.db.connect() as conn:
            queue_row = conn.execute("SELECT status, progress_chunks FROM queue WHERE file_id=?", (file_id,)).fetchone()
            file_row = conn.execute("SELECT state FROM files WHERE id=?", (file_id,)).fetchone()
        self.assertEqual(queue_row["status"], "done")
        self.assertEqual(queue_row["progress_chunks"], 2)
        self.assertEqual(file_row["state"], "backed_up")
        self.assertEqual(len(CountingPostClient.posts), 1)

    def test_dry_run_plan_estimates_articles_and_limit_time(self):
        media = self.root / "media"
        media.mkdir()
        (media / "movie.mkv").write_bytes(b"0123456789abcdef")
        self.config.article_size = 8
        self.config.hourly_post_limit_bytes = 16
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        plan = dry_run_plan(self.db, self.config)
        self.assertEqual(plan["estimated_articles"], 2)
        self.assertEqual(plan["estimated_hours_at_limit"], 1.0)

    def test_maintenance_prunes_old_verbose_events(self):
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO events(ts, level, event_type, message, data) VALUES(?,?,?,?,?)",
                ("2000-01-01T00:00:00+00:00", "verbose", "old", "old", ""),
            )
            conn.execute("INSERT INTO transfer_samples(ts, direction, size) VALUES(?,?,?)", ("2026-01-01T00:00:01+00:00", "upload", 1))
            conn.execute("INSERT INTO transfer_samples(ts, direction, size) VALUES(?,?,?)", ("2026-01-01T00:00:02+00:00", "upload", 2))
        self.config.log_retention_days = 3650
        self.config.verbose_log_retention_days = 1
        result = run_maintenance(self.db, self.config)
        self.assertGreaterEqual(result["pruned_events"], 1)
        self.assertGreaterEqual(result["compacted_transfer_samples"], 1)
        self.assertEqual(len(self.db.maintenance_rows()), 1)

    def test_transfer_samples_aggregate_by_minute(self):
        self.db.record_transfer_sample("upload", 4)
        self.db.record_transfer_sample("upload", 6)
        with self.db.connect() as conn:
            rows = conn.execute("SELECT direction, size FROM transfer_samples").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["direction"], "upload")
        self.assertEqual(rows[0]["size"], 10)

    def test_post_next_replaces_chunks_after_successful_retry(self):
        media = self.root / "media"
        media.mkdir()
        (media / "movie.mkv").write_bytes(b"0123456789abcdef")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
        self.db.add_chunk(file_id, 0, "<old@example.test>", 3, "abc", "[old]")
        with patch("backuprr.backup.UsenetClient", FakePostClient):
            self.assertIsNotNone(post_next(self.db, self.config))
        with self.db.connect() as conn:
            chunks = conn.execute("SELECT message_id FROM chunks WHERE file_id=? ORDER BY chunk_index", (file_id,)).fetchall()
        self.assertTrue(chunks)
        self.assertNotEqual(chunks[0]["message_id"], "<old@example.test>")

    def test_post_next_resumes_interrupted_post_from_cataloged_chunks(self):
        media = self.root / "media"
        media.mkdir()
        (media / "movie.mkv").write_bytes(b"0123456789abcdef")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
            conn.execute("UPDATE files SET state='queued' WHERE id=?", (file_id,))
            conn.execute("UPDATE queue SET reason='startup-posting-retry' WHERE file_id=?", (file_id,))
        self.db.add_chunk(file_id, 0, "<old-existing@example.test>", 8, "abc", "[old]", article_size=8)
        CountingPostClient.posts = []
        with patch("backuprr.backup.UsenetClient", CountingPostClient):
            self.assertIsNotNone(post_next(self.db, self.config))
        with self.db.connect() as conn:
            chunks = conn.execute("SELECT chunk_index, message_id FROM chunks WHERE file_id=? ORDER BY chunk_index", (file_id,)).fetchall()
            queue_row = conn.execute("SELECT progress_chunks FROM queue WHERE file_id=?", (file_id,)).fetchone()
        self.assertEqual(len(CountingPostClient.posts), 1)
        self.assertEqual([row["chunk_index"] for row in chunks], [0, 1])
        self.assertEqual(chunks[0]["message_id"], "<old-existing@example.test>")
        self.assertEqual(queue_row["progress_chunks"], 2)

    def test_post_next_restarts_partial_chunks_when_article_size_changes(self):
        media = self.root / "media"
        media.mkdir()
        (media / "movie.mkv").write_bytes(b"0123456789abcdef")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
            conn.execute("UPDATE files SET state='queued' WHERE id=?", (file_id,))
            conn.execute("UPDATE queue SET reason='startup-posting-retry' WHERE file_id=?", (file_id,))
        self.db.add_chunk(file_id, 0, "<old-existing@example.test>", 8, "abc", "[old]", article_size=8)
        self.config.article_size = 4
        CountingPostClient.posts = []
        with patch("backuprr.backup.UsenetClient", CountingPostClient):
            self.assertIsNotNone(post_next(self.db, self.config))
        with self.db.connect() as conn:
            chunks = conn.execute(
                "SELECT chunk_index, message_id, article_size FROM chunks WHERE file_id=? ORDER BY chunk_index",
                (file_id,),
            ).fetchall()
            queue_row = conn.execute("SELECT progress_chunks FROM queue WHERE file_id=?", (file_id,)).fetchone()
        self.assertEqual(len(CountingPostClient.posts), 4)
        self.assertEqual([row["chunk_index"] for row in chunks], [0, 1, 2, 3])
        self.assertNotEqual(chunks[0]["message_id"], "<old-existing@example.test>")
        self.assertEqual({row["article_size"] for row in chunks}, {4})
        self.assertEqual(queue_row["progress_chunks"], 4)

    def test_missing_par2_command_fails_queue_item_cleanly(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"0123456789abcdef")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        self.config.par2 = {"enabled": True, "command": "definitely-missing-par2", "redundancy_percent": 10}
        with self.assertRaisesRegex(RuntimeError, "PAR2 command not found"):
            post_next(self.db, self.config)
        with self.db.connect() as conn:
            file_row = conn.execute("SELECT state FROM files").fetchone()
            queue_row = conn.execute("SELECT status FROM queue").fetchone()
            event = conn.execute("SELECT message FROM events WHERE event_type='post' ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(file_row["state"], "failed")
        self.assertEqual(queue_row["status"], "failed")
        self.assertIn("PAR2 command not found", event["message"])

    def test_failed_rebackup_preserves_existing_chunks(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"0123456789abcdef")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
        self.db.add_chunk(file_id, 0, "<old@example.test>", 3, "abc", "[old]")
        self.config.par2 = {"enabled": True, "command": "definitely-missing-par2", "redundancy_percent": 10}
        with self.assertRaisesRegex(RuntimeError, "PAR2 command not found"):
            post_next(self.db, self.config)
        with self.db.connect() as conn:
            chunks = conn.execute("SELECT message_id FROM chunks WHERE file_id=?", (file_id,)).fetchall()
        self.assertEqual([row["message_id"] for row in chunks], ["<old@example.test>"])

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

    def test_all_chunks_verified_updates_last_verify_at(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
        self.db.add_chunk(file_id, 0, "<one@example.test>", 3, "abc", "[one]")
        self.db.add_chunk(file_id, 1, "<two@example.test>", 3, "def", "[two]")
        with self.db.connect() as conn:
            chunk_ids = [row["id"] for row in conn.execute("SELECT id FROM chunks ORDER BY id").fetchall()]
        self.db.mark_chunk_verified(chunk_ids[0], exists=True)
        with self.db.connect() as conn:
            self.assertIsNone(conn.execute("SELECT last_verify_at FROM files WHERE id=?", (file_id,)).fetchone()["last_verify_at"])
        self.db.mark_chunk_verified(chunk_ids[1], exists=True)
        with self.db.connect() as conn:
            self.assertIsNotNone(conn.execute("SELECT last_verify_at FROM files WHERE id=?", (file_id,)).fetchone()["last_verify_at"])

    def test_queue_hides_completed_backed_up_files_by_default(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
            conn.execute("UPDATE files SET state='backed_up' WHERE id=?", (file_id,))
        self.db.cleanup_completed_queue()
        self.assertEqual(len(self.db.list_queue()), 0)
        self.assertEqual(len(self.db.list_queue(include_done=True)), 1)

    def test_queue_hides_failed_files_by_default(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
        self.db.update_file_state(file_id, "failed")
        self.db.set_queue_status(file_id, "failed")
        self.assertEqual(len(self.db.list_queue()), 0)
        self.assertEqual(len(self.db.list_queue(status="failed")), 1)

    def test_queue_uses_live_progress_for_active_posting(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"0123456789abcdef")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
        self.db.set_queue_status(file_id, "posting")
        self.db.update_file_state(file_id, "posting")
        self.db.set_queue_progress(file_id, 1, 8)
        row = self.db.list_queue()[0]
        self.assertEqual(row["posted_chunks"], 1)
        self.assertEqual(row["posted_bytes"], 8)

    def test_file_rows_include_live_queue_progress(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"0123456789abcdef")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
        self.db.set_queue_status(file_id, "posting")
        self.db.update_file_state(file_id, "posting")
        self.db.set_queue_progress(file_id, 1, 8)
        row = self.db.list_files()[0]
        self.assertEqual(row["queue_status"], "posting")
        self.assertEqual(row["progress_chunks"], 1)
        self.assertEqual(row["progress_bytes"], 8)

    def test_queue_file_ignores_backed_up_files(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
            conn.execute("UPDATE files SET state='backed_up' WHERE id=?", (file_id,))
        self.db.queue_file(file_id)
        self.assertEqual(len(self.db.list_queue(include_done=True)), 0)

    def test_enqueue_unbacked_does_not_auto_retry_failed_files(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
            conn.execute("UPDATE files SET state='failed' WHERE id=?", (file_id,))
        self.assertEqual(enqueue_unbacked(self.db), 0)
        self.db.queue_file(file_id)
        self.assertEqual(len(self.db.list_queue()), 1)

    def test_log_filtering_by_level(self):
        self.db.log("info", "test.info", "info message")
        self.db.log("debug", "test.debug", "debug message")
        self.db.log("error", "test.error", "error message")
        self.db.log("verbose", "test.verbose", "verbose message")
        rows = self.db.list_events(["error"])
        self.assertEqual([row["level"] for row in rows], ["error"])
        debug_rows = self.db.list_events(["debug"])
        self.assertEqual([row["level"] for row in debug_rows], ["debug"])
        all_rows = self.db.list_events([])
        self.assertEqual(len(all_rows), 4)

    def test_log_filtering_by_event_type_and_exclusion(self):
        self.db.log("verbose", "web.access", "GET /api/status")
        self.db.log("info", "scan", "scan message")
        self.db.log("info", "queue", "queue message")
        scan_rows = self.db.list_events(["info", "verbose"], event_types=["scan"])
        self.assertEqual([row["event_type"] for row in scan_rows], ["scan"])
        visible_rows = self.db.list_events(["info", "verbose"], exclude_event_types=["web.access"])
        self.assertNotIn("web.access", [row["event_type"] for row in visible_rows])
        self.assertIn("scan", self.db.event_types())

    def test_change_token_ignores_web_access_events(self):
        first = self.db.change_token()["event_id"]
        self.db.log("verbose", "web.access", "GET /api/status")
        self.assertEqual(self.db.change_token()["event_id"], first)
        self.db.log("info", "scan", "scan message")
        self.assertGreater(self.db.change_token()["event_id"], first)

    def test_speed_samples_include_posted_chunks(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
        self.db.add_chunk(file_id, 0, "<chunk@example.test>", 120, "abc", "[hidden]")
        samples = self.db.speed_samples(minutes=5, bucket_seconds=60)
        self.assertTrue(any(sample["upload_bps"] > 0 for sample in samples))

    def test_status_throughput_summary_reports_mbps(self):
        summary = throughput_summary(
            [
                {"upload_bps": 125000, "download_bps": 0},
                {"upload_bps": 250000, "download_bps": 500000},
            ]
        )
        self.assertEqual(summary["upload_mbps"], 2.0)
        self.assertEqual(summary["download_mbps"], 4.0)
        self.assertEqual(summary["average_upload_mbps"], 1.5)

    def test_hourly_post_budget_reports_used_limit_and_remaining_bytes(self):
        self.config.hourly_post_limit_bytes = 10
        self.db.record_transfer_sample("upload", 4)
        budget = hourly_post_budget(self.db, self.config)
        self.assertEqual(budget["used_bytes"], 4)
        self.assertEqual(budget["limit_bytes"], 10)
        self.assertEqual(budget["remaining_bytes"], 6)
        self.assertEqual(budget["percent"], 40)
        self.assertEqual(budget["enabled"], 1)

    def test_status_thread_usage_caps_at_configured_threads(self):
        usage = thread_usage_summary(
            [
                {"size": 100, "posted_chunks": 1},
                {"size": 40, "posted_chunks": 0},
            ],
            article_size=10,
            configured_threads=4,
        )
        self.assertEqual(usage, {"in_use": 4, "total": 4})

    def test_queue_pagination_and_folder_priority(self):
        media = self.root / "media"
        folder = media / "season"
        folder.mkdir(parents=True)
        (folder / "one.mkv").write_bytes(b"one")
        (folder / "two.mkv").write_bytes(b"two")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        self.assertEqual(self.db.queue_count(), 2)
        self.assertEqual(len(self.db.list_queue(limit=1)), 1)
        changed = self.db.boost_folder_priority("season")
        self.assertEqual(changed, 2)
        with self.db.connect() as conn:
            priorities = [row["priority"] for row in conn.execute("SELECT priority FROM queue ORDER BY file_id").fetchall()]
        self.assertEqual(priorities, [90, 90])

    def test_queue_rows_include_posted_progress_counts(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"0123456789abcdef")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
        self.db.add_chunk(file_id, 0, "<chunk@example.test>", 120, "abc", "[hidden]")
        rows = self.db.list_queue()
        self.assertEqual(rows[0]["posted_chunks"], 1)
        self.assertEqual(rows[0]["posted_bytes"], 120)

    def test_recover_stale_posting_requeues_file(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
            conn.execute("UPDATE files SET state='posting' WHERE id=?", (file_id,))
            conn.execute(
                "UPDATE queue SET status='posting', progress_chunks=2, progress_bytes=123, updated_at='2000-01-01T00:00:00+00:00' WHERE file_id=?",
                (file_id,),
            )
        self.assertEqual(self.db.recover_stale_posting(stale_after_seconds=1), 1)
        with self.db.connect() as conn:
            file_row = conn.execute("SELECT state FROM files WHERE id=?", (file_id,)).fetchone()
            queue_row = conn.execute("SELECT status, reason, progress_chunks, progress_bytes FROM queue WHERE file_id=?", (file_id,)).fetchone()
        self.assertEqual(file_row["state"], "queued")
        self.assertEqual(queue_row["status"], "queued")
        self.assertEqual(queue_row["reason"], "stale-posting-retry")
        self.assertEqual(queue_row["progress_chunks"], 0)
        self.assertEqual(queue_row["progress_bytes"], 0)

    def test_recover_interrupted_posting_requeues_immediately_on_startup(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
            conn.execute("UPDATE files SET state='posting' WHERE id=?", (file_id,))
            conn.execute("UPDATE queue SET status='posting', progress_chunks=898, progress_bytes=706215936 WHERE file_id=?", (file_id,))
        self.assertEqual(self.db.recover_interrupted_posting(), 1)
        with self.db.connect() as conn:
            file_row = conn.execute("SELECT state FROM files WHERE id=?", (file_id,)).fetchone()
            queue_row = conn.execute("SELECT status, reason, progress_chunks, progress_bytes FROM queue WHERE file_id=?", (file_id,)).fetchone()
        self.assertEqual(file_row["state"], "queued")
        self.assertEqual(queue_row["status"], "queued")
        self.assertEqual(queue_row["reason"], "startup-posting-retry")
        self.assertEqual(queue_row["progress_chunks"], 0)
        self.assertEqual(queue_row["progress_bytes"], 0)

    def test_recover_queued_failed_mismatch_requeues_file(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
            conn.execute("UPDATE files SET state='queued' WHERE id=?", (file_id,))
            conn.execute("UPDATE queue SET status='failed', progress_chunks=2, progress_bytes=123 WHERE file_id=?", (file_id,))
        self.assertEqual(self.db.recover_queued_failed_mismatches(), 1)
        with self.db.connect() as conn:
            queue_row = conn.execute("SELECT status, reason, progress_chunks, progress_bytes FROM queue WHERE file_id=?", (file_id,)).fetchone()
        self.assertEqual(queue_row["status"], "queued")
        self.assertEqual(queue_row["reason"], "queued-state-recovery")
        self.assertEqual(queue_row["progress_chunks"], 0)
        self.assertEqual(queue_row["progress_bytes"], 0)

    def test_update_config_from_settings_payload(self):
        update_config(
            self.config,
            {
                "article_size": 256 * 1024,
                "newsgroup": "alt.binaries.example",
                "verification_interval_days": 30,
                "verification_task_interval_seconds": 45,
                "verification_files_per_run": 3,
                "scan_interval_seconds": 15,
                "backup_interval_seconds": 20,
                "cloud_backup_interval_seconds": 55,
                "maintenance_interval_seconds": 66,
                "restore_drill_task_interval_seconds": 77,
                "file_stability_seconds": 88,
                "nntp_threads": 6,
                "hourly_post_limit_bytes": 123456,
                "usenet_retry_attempts": 4,
                "usenet_retry_backoff_seconds": 8,
                "ui_theme": "nordic_mint",
                "log_retention_days": 40,
                "verbose_log_retention_days": 5,
                "restore_drill_interval_days": 9,
                "restore_drill_sample_bytes": 2048,
                "log_web_access": True,
                "log_chunk_events": True,
                "compact_chunk_metadata": False,
                "transfer_sample_bucket_seconds": 60,
                "auto_queue_exclude_patterns": ["*.sample", ".tmp"],
                "zip_subfolders": True,
                "encrypt_bodies": True,
                "encryption_passphrase_env": "BACKUPRR_SECRET",
                "endpoints": [str(self.root / "media"), ""],
                "usenet_hosts": [
                    {
                        "name": "read",
                        "mode": "read",
                        "host": "news.example.test",
                        "port": 563,
                        "tls": "implicit",
                        "username": "provider-user",
                        "password": "provider-password",
                    }
                ],
                "par2": {"enabled": True, "command": "par2", "redundancy_percent": 12},
                "cloud_backups": [
                    {"name": "local", "provider": "local", "target": str(self.root / "cloud"), "enabled": True}
                ],
                "log_destinations": [
                    {
                        "name": "loki",
                        "platform": "loki",
                        "url": "http://127.0.0.1:3100/loki/api/v1/push",
                        "api_key": "token",
                        "min_level": "warning",
                        "timeout_seconds": 9,
                        "enabled": True,
                    }
                ],
            },
        )
        self.assertEqual(self.config.article_size, 256 * 1024)
        self.assertEqual(self.config.newsgroup, "alt.binaries.example")
        self.assertEqual(self.config.verification_interval_days, 30)
        self.assertEqual(self.config.verification_task_interval_seconds, 45)
        self.assertEqual(self.config.verification_files_per_run, 3)
        self.assertEqual(self.config.scan_interval_seconds, 15)
        self.assertEqual(self.config.backup_interval_seconds, 20)
        self.assertEqual(self.config.cloud_backup_interval_seconds, 55)
        self.assertEqual(self.config.maintenance_interval_seconds, 66)
        self.assertEqual(self.config.restore_drill_task_interval_seconds, 77)
        self.assertEqual(self.config.file_stability_seconds, 88)
        self.assertEqual(self.config.nntp_threads, 6)
        self.assertEqual(self.config.hourly_post_limit_bytes, 123456)
        self.assertEqual(self.config.usenet_retry_attempts, 4)
        self.assertEqual(self.config.usenet_retry_backoff_seconds, 8)
        self.assertEqual(self.config.ui_theme, "nordic_mint")
        self.assertEqual(self.config.log_retention_days, 40)
        self.assertEqual(self.config.verbose_log_retention_days, 5)
        self.assertEqual(self.config.restore_drill_interval_days, 9)
        self.assertEqual(self.config.restore_drill_sample_bytes, 2048)
        self.assertTrue(self.config.log_web_access)
        self.assertTrue(self.config.log_chunk_events)
        self.assertFalse(self.config.compact_chunk_metadata)
        self.assertEqual(self.config.transfer_sample_bucket_seconds, 60)
        self.assertEqual(self.config.auto_queue_exclude_patterns, ["*.sample", ".tmp"])
        self.assertTrue(self.config.zip_subfolders)
        self.assertTrue(self.config.encrypt_bodies)
        self.assertEqual(self.config.endpoints, [str(self.root / "media")])
        self.assertEqual(self.config.usenet_hosts[0].tls, "implicit")
        self.assertEqual(self.config.usenet_hosts[0].resolved_username(), "provider-user")
        self.assertEqual(self.config.usenet_hosts[0].resolved_password(), "provider-password")
        self.assertEqual(self.config.par2["redundancy_percent"], 12)
        self.assertEqual(self.config.cloud_backups[0].provider, "local")
        self.assertEqual(self.config.log_destinations[0].platform, "loki")
        self.assertEqual(self.config.log_destinations[0].api_key, "token")
        self.assertEqual(self.config.log_destinations[0].min_level, "warning")

    def test_update_config_preserves_blank_existing_log_destination_secret(self):
        self.config.log_destinations = [
            LogDestination(name="seq", platform="seq", url="http://seq.example.test", api_key="secret", enabled=True)
        ]
        update_config(
            self.config,
            {
                "log_destinations": [
                    {
                        "name": "seq",
                        "platform": "seq",
                        "url": "http://seq.example.test",
                        "api_key": "",
                        "min_level": "info",
                        "timeout_seconds": 5,
                        "enabled": True,
                    }
                ]
            },
        )
        self.assertEqual(self.config.log_destinations[0].api_key, "secret")
        public = self.config.public_dict()["log_destinations"][0]
        self.assertEqual(public["api_key"], "")
        self.assertTrue(public["has_api_key"])

    def test_log_forwarding_payloads_match_platform(self):
        event = {
            "ts": "2026-07-11T08:00:00+00:00",
            "level": "warning",
            "event_type": "backup.task",
            "message": "worker paused",
            "file_id": 7,
            "data": "",
        }
        splunk_body, splunk_headers = build_payload(
            LogDestination(name="splunk", platform="splunk_hec", url="http://splunk.example.test", api_key="hec"),
            event,
        )
        self.assertEqual(splunk_headers["Authorization"], "Splunk hec")
        self.assertIn(b'"sourcetype": "backuprr:event"', splunk_body)

        loki_body, loki_headers = build_payload(
            LogDestination(name="loki", platform="loki", url="http://loki.example.test"),
            event,
        )
        self.assertEqual(loki_headers["Content-Type"], "application/json")
        self.assertIn(b'"streams"', loki_body)

    def test_cloud_backup_writes_config_and_database_archive(self):
        config_path = self.root / "config.json"
        self.config.source_path = config_path
        self.config.save(str(config_path))
        target = self.root / "cloud"
        self.config.cloud_backups = [
            type("Target", (), {"name": "local", "provider": "local", "target": str(target), "command": "", "enabled": True})()
        ]
        results = backup_config_and_database(self.db, self.config)
        self.assertEqual(len(results), 1)
        archives = list(target.glob("backuprr-backup-*.zip"))
        self.assertEqual(len(archives), 1)

    def test_cloud_backup_if_changed_skips_unchanged_state(self):
        config_path = self.root / "config.json"
        self.config.source_path = config_path
        self.config.save(str(config_path))
        target = self.root / "cloud"
        self.config.cloud_backups = [
            type("Target", (), {"name": "local", "provider": "local", "target": str(target), "command": "", "enabled": True})()
        ]
        self.assertEqual(len(backup_config_and_database_if_changed(self.db, self.config)), 1)
        self.assertEqual(backup_config_and_database_if_changed(self.db, self.config), [])
        self.db.log("info", "test.change", "catalog changed enough to trigger token")
        self.assertEqual(backup_config_and_database_if_changed(self.db, self.config), [])

    def test_update_config_preserves_blank_existing_host_password(self):
        self.config.usenet_hosts = [
            UsenetHost(name="read", mode="read", host="news.example.test", port=563, tls="implicit", password="secret")
        ]
        update_config(
            self.config,
            {
                "usenet_hosts": [
                    {
                        "name": "read",
                        "mode": "read",
                        "host": "news.example.test",
                        "port": 563,
                        "tls": "implicit",
                        "password": "",
                    }
                ]
            },
        )
        self.assertEqual(self.config.usenet_hosts[0].password, "secret")

    def test_update_config_preserves_null_existing_host_password(self):
        self.config.usenet_hosts = [
            UsenetHost(name="post", mode="post", host="post.example.test", port=563, tls="implicit", password="secret")
        ]
        update_config(
            self.config,
            {
                "usenet_hosts": [
                    {
                        "name": "post",
                        "mode": "post",
                        "host": "post.example.test",
                        "port": 563,
                        "tls": "implicit",
                        "password": None,
                    }
                ]
            },
        )
        self.assertEqual(self.config.usenet_hosts[0].password, "secret")

    def test_public_host_dict_hides_password_but_marks_presence(self):
        host = UsenetHost(name="post", mode="post", host="post.example.test", port=563, tls="implicit", password="secret")
        public = host.public_dict()
        self.assertEqual(public["password"], "")
        self.assertTrue(public["has_password"])

    def test_config_load_accepts_utf8_bom(self):
        config_path = self.root / "bom-config.json"
        config_path.write_text('{"database":"test.sqlite3"}', encoding="utf-8-sig")
        loaded = Config.load(str(config_path))
        self.assertEqual(loaded.database, "test.sqlite3")

    def test_subsecond_duration_formats_as_milliseconds(self):
        self.assertEqual(format_duration(0), "1ms")
        self.assertEqual(format_duration(0.124), "124ms")
        self.assertEqual(format_duration(1.2), "1s")

    def test_running_task_duration_reports_current_elapsed_time(self):
        monitor = CatalogMonitor(self.db, self.config)
        with patch("backuprr.monitor.time.perf_counter", side_effect=[100.0, 102.4]):
            monitor._mark_started()
            task = monitor.tasks()[0]
        self.assertEqual(task["status"], "running")
        self.assertEqual(task["last_run_duration"], "2s")

    def test_old_env_host_keys_are_ignored_when_loading_hosts(self):
        host = UsenetHost.from_dict(
            {
                "name": "read",
                "mode": "read",
                "host": "news.example.test",
                "port": 563,
                "tls": "implicit",
                "username_env": "OLD_USER_ENV",
                "password_env": "OLD_PASS_ENV",
                "username": "direct-user",
                "password": "direct-password",
            }
        )
        self.assertEqual(host.resolved_username(), "direct-user")
        self.assertEqual(host.resolved_password(), "direct-password")
        self.assertNotIn("username_env", host.public_dict())

    def test_catalog_monitor_scan_once_catalogs_endpoint(self):
        media = self.root / "media"
        media.mkdir()
        (media / "episode.mkv").write_bytes(b"episode")
        self.db.add_endpoint(str(media))
        monitor = CatalogMonitor(self.db, self.config)
        self.assertEqual(monitor.scan_once(), 1)
        with self.db.connect() as conn:
            row = conn.execute("SELECT relative_path FROM files").fetchone()
        self.assertEqual(row["relative_path"], "episode.mkv")
        self.assertEqual(self.db.stats()["queue_queued"], 1)

    def test_catalog_monitor_reports_task_state(self):
        monitor = CatalogMonitor(self.db, self.config)
        tasks = monitor.tasks()
        self.assertEqual(tasks[0]["name"], "Catalog monitor")
        self.assertEqual(tasks[0]["status"], "scheduled")
        self.assertEqual(tasks[0]["interval_seconds"], self.config.scan_interval_seconds)
        monitor.scan_once()
        tasks = monitor.tasks()
        self.assertEqual(tasks[0]["runs"], 1)
        self.assertIn("last_run", tasks[0])
        self.assertIn("last_run_duration", tasks[0])
        self.assertNotEqual(tasks[0]["last_run_duration"], "0s")
        self.assertIn("time_until_next_run", tasks[0])
        self.assertNotIn("last_started_at", tasks[0])
        self.assertIn("files scanned", tasks[0]["last_result"])
        self.assertGreater(tasks[0]["revision"], 0)

    def test_backup_monitor_posts_next_queued_file(self):
        media = self.root / "media"
        media.mkdir()
        (media / "movie.mkv").write_bytes(b"0123456789abcdef")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        monitor = BackupMonitor(self.db, self.config)
        with patch("backuprr.backup.UsenetClient", FakePostClient):
            self.assertIsNotNone(monitor.post_once())
        tasks = monitor.tasks()
        self.assertEqual(tasks[0]["name"], "Usenet backup worker")
        self.assertIn("posted file id", tasks[0]["last_result"])

    def test_backup_monitor_reports_active_posting_count(self):
        media = self.root / "media"
        media.mkdir()
        (media / "movie.mkv").write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
            conn.execute("UPDATE files SET state='posting' WHERE id=?", (file_id,))
            conn.execute("UPDATE queue SET status='posting' WHERE file_id=?", (file_id,))
        monitor = BackupMonitor(self.db, self.config)
        result = monitor.run_once()
        self.assertIn("0 newly queued", result)
        self.assertIn("1 posting", result)

    def test_verification_monitor_warns_on_socket_permission_block(self):
        monitor = VerificationMonitor(self.db, self.config)
        with patch("backuprr.monitor.verify_due_chunks", side_effect=FakeSocketPermissionError("blocked")):
            self.assertEqual(monitor.verify_once(force=True), 0)
        rows = self.db.list_events(["warning"], event_types=["verify.network"])
        self.assertEqual(len(rows), 1)
        self.assertIn("socket access is blocked", rows[0]["message"])

    def test_verify_selected_file_chunks_only_checks_selected_file(self):
        media = self.root / "media"
        media.mkdir()
        first = media / "one.mkv"
        second = media / "two.mkv"
        first.write_bytes(b"one")
        second.write_bytes(b"two")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            rows = conn.execute("SELECT id FROM files ORDER BY relative_path").fetchall()
        self.db.add_chunk(rows[0]["id"], 0, "<one@example.test>", 3, "abc", "[one]")
        self.db.add_chunk(rows[1]["id"], 0, "<two@example.test>", 3, "def", "[two]")
        self.config.usenet_hosts.append(UsenetHost(name="read", mode="read", host="example.test", port=563, tls="implicit"))
        with patch("backuprr.backup.UsenetClient", FakeReadClient):
            self.assertEqual(verify_file_chunks(self.db, self.config, [rows[0]["id"]]), 1)
        with self.db.connect() as conn:
            verified = conn.execute("SELECT file_id FROM chunks WHERE status='verified'").fetchall()
        self.assertEqual([row["file_id"] for row in verified], [rows[0]["id"]])

    def test_automatic_verification_uses_per_file_due_dates_and_batch_limit(self):
        media = self.root / "media"
        media.mkdir()
        for name in ("old-one.mkv", "old-two.mkv", "recent.mkv"):
            (media / name).write_bytes(name.encode())
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            rows = conn.execute("SELECT id, relative_path FROM files ORDER BY relative_path").fetchall()
            for row in rows:
                conn.execute(
                    "UPDATE files SET state='backed_up', last_backup_at=? WHERE id=?",
                    ("2999-01-01T00:00:00+00:00" if row["relative_path"] == "recent.mkv" else "2000-01-01T00:00:00+00:00", row["id"]),
                )
        for row in rows:
            self.db.add_chunk(row["id"], 0, f"<{row['relative_path']}@example.test>", 3, "abc", "[hidden]")
        self.config.usenet_hosts.append(UsenetHost(name="read", mode="read", host="example.test", port=563, tls="implicit"))
        self.config.verification_files_per_run = 1
        with patch("backuprr.backup.UsenetClient", FakeReadClient):
            self.assertEqual(verify_due_chunks(self.db, self.config), 1)
        with self.db.connect() as conn:
            verified = conn.execute(
                """
                SELECT f.relative_path
                FROM chunks c
                JOIN files f ON f.id = c.file_id
                WHERE c.status='verified'
                ORDER BY f.relative_path
                """
            ).fetchall()
        self.assertEqual([row["relative_path"] for row in verified], ["old-one.mkv"])

    def test_restore_file_accepts_modern_nntplib_article_response(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"placeholder")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
        self.db.add_chunk(file_id, 0, "<chunk@example.test>", 16, "abc", "[hidden]")
        self.config.usenet_hosts.append(UsenetHost(name="read", mode="read", host="example.test", port=563, tls="implicit"))
        target = self.root / "restore" / "movie.mkv"
        with patch("backuprr.restore.UsenetClient", FakeRestoreClient):
            self.assertEqual(restore_file(self.db, self.config, str(path), str(target)), target)
        self.assertEqual(target.read_bytes(), b"restored payload")

    def test_restore_confidence_reports_chunk_state(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"placeholder")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
        self.db.add_chunk(file_id, 0, "<chunk@example.test>", 16, "abc", "[hidden]")
        confidence = restore_confidence(self.db, str(path))
        self.assertTrue(confidence["restorable"])
        self.assertEqual(confidence["chunk_count"], 1)

    def test_restore_plan_reports_destination_and_overwrite(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"placeholder")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
        self.db.add_chunk(file_id, 0, "<chunk@example.test>", 16, "abc", "[hidden]")
        target = self.root / "restore.mkv"
        target.write_bytes(b"old")
        plan = restore_plan(self.db, str(path), str(target))
        self.assertTrue(plan["will_overwrite"])
        self.assertEqual(plan["target"], str(target))
        self.assertEqual(plan["bytes_total"], len(b"placeholder"))

    def test_restore_sample_and_restore_drill_download_limited_bytes(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"placeholder")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
            conn.execute("UPDATE files SET state='backed_up' WHERE id=?", (file_id,))
        self.db.add_chunk(file_id, 0, "<chunk@example.test>", 16, "abc", "[hidden]")
        self.config.usenet_hosts.append(UsenetHost(name="read", mode="read", host="example.test", port=563, tls="implicit"))
        self.config.restore_drill_sample_bytes = 4
        with patch("backuprr.restore.UsenetClient", FakeRestoreClient):
            self.assertEqual(restore_sample(self.db, self.config, str(path), 4), b"rest")
        with patch("backuprr.restore.UsenetClient", FakeRestoreClient):
            result = run_restore_drill(self.db, self.config)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["bytes_checked"], 4)

    def test_restore_to_original_path_stays_backed_up_and_unqueued(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"placeholder")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
        self.db.add_chunk(file_id, 0, "<chunk@example.test>", 16, "abc", "[hidden]")
        self.db.update_file_state(file_id, "backed_up")
        self.config.usenet_hosts.append(UsenetHost(name="read", mode="read", host="example.test", port=563, tls="implicit"))
        with patch("backuprr.restore.UsenetClient", FakeRestoreClient):
            self.assertEqual(restore_file(self.db, self.config, str(path)), path)
        scan_all(self.db)
        self.assertEqual(enqueue_unbacked(self.db), 0)
        with self.db.connect() as conn:
            file_row = conn.execute("SELECT state, size, sha256 FROM files WHERE id=?", (file_id,)).fetchone()
        self.assertEqual(file_row["state"], "backed_up")
        self.assertEqual(file_row["size"], len(b"restored payload"))
        self.assertEqual(len(self.db.list_queue()), 0)

    def test_cloud_backup_monitor_reports_no_changes_after_first_backup(self):
        config_path = self.root / "config.json"
        self.config.source_path = config_path
        self.config.save(str(config_path))
        target = self.root / "cloud"
        self.config.cloud_backups = [
            type("Target", (), {"name": "local", "provider": "local", "target": str(target), "command": "", "enabled": True})()
        ]
        monitor = CloudBackupMonitor(self.db, self.config)
        self.assertIn("cloud targets", monitor.run_once())
        self.assertIn("no config/catalog changes", monitor.run_once())


if __name__ == "__main__":
    unittest.main()
