import io
import json
import nntplib
import os
import email.message
import hashlib
import subprocess
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from backuprr import __version__
from backuprr.backup import (
    cleanup_payload,
    compression_enabled_for,
    decode_chunk,
    discover_par2_command,
    encode_chunk,
    iter_compressed_chunks,
    par2_create_args,
    post_next,
    prepare_payload,
    resolve_par2_command,
    verify_due_chunks,
    verify_file_chunks,
)
from backuprr.cloud_backup import backup_config_and_database, backup_config_and_database_if_changed
from backuprr.cli import sync_config_endpoints
from backuprr.config import Config, LogDestination, UsenetHost, update_config
from backuprr.crypto import xor_crypt
from backuprr.db import Database
from backuprr.log_forwarding import build_payload
from backuprr.monitor import BackupMonitor, CatalogMonitor, VerificationMonitor, CloudBackupMonitor, format_duration
from backuprr.operations import (
    check_usenet_hosts,
    audit_event,
    backup_manifest_export,
    backup_readiness_report,
    db_growth_report,
    diagnostics_bundle,
    disaster_recovery_report,
    dry_run_plan,
    file_integrity_receipt,
    provider_failover_simulation,
    config_history_rows,
    maintenance_schedule_report,
    notification_alerts,
    record_config_history,
    retention_policy_for_path,
    threat_model_report,
    prometheus_metrics,
    provider_confidence_report,
    restore_confidence,
    restore_plan,
    restore_preview,
    run_maintenance,
    run_restore_drill,
    setup_health_check,
    synthetic_catalog_plan,
    test_post_host_article_size,
)
from backuprr.queueing import enqueue_unbacked, excluded_by_auto_queue_filter, prioritize
from backuprr.restore import restore_file, restore_sample, restored_payloads
from backuprr.scanner import scan_all
from backuprr.usenet import UsenetClient
from backuprr.update_checker import check_for_updates, compare_versions, update_result
from backuprr.web import Handler, ResponseZipWriter, hourly_post_budget, thread_usage_summary, throughput_summary, totp_valid


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


class SocketBlockedPostClient(FakePostClient):
    attempts = 0

    def post(self, newsgroup, subject, body):
        self.__class__.attempts += 1
        raise FakeSocketPermissionError("An attempt was made to access a socket in a way forbidden by its access permissions")


class FakeReadClient:
    def __init__(self, host):
        self.host = host

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def article_exists(self, message_id):
        return True


class RateLimitedReadClient(FakeReadClient):
    def article_exists(self, message_id):
        raise nntplib.NNTPTemporaryError("480 rate limit exceeded")


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


class FakeGitHubResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


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
        self.assertEqual(__version__, "0.2.94")

    def test_config_endpoints_are_synced_to_database_on_startup(self):
        media = self.root / "media"
        media.mkdir()
        (media / "sample.bin").write_bytes(b"sample")
        self.config.endpoints = [str(media)]
        sync_config_endpoints(self.db, self.config)
        self.assertEqual(scan_all(self.db), 1)
        rows = self.db.list_rows("files")
        self.assertEqual(rows[0]["relative_path"], "sample.bin")

    def test_synthetic_catalog_plan_estimates_chunk_rows(self):
        plan = synthetic_catalog_plan(50000, 1024 * 1024 * 1024, 2 * 1024 * 1024, 1000)
        self.assertEqual(plan["files"], 50000)
        self.assertEqual(plan["estimated_chunk_rows"], 50000 * 512)
        self.assertGreater(plan["estimated_chunk_table_bytes"], 0)

    def test_prometheus_metrics_include_queue_and_worker_values(self):
        self.db.save_worker_state("backup", "Usenet backup worker", "", "", "", 0.1, "ok", "", 2, 1)
        metrics = prometheus_metrics(self.db, self.config)
        self.assertIn("backuprr_files_total", metrics)
        self.assertIn('backuprr_worker_runs{kind="backup"} 2', metrics)

    def test_disaster_recovery_report_flags_missing_cloud_targets(self):
        report = disaster_recovery_report(self.db, self.config)
        self.assertFalse(report["ok"])
        self.assertIn("no config/database cloud backup targets configured", report["issues"])

    def test_compare_versions_handles_prefixed_semver(self):
        self.assertGreater(compare_versions("v0.2.10", "0.2.9"), 0)
        self.assertEqual(compare_versions("v1.0.0", "1"), 0)
        self.assertLess(compare_versions("0.2.8", "0.2.9"), 0)

    def test_update_checker_records_github_release_result(self):
        requests = []

        def fake_opener(request, timeout):
            requests.append((request, timeout))
            return FakeGitHubResponse(
                {
                    "tag_name": "v9.9.9",
                    "html_url": "https://github.com/kelau/Backuprr/releases/tag/v9.9.9",
                    "name": "Backuprr 9.9.9",
                    "published_at": "2099-01-01T00:00:00Z",
                    "body": "Future release notes",
                }
            )

        result = check_for_updates(self.db, self.config, opener=fake_opener)
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["update_available"])
        self.assertEqual(result["latest_version"], "9.9.9")
        self.assertEqual(update_result(self.db)["latest_version"], "9.9.9")
        self.assertEqual(requests[0][1], self.config.update_check_timeout_seconds)
        self.assertIn("/repos/kelau/Backuprr/releases/latest", requests[0][0].full_url)

    def test_update_checker_falls_back_to_tags_when_latest_release_missing(self):
        urls = []

        def fake_opener(request, timeout):
            urls.append(request.full_url)
            if request.full_url.endswith("/releases/latest"):
                raise HTTPError(request.full_url, 404, "Not Found", hdrs=None, fp=None)
            return FakeGitHubResponse([{"name": "v9.8.7", "commit": {"sha": "abc123"}}])

        result = check_for_updates(self.db, self.config, opener=fake_opener)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["latest_version"], "9.8.7")
        self.assertEqual(result["source_kind"], "tag")
        self.assertTrue(urls[1].endswith("/tags?per_page=1"))

    def test_update_checker_sends_token_from_configured_environment(self):
        seen_auth = []
        os.environ["BACKUPRR_TEST_GITHUB_TOKEN"] = "private-token"
        self.config.update_github_token_env = "BACKUPRR_TEST_GITHUB_TOKEN"

        def fake_opener(request, timeout):
            seen_auth.append(request.headers.get("Authorization"))
            return FakeGitHubResponse({"tag_name": "v9.9.9", "html_url": "https://example.test/release"})

        try:
            result = check_for_updates(self.db, self.config, opener=fake_opener)
        finally:
            os.environ.pop("BACKUPRR_TEST_GITHUB_TOKEN", None)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(seen_auth, ["Bearer private-token"])

    def test_update_checker_can_be_disabled(self):
        self.config.update_check_enabled = False
        result = check_for_updates(self.db, self.config, opener=lambda *_args, **_kwargs: self.fail("network should not be used"))
        self.assertEqual(result["status"], "disabled")
        self.assertEqual(update_result(self.db)["status"], "disabled")

    def test_totp_validation_accepts_current_code(self):
        secret = "JBSWY3DPEHPK3PXP"
        self.assertTrue(totp_valid(secret, "996554", now=59))
        self.assertFalse(totp_valid(secret, "000000", now=59))

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
        self.assertIn("chunk_manifests", tables)
        self.assertIn("maintenance_runs", tables)
        self.assertIn("restore_drills", tables)
        self.assertIn("schema_migrations", tables)

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

    def test_event_log_can_fetch_rows_after_id_incrementally(self):
        self.db.log("info", "backup.task", "Initial proxmox event")
        first = self.db.list_events(["info"], limit=1)[0]
        self.db.log("info", "backup.task", "New proxmox event")
        self.db.log("warning", "verify.chunk", "Filtered warning")
        rows = self.db.list_events_after_id(first["id"], ["info"], limit=10, search="proxmox")
        self.assertEqual(len(rows), 1)
        self.assertGreater(rows[0]["id"], first["id"])
        self.assertIn("New proxmox", rows[0]["message"])

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

    def test_stats_include_compression_and_par2_rollups(self):
        media = self.root / "media"
        media.mkdir()
        first = media / "first.txt"
        second = media / "second.txt"
        first.write_bytes(b"a" * 100)
        second.write_bytes(b"b" * 200)
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            rows = conn.execute("SELECT id FROM files ORDER BY relative_path").fetchall()
            conn.execute("UPDATE files SET state='backed_up' WHERE id IN (?,?)", (rows[0]["id"], rows[1]["id"]))
        self.db.set_file_backup_features(rows[0]["id"], 100, 40, True, True)
        self.db.set_file_backup_features(rows[1]["id"], 200, 180, True, False)
        stats = self.db.stats()
        self.assertEqual(stats["files_compressed"], 2)
        self.assertEqual(stats["files_par2"], 1)
        self.assertEqual(stats["files_compressible_backed_up"], 2)
        self.assertEqual(stats["backup_uncompressed_bytes_total"], 300)
        self.assertEqual(stats["backup_compressed_bytes_total"], 220)
        self.assertEqual(stats["backup_par2_bytes_total"], 40)

    def test_queue_attention_status_includes_failed_and_blocked_items(self):
        media = self.root / "media"
        media.mkdir()
        failed = media / "failed.pdf"
        blocked = media / "blocked.pdf"
        done_blocked = media / "done-blocked.pdf"
        normal = media / "normal.pdf"
        failed.write_bytes(b"failed")
        blocked.write_bytes(b"blocked")
        done_blocked.write_bytes(b"done")
        normal.write_bytes(b"normal")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            rows = conn.execute("SELECT id, relative_path FROM files").fetchall()
            ids = {row["relative_path"]: row["id"] for row in rows}
        self.db.queue_file(ids["failed.pdf"], reason="manual")
        self.db.queue_file(ids["blocked.pdf"], reason="network-blocked")
        self.db.queue_file(ids["done-blocked.pdf"], reason="network-blocked")
        self.db.queue_file(ids["normal.pdf"], reason="manual")
        with self.db.connect() as conn:
            conn.execute("UPDATE queue SET status='failed', reason='par2-missing' WHERE file_id=?", (ids["failed.pdf"],))
            conn.execute("UPDATE files SET state='failed' WHERE id=?", (ids["failed.pdf"],))
            conn.execute("UPDATE queue SET status='done' WHERE file_id=?", (ids["done-blocked.pdf"],))
            conn.execute("UPDATE files SET state='backed_up' WHERE id=?", (ids["done-blocked.pdf"],))
        attention = self.db.list_queue(status="attention")
        self.assertEqual(self.db.queue_count(status="attention"), 2)
        self.assertEqual({row["relative_path"] for row in attention}, {"failed.pdf", "blocked.pdf"})

    def test_recover_retryable_failed_requeues_failed_items_without_chunks(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "manual.pdf"
        path.write_bytes(b"pdf")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
        self.db.queue_file(file_id, reason="unbacked")
        with self.db.connect() as conn:
            conn.execute("UPDATE queue SET status='failed' WHERE file_id=?", (file_id,))
            conn.execute("UPDATE files SET state='failed' WHERE id=?", (file_id,))
        self.assertEqual(self.db.recover_retryable_failed(), 1)
        with self.db.connect() as conn:
            row = conn.execute("SELECT q.status, q.reason, f.state FROM queue q JOIN files f ON f.id=q.file_id WHERE q.file_id=?", (file_id,)).fetchone()
        self.assertEqual(row["status"], "queued")
        self.assertEqual(row["reason"], "failed-retry")
        self.assertEqual(row["state"], "queued")

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

    def test_auto_queue_uses_configured_strategy(self):
        media = self.root / "media"
        media.mkdir()
        small = media / "small.mkv"
        large = media / "large.mkv"
        small.write_bytes(b"1")
        large.write_bytes(b"1" * 100)
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        self.config.queue_strategy = "larger-first"
        enqueue_unbacked(self.db, self.config)
        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT f.relative_path FROM queue q
                JOIN files f ON f.id=q.file_id
                ORDER BY q.position
                """
            ).fetchall()
        self.assertEqual([row["relative_path"] for row in rows], ["large.mkv", "small.mkv"])

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
            live_chunks = conn.execute("SELECT * FROM chunks ORDER BY chunk_index").fetchall()
            compact = conn.execute("SELECT chunk_count, bytes_total FROM chunk_manifests").fetchone()
            file_row = conn.execute("SELECT state FROM files LIMIT 1").fetchone()
        chunks = self.db.chunks_for_file_ids([1])
        self.assertEqual(len(live_chunks), 0)
        self.assertEqual(compact["chunk_count"], 2)
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

    def test_completed_post_compacts_chunks_but_preserves_restore_catalog(self):
        media = self.root / "media"
        media.mkdir()
        (media / "movie.mkv").write_bytes(b"0123456789abcdef")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        with patch("backuprr.backup.UsenetClient", FakePostClient):
            self.assertIsNotNone(post_next(self.db, self.config))
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
            live = conn.execute("SELECT COUNT(*) FROM chunks WHERE file_id=?", (file_id,)).fetchone()[0]
            compact = conn.execute("SELECT chunk_count, bytes_total FROM chunk_manifests WHERE file_id=?", (file_id,)).fetchone()
        self.assertEqual(live, 0)
        self.assertEqual(compact["chunk_count"], 2)
        self.assertEqual(self.db.chunk_count_for_file(file_id), 2)
        entries = self.db.chunks_for_file_ids([file_id])
        self.assertEqual([entry["chunk_index"] for entry in entries], [0, 1])
        self.assertTrue(str(entries[0]["id"]).startswith(f"manifest:{file_id}:"))

    def test_compressed_chunks_round_trip_and_skip_known_compressed_extensions(self):
        media = self.root / "media"
        media.mkdir()
        text_path = media / "notes.txt"
        text_path.write_bytes((b"compress me " * 1000))
        compressed = b"".join(iter_compressed_chunks(text_path, 37))
        self.assertEqual(zlib.decompress(compressed, wbits=31), text_path.read_bytes())

        self.config.compress_files = True
        self.assertTrue(compression_enabled_for(text_path, self.config))
        self.assertFalse(compression_enabled_for(media / "movie.mkv", self.config))
        self.assertFalse(compression_enabled_for(media / "archive.zip", self.config))

    def test_compression_sampling_skips_low_gain_payloads(self):
        media = self.root / "media"
        media.mkdir()
        randomish = media / "random.bin"
        randomish.write_bytes(os.urandom(32 * 1024))
        self.config.compress_files = True
        self.config.compression_min_gain_percent = 95
        self.assertFalse(compression_enabled_for(randomish, self.config))

    def test_post_next_records_compressed_backup_metadata(self):
        media = self.root / "media"
        media.mkdir()
        data = b"same text " * 500
        (media / "notes.txt").write_bytes(data)
        self.config.compress_files = True
        self.config.article_size = 64
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        CountingPostClient.posts = []
        with patch("backuprr.backup.UsenetClient", CountingPostClient):
            self.assertIsNotNone(post_next(self.db, self.config))
        with self.db.connect() as conn:
            file_row = conn.execute("SELECT state, backup_uncompressed_size, backup_compressed_size, backup_compressed, backup_par2 FROM files").fetchone()
            manifest = conn.execute("SELECT flags, bytes_total FROM backup_manifests ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(file_row["state"], "backed_up")
        self.assertEqual(file_row["backup_uncompressed_size"], len(data))
        self.assertEqual(file_row["backup_compressed"], 1)
        self.assertEqual(file_row["backup_par2"], 0)
        self.assertGreater(file_row["backup_compressed_size"], 0)
        self.assertLess(file_row["backup_compressed_size"], len(data))
        self.assertIn("compressed", manifest["flags"])
        self.assertEqual(manifest["bytes_total"], file_row["backup_compressed_size"])

    def test_chunk_event_logging_can_be_enabled(self):
        media = self.root / "media"
        media.mkdir()
        (media / "movie.mkv").write_bytes(b"0123456789abcdef")
        self.config.log_chunk_events = True
        self.config.compact_chunk_metadata = False
        self.config.compact_chunk_rows = False
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
        self.assertEqual(plan["estimated_chunk_rows"], 2)
        self.assertIn("estimated_post_bytes", plan)

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
        chunks = self.db.chunks_for_file_ids([file_id])
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
            queue_row = conn.execute("SELECT progress_chunks FROM queue WHERE file_id=?", (file_id,)).fetchone()
        chunks = self.db.chunks_for_file_ids([file_id])
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
            queue_row = conn.execute("SELECT progress_chunks FROM queue WHERE file_id=?", (file_id,)).fetchone()
        chunks = self.db.chunks_for_file_ids([file_id])
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

    def test_prepare_payload_invokes_configured_par2_command(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"0123456789abcdef")
        self.config.par2 = {"enabled": True, "command": "fake-par2", "redundancy_percent": 17}

        calls = []

        def fake_run(args, **kwargs):
            calls.append((args, kwargs))
            cwd = kwargs["cwd"]
            Path(cwd, "movie.mkv.par2").write_bytes(b"par2")
            return subprocess.CompletedProcess(args, 0, stdout="ok", stderr="")

        with patch("backuprr.backup.shutil.which", return_value="C:/tools/fake-par2.exe"):
            with patch("backuprr.backup.subprocess.run", side_effect=fake_run):
                payload = prepare_payload(path, self.config)
        try:
            self.assertNotEqual(payload, path)
            self.assertEqual(payload.name, "movie.mkv")
            self.assertTrue(payload.exists())
            self.assertEqual(payload.read_bytes(), b"0123456789abcdef")
            self.assertEqual(len(calls), 1)
            args, kwargs = calls[0]
            self.assertEqual(args, ["C:/tools/fake-par2.exe", "create", "-r17", str(payload.with_name("movie.mkv.par2")), str(payload)])
            cwd = kwargs["cwd"]
            self.assertEqual(cwd, str(payload.parent))
            self.assertTrue(kwargs["capture_output"])
            self.assertTrue(Path(cwd, "movie.mkv.par2").exists())
        finally:
            cleanup_payload(payload, path)

    def test_par2_create_args_support_multipar_par2j(self):
        payload = self.root / "payload.iso"
        args = par2_create_args("C:/Program Files (x86)/MultiPar/par2j.exe", payload, "10")
        self.assertEqual(args, ["C:/Program Files (x86)/MultiPar/par2j.exe", "c", "/rr10", "/uo", str(payload.with_name("payload.iso.par2")), str(payload)])

    def test_resolve_par2_command_uses_bundled_candidate(self):
        bundled = self.root / "bin" / "par2.exe"
        bundled.parent.mkdir()
        bundled.write_bytes(b"fake")
        self.config.base_dir = self.root
        with patch("backuprr.backup.shutil.which", return_value=None):
            self.assertEqual(resolve_par2_command("par2", self.config), str(bundled))

    def test_discover_par2_command_prefers_path_candidate(self):
        path_candidate = self.root / "tools" / "par2.exe"
        path_candidate.parent.mkdir()
        path_candidate.write_bytes(b"fake")
        with patch("backuprr.backup.shutil.which", return_value=str(path_candidate)):
            result = discover_par2_command(self.config)
        self.assertTrue(result["found"])
        self.assertEqual(result["command"], str(path_candidate))
        self.assertIn("PATH", result["label"])

    def test_discover_par2_command_finds_multipar_candidate(self):
        multipar = self.root / "Program Files" / "MultiPar" / "par2j.exe"
        multipar.parent.mkdir(parents=True)
        multipar.write_bytes(b"fake")
        with patch("backuprr.backup.platform.system", return_value="Windows"), patch("backuprr.backup.shutil.which", return_value=None), patch.dict(os.environ, {"ProgramFiles": str(self.root / "Program Files")}, clear=False):
            result = discover_par2_command(self.config)
        self.assertTrue(result["found"])
        self.assertEqual(result["command"], str(multipar))

    def test_post_next_requeues_when_socket_access_is_blocked(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"0123456789abcdef")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)

        SocketBlockedPostClient.attempts = 0
        with patch("backuprr.backup.UsenetClient", SocketBlockedPostClient):
            self.assertIsNone(post_next(self.db, self.config))

        with self.db.connect() as conn:
            file_row = conn.execute("SELECT state FROM files").fetchone()
            queue_row = conn.execute("SELECT status, reason FROM queue").fetchone()
            event = conn.execute("SELECT level, message FROM events WHERE event_type='post.network' ORDER BY id DESC LIMIT 1").fetchone()
            run = conn.execute("SELECT status, error FROM backup_runs ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(file_row["state"], "queued")
        self.assertEqual(queue_row["status"], "queued")
        self.assertEqual(queue_row["reason"], "network-blocked")
        self.assertEqual(event["level"], "warning")
        self.assertIn("socket access is blocked", event["message"])
        self.assertEqual(run["status"], "paused")
        first_attempts = SocketBlockedPostClient.attempts

        with patch("backuprr.backup.UsenetClient", SocketBlockedPostClient):
            self.assertIsNone(post_next(self.db, self.config))
        self.assertEqual(SocketBlockedPostClient.attempts, first_attempts)

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

    def test_missing_chunk_recheck_recovers_failed_file_and_queue(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
        self.db.add_chunk(file_id, 0, "<missing@example.test>", 3, "abc", "[hidden]")
        self.db.add_chunk(file_id, 1, "<ok@example.test>", 3, "def", "[hidden]")
        with self.db.connect() as conn:
            chunk_ids = [row["id"] for row in conn.execute("SELECT id FROM chunks ORDER BY id").fetchall()]
        self.db.mark_chunk_verified(chunk_ids[0], exists=False)
        with self.db.connect() as conn:
            conn.execute("UPDATE files SET state='failed' WHERE id=?", (file_id,))
            conn.execute("UPDATE queue SET status='failed', reason='missing-chunks' WHERE file_id=?", (file_id,))

        self.db.mark_chunk_verified(chunk_ids[0], exists=True)
        self.db.mark_chunk_verified(chunk_ids[1], exists=True)

        with self.db.connect() as conn:
            file_row = conn.execute("SELECT state, last_verify_at FROM files WHERE id=?", (file_id,)).fetchone()
            queue_row = conn.execute("SELECT status, reason FROM queue WHERE file_id=?", (file_id,)).fetchone()
            missing = conn.execute("SELECT COUNT(*) FROM chunks WHERE file_id=? AND status='missing'", (file_id,)).fetchone()[0]
        self.assertEqual(missing, 0)
        self.assertEqual(file_row["state"], "backed_up")
        self.assertIsNotNone(file_row["last_verify_at"])
        self.assertEqual(queue_row["status"], "done")
        self.assertEqual(queue_row["reason"], "verified-recovered")

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

    def test_queue_pause_patterns_keep_matching_files_out_of_auto_queue(self):
        media = self.root / "media"
        media.mkdir()
        (media / "ready.mkv").write_bytes(b"abc")
        (media / "hold.iso").write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        self.config.queue_pause_patterns = ["*.iso"]
        queued = enqueue_unbacked(self.db, self.config)
        self.assertEqual(queued, 1)
        rows = self.db.list_queue(include_done=True)
        self.assertEqual(len(rows), 1)
        self.assertTrue(str(rows[0]["path"]).endswith("ready.mkv"))

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

    def test_completed_queue_payload_shows_stored_chunks_not_progress(self):
        handler = object.__new__(Handler)
        handler.config = self.config
        payload = handler.queue_row_payload(
            {
                "file_id": 1,
                "path": "movie.mkv",
                "size": 10,
                "status": "done",
                "posted_chunks": 24,
                "posted_bytes": 10,
            }
        )
        self.assertEqual(payload["chunk_count"], 24)
        self.assertEqual(payload["progress"], "24 chunks stored")
        self.assertEqual(payload["progress_percent"], 100)

    def test_completed_queue_orders_by_completion_time_ascending(self):
        media = self.root / "media"
        media.mkdir()
        older = media / "older.mkv"
        newer = media / "newer.mkv"
        older.write_bytes(b"older")
        newer.write_bytes(b"newer")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        with self.db.connect() as conn:
            ids = {row["relative_path"]: row["id"] for row in conn.execute("SELECT id, relative_path FROM files").fetchall()}
            conn.execute("UPDATE queue SET status='done', updated_at='2026-01-01T00:00:00+00:00' WHERE file_id=?", (ids["older.mkv"],))
            conn.execute("UPDATE queue SET status='done', updated_at='2026-01-02T00:00:00+00:00' WHERE file_id=?", (ids["newer.mkv"],))
        rows = self.db.list_queue(status="done")
        self.assertEqual([row["relative_path"] for row in rows], ["older.mkv", "newer.mkv"])

    def test_queue_sort_applies_before_pagination(self):
        media = self.root / "media"
        media.mkdir()
        small = media / "small.mkv"
        large = media / "large.mkv"
        small.write_bytes(b"1")
        large.write_bytes(b"1" * 100)
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        rows = self.db.list_queue_sorted(limit=1, sort_by="size", sort_dir="desc")
        self.assertEqual(rows[0]["relative_path"], "large.mkv")

    def test_file_sort_applies_before_pagination(self):
        media = self.root / "media"
        media.mkdir()
        small = media / "small.mkv"
        large = media / "large.mkv"
        small.write_bytes(b"1")
        large.write_bytes(b"1" * 100)
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        rows = self.db.list_files(limit=1, sort_by="size", sort_dir="desc")
        self.assertEqual(rows[0]["relative_path"], "large.mkv")

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
                "auto_vacuum_after_compaction_rows": 1234,
                "restore_drill_task_interval_seconds": 77,
                "update_check_interval_seconds": 86400,
                "file_stability_seconds": 88,
                "nntp_threads": 6,
                "hourly_post_limit_bytes": 123456,
                "auto_pause_auth_failures": 7,
                "auto_pause_provider_failures": 11,
                "usenet_retry_attempts": 4,
                "usenet_retry_backoff_seconds": 8,
                "provider_retry_policy": {"network": {"attempts": 3, "backoff_seconds": 30}},
                "queue_strategy": "folder-first",
                "ui_theme": "nordic_mint",
                "ui_reduced_motion": True,
                "log_retention_days": 40,
                "verbose_log_retention_days": 5,
                "restore_drill_interval_days": 9,
                "restore_drill_sample_bytes": 2048,
                "log_web_access": True,
                "log_chunk_events": True,
                "compact_chunk_metadata": False,
                "transfer_sample_bucket_seconds": 60,
                "compression_sample_bytes": 4096,
                "compression_min_gain_percent": 12,
                "update_check_enabled": True,
                "update_github_repo": "example/Backuprr",
                "update_github_token_env": "BACKUPRR_TEST_GITHUB_TOKEN",
                "update_check_timeout_seconds": 12,
                "auto_queue_exclude_patterns": ["*.sample", ".tmp"],
                "queue_pause_patterns": ["*.iso"],
                "retention_policy_patterns": ["critical:*.iso:14"],
                "critical_verification_interval_days": 14,
                "external_api_keys": ["ha-key", "automation-key"],
                "external_api_key_scopes": {"ha-key": ["read", "backup"], "automation-key": ["read"]},
                "api_rate_limit_per_minute": 240,
                "external_api_rate_limit_per_minute": 80,
                "web_ui_username": "operator",
                "web_ui_password": "ui-secret",
                "web_ui_role": "operator",
                "web_ui_totp_secret_env": "BACKUPRR_TEST_TOTP",
                "read_only_mode": True,
                "config_secret_key_env": "BACKUPRR_TEST_CONFIG_SECRET",
                "restore_sandbox_enabled": True,
                "restore_sandbox_path": str(self.root / "sandbox"),
                "audit_mode": True,
                "audit_secret_key_env": "BACKUPRR_TEST_AUDIT",
                "manifest_export_enabled": True,
                "manifest_export_encrypt": False,
                "manifest_export_passphrase_env": "BACKUPRR_TEST_MANIFEST",
                "manifest_export_interval_seconds": 7200,
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
                        "priority": 250,
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
        self.assertEqual(self.config.auto_vacuum_after_compaction_rows, 1234)
        self.assertEqual(self.config.restore_drill_task_interval_seconds, 77)
        self.assertEqual(self.config.update_check_interval_seconds, 86400)
        self.assertEqual(self.config.file_stability_seconds, 88)
        self.assertEqual(self.config.nntp_threads, 6)
        self.assertEqual(self.config.hourly_post_limit_bytes, 123456)
        self.assertEqual(self.config.auto_pause_auth_failures, 7)
        self.assertEqual(self.config.auto_pause_provider_failures, 11)
        self.assertEqual(self.config.usenet_retry_attempts, 4)
        self.assertEqual(self.config.usenet_retry_backoff_seconds, 8)
        self.assertEqual(self.config.provider_retry_policy["network"]["attempts"], 3)
        self.assertEqual(self.config.queue_strategy, "folder-first")
        self.assertEqual(self.config.ui_theme, "nordic_mint")
        self.assertTrue(self.config.ui_reduced_motion)
        self.assertEqual(self.config.log_retention_days, 40)
        self.assertEqual(self.config.verbose_log_retention_days, 5)
        self.assertEqual(self.config.restore_drill_interval_days, 9)
        self.assertEqual(self.config.restore_drill_sample_bytes, 2048)
        self.assertTrue(self.config.log_web_access)
        self.assertTrue(self.config.log_chunk_events)
        self.assertFalse(self.config.compact_chunk_metadata)
        self.assertEqual(self.config.transfer_sample_bucket_seconds, 60)
        self.assertEqual(self.config.compression_sample_bytes, 4096)
        self.assertEqual(self.config.compression_min_gain_percent, 12)
        self.assertTrue(self.config.update_check_enabled)
        self.assertEqual(self.config.update_github_repo, "example/Backuprr")
        self.assertEqual(self.config.update_github_token_env, "BACKUPRR_TEST_GITHUB_TOKEN")
        self.assertEqual(self.config.update_check_timeout_seconds, 12)
        self.assertEqual(self.config.auto_queue_exclude_patterns, ["*.sample", ".tmp"])
        self.assertEqual(self.config.queue_pause_patterns, ["*.iso"])
        self.assertEqual(self.config.retention_policy_patterns, ["critical:*.iso:14"])
        self.assertEqual(self.config.critical_verification_interval_days, 14)
        self.assertEqual(self.config.external_api_keys, ["ha-key", "automation-key"])
        self.assertEqual(self.config.external_api_key_scopes["ha-key"], ["backup", "read"])
        self.assertEqual(self.config.api_rate_limit_per_minute, 240)
        self.assertEqual(self.config.external_api_rate_limit_per_minute, 80)
        self.assertEqual(self.config.web_ui_username, "operator")
        self.assertEqual(self.config.web_ui_password, "ui-secret")
        self.assertEqual(self.config.web_ui_role, "operator")
        self.assertEqual(self.config.web_ui_totp_secret_env, "BACKUPRR_TEST_TOTP")
        self.assertTrue(self.config.read_only_mode)
        self.assertEqual(self.config.config_secret_key_env, "BACKUPRR_TEST_CONFIG_SECRET")
        self.assertTrue(self.config.restore_sandbox_enabled)
        self.assertEqual(self.config.restore_sandbox_path, str(self.root / "sandbox"))
        self.assertTrue(self.config.audit_mode)
        self.assertEqual(self.config.audit_secret_key_env, "BACKUPRR_TEST_AUDIT")
        self.assertTrue(self.config.manifest_export_enabled)
        self.assertFalse(self.config.manifest_export_encrypt)
        self.assertEqual(self.config.manifest_export_interval_seconds, 7200)
        self.assertTrue(self.config.zip_subfolders)
        self.assertTrue(self.config.compress_files)
        self.assertTrue(self.config.encrypt_bodies)
        self.assertEqual(self.config.endpoints, [str(self.root / "media")])
        self.assertEqual(self.config.usenet_hosts[0].tls, "implicit")
        self.assertEqual(self.config.usenet_hosts[0].priority, 250)
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

    def test_config_save_protects_secrets_when_key_env_is_set(self):
        config_path = self.root / "protected.json"
        os.environ["BACKUPRR_TEST_CONFIG_SECRET"] = "local-test-key"
        self.config.config_secret_key_env = "BACKUPRR_TEST_CONFIG_SECRET"
        self.config.usenet_hosts = [UsenetHost(name="post", mode="post", host="example.test", port=563, password="provider-secret")]
        self.config.external_api_keys = ["external-secret"]
        self.config.web_ui_password = "ui-secret"
        try:
            self.config.save(str(config_path))
            raw = config_path.read_text(encoding="utf-8")
            self.assertIn("enc:v1:", raw)
            self.assertNotIn("provider-secret", raw)
            self.assertNotIn("external-secret", raw)
            loaded = Config.load(str(config_path))
        finally:
            os.environ.pop("BACKUPRR_TEST_CONFIG_SECRET", None)
        self.assertEqual(loaded.usenet_hosts[0].password, "provider-secret")
        self.assertEqual(loaded.external_api_keys, ["external-secret"])
        self.assertEqual(loaded.web_ui_password, "ui-secret")

    def test_setup_health_alerts_and_diagnostics_are_redacted(self):
        media = self.root / "media"
        media.mkdir()
        (media / "movie.mkv").write_bytes(b"abc")
        self.config.endpoints = [str(media)]
        self.config.external_api_keys = ["ha-key"]
        self.config.web_ui_password = "ui-secret"
        self.config.usenet_hosts = [
            UsenetHost(name="read", mode="read", host="news.example.test", port=563, username="user", password="secret"),
            UsenetHost(name="post", mode="post", host="post.example.test", port=563),
        ]
        scan_all(self.db)
        setup = setup_health_check(self.db, self.config)
        self.assertFalse(setup["ok"])
        self.assertTrue(any(check["id"] == "cloud-backup" for check in setup["checks"]))
        alerts = notification_alerts(self.db, self.config)
        self.assertTrue(any(alert["title"] == "No config/database cloud backup" for alert in alerts))
        bundle = diagnostics_bundle(self.db, self.config)
        self.assertEqual(bundle["config"]["usenet_hosts"][0]["username"], "***")
        self.assertEqual(bundle["config"]["usenet_hosts"][0]["password"], "")
        self.assertIn("tables", bundle)

    def test_threat_model_and_failover_reports_reflect_security_config(self):
        self.config.external_api_keys = ["ha-key"]
        self.config.web_ui_password = "ui-secret"
        self.config.usenet_hosts = [
            UsenetHost(name="read-a", mode="read", host="news-a.example.test", port=563, priority=10),
            UsenetHost(name="post-a", mode="post", host="post-a.example.test", port=563, priority=10),
            UsenetHost(name="post-b", mode="post", host="post-b.example.test", port=563, priority=5),
        ]
        model = threat_model_report(self.db, self.config)
        self.assertTrue(any(item["area"] == "External API" and item["status"] == "ok" for item in model["mitigations"]))
        failover = provider_failover_simulation(self.config, "post-a")
        self.assertTrue(failover["modes"]["post"]["ok"])
        self.assertEqual(failover["modes"]["post"]["primary"], "post-b")

    def test_provider_growth_manifest_receipt_preview_and_audit_helpers(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"0123456789abcdef")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        enqueue_unbacked(self.db)
        with patch("backuprr.backup.UsenetClient", FakePostClient):
            self.assertIsNotNone(post_next(self.db, self.config))
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
        self.db.record_host_check("post", "post", "ok", "fine", latency_ms=20, article_size_bytes=1024)
        self.assertTrue(provider_confidence_report(self.db)[0]["confidence_score"] > 0)
        self.assertIn("projected_db_bytes", db_growth_report(self.db, self.config))
        receipt = file_integrity_receipt(self.db, file_id)
        self.assertEqual(receipt["chunk_count"], 2)
        export = backup_manifest_export(self.db, self.config)
        self.assertTrue(export["enabled"])
        self.assertEqual(export["file_count"], 1)
        preview = restore_preview(self.db, [file_id])
        self.assertEqual(preview["files"], 1)
        self.config.audit_mode = True
        audit_event(self.db, self.config, "tester", "unit.action", {"file_id": file_id})
        self.assertEqual(len(self.db.list_events(["info"], event_types=["audit"])), 1)

    def test_readiness_maintenance_and_config_history_reports(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"abc")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
            conn.execute("UPDATE files SET state='backed_up' WHERE id=?", (file_id,))
        self.db.add_chunk(file_id, 0, "<chunk@example.test>", 3, "abc", "[hidden]")
        readiness = backup_readiness_report(self.db, self.config)
        self.assertIn("score", readiness)
        self.assertEqual(readiness["protection_coverage"], 100)
        self.assertEqual(readiness["score"], readiness["protection_coverage"])
        self.assertLess(readiness["hardening_score"], readiness["protection_coverage"])
        self.assertTrue(readiness["hardening_gaps"])
        schedule = maintenance_schedule_report(self.db, self.config)
        self.assertIn("estimated_reclaimable_hint_bytes", schedule)
        record_config_history(self.db, "tester", ["read_only_mode", "web_ui_role"])
        history = config_history_rows(self.db)
        self.assertEqual(history[0]["actor"], "tester")
        self.assertIn("read_only_mode", history[0]["keys"])

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

    def test_usenet_hosts_for_mode_are_priority_sorted(self):
        self.config.usenet_hosts = [
            UsenetHost(name="low", mode="post", host="low.example.test", port=563, tls="implicit", priority=10),
            UsenetHost(name="high", mode="post", host="high.example.test", port=563, tls="implicit", priority=500),
            UsenetHost(name="read", mode="read", host="read.example.test", port=563, tls="implicit", priority=999),
        ]
        self.assertEqual([host.name for host in self.config.hosts_for_mode("post")], ["high", "low"])

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
        self.assertEqual(public["auth_state"], "incomplete")

    def test_public_host_dict_reports_auth_state(self):
        self.assertEqual(
            UsenetHost(name="post", mode="post", host="post.example.test", port=563).public_dict()["auth_state"],
            "missing",
        )
        self.assertEqual(
            UsenetHost(
                name="post",
                mode="post",
                host="post.example.test",
                port=563,
                username="user",
            ).public_dict()["auth_state"],
            "incomplete",
        )
        self.assertEqual(
            UsenetHost(
                name="post",
                mode="post",
                host="post.example.test",
                port=563,
                username="user",
                password="secret",
            ).public_dict()["auth_state"],
            "configured",
        )

    def test_usenet_client_rejects_missing_auth_before_connecting(self):
        host = UsenetHost(name="post", mode="post", host="post.example.test", port=563, tls="implicit")
        with self.assertRaisesRegex(RuntimeError, "missing username and password"):
            with UsenetClient(host):
                pass

    def test_usenet_client_rejects_incomplete_auth_before_connecting(self):
        host = UsenetHost(name="post", mode="post", host="post.example.test", port=563, tls="implicit", username="user")
        with self.assertRaisesRegex(RuntimeError, "missing password"):
            with UsenetClient(host):
                pass

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

    def test_worker_next_run_persists_for_restart(self):
        monitor = CatalogMonitor(self.db, self.config)
        monitor._schedule_next(123)
        original_next_run = monitor.tasks()[0]["next_run_at"]
        restarted = CatalogMonitor(self.db, self.config)
        tasks = restarted.tasks()
        self.assertEqual(tasks[0]["next_run_at"], original_next_run)
        self.assertEqual(tasks[0]["name"], "Catalog monitor")
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
        progress = []
        with patch("backuprr.backup.UsenetClient", FakeReadClient):
            self.assertEqual(verify_file_chunks(self.db, self.config, [rows[0]["id"]], progress=lambda done, total: progress.append((done, total))), 1)
        self.assertEqual(progress, [(1, 1)])
        with self.db.connect() as conn:
            verified = conn.execute("SELECT file_id FROM chunks WHERE status='verified'").fetchall()
        self.assertEqual([row["file_id"] for row in verified], [rows[0]["id"]])

    def test_verify_selected_file_chunks_updates_compacted_manifest(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"movie")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
        self.db.add_chunk(file_id, 0, "<one@example.test>", 3, "abc", "[one]")
        self.db.add_chunk(file_id, 1, "<two@example.test>", 3, "def", "[two]")
        self.assertEqual(self.db.compact_chunks_to_manifest(file_id), 2)
        self.config.usenet_hosts.append(UsenetHost(name="read", mode="read", host="example.test", port=563, tls="implicit"))
        progress = []
        with patch("backuprr.backup.UsenetClient", FakeReadClient):
            self.assertEqual(verify_file_chunks(self.db, self.config, [file_id], progress=lambda done, total: progress.append((done, total))), 2)
        self.assertEqual(progress, [(1, 2), (2, 2)])
        with self.db.connect() as conn:
            compact = conn.execute("SELECT verified_count, missing_count FROM chunk_manifests WHERE file_id=?", (file_id,)).fetchone()
            file_row = conn.execute("SELECT last_verify_at FROM files WHERE id=?", (file_id,)).fetchone()
            live = conn.execute("SELECT COUNT(*) FROM chunks WHERE file_id=?", (file_id,)).fetchone()[0]
        self.assertEqual(live, 0)
        self.assertEqual(compact["verified_count"], 2)
        self.assertEqual(compact["missing_count"], 0)
        self.assertIsNotNone(file_row["last_verify_at"])

    def test_verification_rate_limit_does_not_mark_chunks_missing(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"movie")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
            conn.execute("UPDATE files SET state='backed_up' WHERE id=?", (file_id,))
        self.db.add_chunk(file_id, 0, "<rate-limited@example.test>", 3, "abc", "[hidden]")
        self.config.usenet_hosts.append(UsenetHost(name="read", mode="read", host="example.test", port=563, tls="implicit"))
        progress = []

        with patch("backuprr.backup.UsenetClient", RateLimitedReadClient):
            self.assertEqual(verify_file_chunks(self.db, self.config, [file_id], progress=lambda done, total: progress.append((done, total))), 0)

        self.assertEqual(progress, [(1, 1)])
        with self.db.connect() as conn:
            chunk = conn.execute("SELECT status, verified_at FROM chunks WHERE file_id=?", (file_id,)).fetchone()
            file_row = conn.execute("SELECT state, last_verify_at FROM files WHERE id=?", (file_id,)).fetchone()
            event = conn.execute("SELECT level, event_type, message FROM events ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(chunk["status"], "posted")
        self.assertIsNone(chunk["verified_at"])
        self.assertEqual(file_row["state"], "backed_up")
        self.assertIsNone(file_row["last_verify_at"])
        self.assertEqual(event["event_type"], "verify.retry")
        self.assertIn("rate limit", event["message"])

    def test_force_verification_rechecks_missing_chunks(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"movie")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
            conn.execute("UPDATE files SET state='failed' WHERE id=?", (file_id,))
        self.db.add_chunk(file_id, 0, "<missing@example.test>", 3, "abc", "[hidden]")
        with self.db.connect() as conn:
            chunk_id = conn.execute("SELECT id FROM chunks WHERE file_id=?", (file_id,)).fetchone()["id"]
        self.db.mark_chunk_verified(chunk_id, exists=False)
        with self.db.connect() as conn:
            conn.execute("UPDATE queue SET status='failed', reason='missing-chunks' WHERE file_id=?", (file_id,))
        self.config.usenet_hosts.append(UsenetHost(name="read", mode="read", host="example.test", port=563, tls="implicit"))

        with patch("backuprr.backup.UsenetClient", FakeReadClient):
            self.assertEqual(verify_due_chunks(self.db, self.config, force=True), 1)

        with self.db.connect() as conn:
            chunk = conn.execute("SELECT status FROM chunks WHERE id=?", (chunk_id,)).fetchone()
            file_row = conn.execute("SELECT state FROM files WHERE id=?", (file_id,)).fetchone()
            queue_row = conn.execute("SELECT status, reason FROM queue WHERE file_id=?", (file_id,)).fetchone()
        self.assertEqual(chunk["status"], "verified")
        self.assertEqual(file_row["state"], "backed_up")
        self.assertEqual(queue_row["status"], "done")
        self.assertEqual(queue_row["reason"], "verified-recovered")

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
        progress = []
        with patch("backuprr.restore.UsenetClient", FakeRestoreClient):
            self.assertEqual(restore_file(self.db, self.config, str(path), str(target), progress=lambda done, total, bytes_done: progress.append((done, total, bytes_done))), target)
        self.assertEqual(target.read_bytes(), b"restored payload")
        self.assertEqual(progress, [(1, 1, len(b"restored payload"))])

    def test_restore_file_reads_compacted_manifest_chunks(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"placeholder")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
        self.db.add_chunk(file_id, 0, "<chunk@example.test>", 16, "abc", "[hidden]")
        self.assertEqual(self.db.compact_chunks_to_manifest(file_id), 1)
        self.config.usenet_hosts.append(UsenetHost(name="read", mode="read", host="example.test", port=563, tls="implicit"))
        target = self.root / "restore" / "movie.mkv"
        with patch("backuprr.restore.UsenetClient", FakeRestoreClient):
            self.assertEqual(restore_file(self.db, self.config, str(path), str(target)), target)
        self.assertEqual(target.read_bytes(), b"restored payload")

    def test_restore_sandbox_validates_before_replacing_origin(self):
        media = self.root / "media"
        media.mkdir()
        path = media / "movie.mkv"
        path.write_bytes(b"placeholder")
        self.db.add_endpoint(str(media))
        scan_all(self.db)
        with self.db.connect() as conn:
            file_id = conn.execute("SELECT id FROM files").fetchone()["id"]
            conn.execute("UPDATE files SET sha256=?, size=? WHERE id=?", (hashlib.sha256(b"restored payload").hexdigest(), len(b"restored payload"), file_id))
        self.db.add_chunk(file_id, 0, "<chunk@example.test>", 16, "abc", "[hidden]")
        self.config.restore_sandbox_enabled = True
        self.config.restore_sandbox_path = str(self.root / "sandbox")
        self.config.usenet_hosts.append(UsenetHost(name="read", mode="read", host="example.test", port=563, tls="implicit"))
        with patch("backuprr.restore.UsenetClient", FakeRestoreClient):
            self.assertEqual(restore_file(self.db, self.config, str(path)), path)
        self.assertEqual(path.read_bytes(), b"restored payload")
        self.assertFalse(any((self.root / "sandbox").iterdir()))

    def test_restored_payloads_reports_download_progress(self):
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
        progress = []
        with patch("backuprr.restore.UsenetClient", FakeRestoreClient):
            _, payloads = restored_payloads(self.db, self.config, str(path), progress=lambda done, total, bytes_done: progress.append((done, total, bytes_done)))
            self.assertEqual(b"".join(payloads), b"restored payload")
        self.assertEqual(progress, [(1, 1, len(b"restored payload"))])

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
        self.config.retention_policy_patterns = ["critical:*.mkv:14"]
        confidence = restore_confidence(self.db, str(path), self.config)
        self.assertTrue(confidence["restorable"])
        self.assertEqual(confidence["chunk_count"], 1)
        self.assertGreaterEqual(confidence["confidence_score"], 70)
        self.assertFalse(confidence["par2_protected"])
        self.assertEqual(confidence["retention_policy"]["policy"], "critical")
        self.assertEqual(retention_policy_for_path(self.config, str(path))["verification_interval_days"], 14)

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
        original_mtime_ns = path.stat().st_mtime_ns
        self.config.usenet_hosts.append(UsenetHost(name="read", mode="read", host="example.test", port=563, tls="implicit"))
        with patch("backuprr.restore.UsenetClient", FakeRestoreClient):
            self.assertEqual(restore_file(self.db, self.config, str(path)), path)
        self.assertEqual(path.stat().st_mtime_ns, original_mtime_ns)
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
