import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

from .backup import post_next
from .config import Config
from .db import Database
from .queueing import enqueue_unbacked
from .scanner import scan_all


def utcnow_dt() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso_or_empty(value: Optional[datetime]) -> str:
    return value.isoformat() if value else ""


def format_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return ""
    total = max(0, int(round(seconds)))
    minutes, secs = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


class ScheduledTask:
    def __init__(self, db: Database, config: Config, name: str, kind: str):
        self.db = db
        self.config = config
        self.name = name
        self.kind = kind
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._state_lock = threading.Lock()
        self._last_started_at: Optional[datetime] = None
        self._last_finished_at: Optional[datetime] = None
        self._next_run_at: Optional[datetime] = None
        self._last_duration_seconds: Optional[float] = None
        self._last_result = ""
        self._last_error = ""
        self._runs = 0
        self._running = False
        self._revision = 0

    @property
    def interval_seconds(self) -> int:
        raise NotImplementedError

    def execute(self) -> str:
        raise NotImplementedError

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name=f"backuprr-{self.kind}", daemon=True)
        self._thread.start()
        self._schedule_next(0)
        self.trigger()

    def trigger(self) -> None:
        self._wake.set()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=5)

    def run_once(self) -> str:
        if not self._lock.acquire(blocking=False):
            self.db.log("verbose", f"{self.kind}.task", f"{self.name} already running")
            return "already running"
        self._mark_started()
        try:
            result = self.execute()
            self._mark_finished(result, "")
            return result
        except Exception as exc:
            self._mark_finished("", str(exc))
            self.db.log("error", f"{self.kind}.task", f"{self.name} failed: {exc}")
            return f"failed: {exc}"
        finally:
            self._lock.release()

    def task_info(self):
        now = utcnow_dt()
        with self._state_lock:
            until_next = ""
            if self._next_run_at:
                until_next = format_duration((self._next_run_at - now).total_seconds())
            return {
                "name": self.name,
                "kind": self.kind,
                "status": "running" if self._running else "scheduled",
                "interval_seconds": self.interval_seconds,
                "last_run": iso_or_empty(self._last_finished_at),
                "last_run_duration": format_duration(self._last_duration_seconds),
                "time_until_next_run": until_next,
                "runs": self._runs,
                "last_result": self._last_result,
                "last_error": self._last_error,
                "revision": self._revision,
            }

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(timeout=self.interval_seconds)
            self._wake.clear()
            if self._stop.is_set():
                break
            self.run_once()
            self._schedule_next(self.interval_seconds)

    def _mark_started(self) -> None:
        with self._state_lock:
            self._running = True
            self._last_started_at = utcnow_dt()
            self._last_error = ""
            self._revision += 1

    def _mark_finished(self, result: str, error: str) -> None:
        finished = utcnow_dt()
        with self._state_lock:
            self._running = False
            self._last_finished_at = finished
            if self._last_started_at:
                self._last_duration_seconds = (finished - self._last_started_at).total_seconds()
            self._runs += 1
            self._last_result = result
            self._last_error = error
            self._next_run_at = utcnow_dt() + timedelta(seconds=self.interval_seconds)
            self._revision += 1

    def _schedule_next(self, seconds: int) -> None:
        with self._state_lock:
            self._next_run_at = utcnow_dt() + timedelta(seconds=seconds)
            self._revision += 1


class CatalogMonitor(ScheduledTask):
    def __init__(self, db: Database, config: Config):
        super().__init__(db, config, "Catalog monitor", "catalog")

    @property
    def interval_seconds(self) -> int:
        return self.config.scan_interval_seconds

    def scan_once(self) -> int:
        result = self.run_once()
        try:
            return int(result.split(" ", 1)[0])
        except (ValueError, IndexError):
            return 0

    def execute(self) -> str:
        count = scan_all(self.db)
        queued = enqueue_unbacked(self.db)
        result = f"{count} files cataloged, {queued} queued"
        self.db.log("info", "monitor.scan", f"Automatic catalog scan completed: {result}")
        return result

    def tasks(self):
        return [self.task_info()]


class BackupMonitor(ScheduledTask):
    def __init__(self, db: Database, config: Config):
        super().__init__(db, config, "Usenet backup worker", "backup")

    @property
    def interval_seconds(self) -> int:
        return self.config.backup_interval_seconds

    def post_once(self) -> Optional[int]:
        result = self.run_once()
        if result.startswith("posted file id "):
            return int(result.removeprefix("posted file id ").split(",", 1)[0])
        return None

    def execute(self) -> str:
        newly_queued = enqueue_unbacked(self.db)
        file_id = post_next(self.db, self.config)
        stats = self.db.stats()
        queued = int(stats.get("queue_queued", 0))
        posting = int(stats.get("queue_posting", 0))
        if file_id is None:
            result = f"{newly_queued} newly queued, {queued} queued, {posting} posting, no file posted"
        else:
            result = f"posted file id {file_id}, {queued} queued, {posting} posting"
        self.db.log("info", "monitor.backup", f"Automatic backup task completed: {result}")
        return result

    def tasks(self):
        return [self.task_info()]
