import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

from .config import Config
from .db import Database
from .scanner import scan_all


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class CatalogMonitor:
    def __init__(self, db: Database, config: Config):
        self.db = db
        self.config = config
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._state_lock = threading.Lock()
        self._last_started_at: Optional[str] = None
        self._last_finished_at: Optional[str] = None
        self._next_run_at: Optional[str] = None
        self._last_result = ""
        self._last_error = ""
        self._runs = 0
        self._running = False

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="backuprr-catalog-monitor", daemon=True)
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

    def scan_once(self) -> int:
        if not self._lock.acquire(blocking=False):
            self.db.log("verbose", "monitor.scan", "Catalog scan already running")
            return 0
        self._mark_started()
        try:
            count = scan_all(self.db)
            self._mark_finished(f"{count} files cataloged", "")
            self.db.log("info", "monitor.scan", f"Automatic catalog scan completed: {count} files")
            return count
        except Exception as exc:
            self._mark_finished("", str(exc))
            self.db.log("error", "monitor.scan", f"Automatic catalog scan failed: {exc}")
            return 0
        finally:
            self._lock.release()

    def _run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(timeout=self.config.scan_interval_seconds)
            self._wake.clear()
            if self._stop.is_set():
                break
            self.scan_once()
            self._schedule_next(self.config.scan_interval_seconds)

    def tasks(self):
        with self._state_lock:
            return [
                {
                    "name": "Catalog monitor",
                    "kind": "catalog",
                    "status": "running" if self._running else "scheduled",
                    "interval_seconds": self.config.scan_interval_seconds,
                    "last_started_at": self._last_started_at,
                    "last_finished_at": self._last_finished_at,
                    "next_run_at": self._next_run_at,
                    "runs": self._runs,
                    "last_result": self._last_result,
                    "last_error": self._last_error,
                }
            ]

    def _mark_started(self) -> None:
        with self._state_lock:
            self._running = True
            self._last_started_at = now_iso()
            self._last_error = ""

    def _mark_finished(self, result: str, error: str) -> None:
        with self._state_lock:
            self._running = False
            self._last_finished_at = now_iso()
            self._runs += 1
            self._last_result = result
            self._last_error = error
            self._next_run_at = (
                datetime.now(timezone.utc) + timedelta(seconds=self.config.scan_interval_seconds)
            ).replace(microsecond=0).isoformat()

    def _schedule_next(self, seconds: int) -> None:
        with self._state_lock:
            self._next_run_at = (
                datetime.now(timezone.utc) + timedelta(seconds=seconds)
            ).replace(microsecond=0).isoformat()
