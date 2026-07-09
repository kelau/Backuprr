import threading
from typing import Optional

from .config import Config
from .db import Database
from .scanner import scan_all


class CatalogMonitor:
    def __init__(self, db: Database, config: Config):
        self.db = db
        self.config = config
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, name="backuprr-catalog-monitor", daemon=True)
        self._thread.start()
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
        try:
            count = scan_all(self.db)
            self.db.log("info", "monitor.scan", f"Automatic catalog scan completed: {count} files")
            return count
        except Exception as exc:
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
