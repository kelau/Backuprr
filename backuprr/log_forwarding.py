import base64
import json
import queue
import threading
from typing import Any, Dict, Iterable, Optional
from urllib import request

from .config import LogDestination


LEVEL_ORDER = {"verbose": 10, "debug": 20, "info": 30, "warning": 40, "error": 50}


class LogForwarder:
    def __init__(self, destinations: Iterable[LogDestination]):
        self.destinations = [dest for dest in destinations if dest.enabled]
        self.queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=1000)
        self.thread: Optional[threading.Thread] = None
        if self.destinations:
            self.thread = threading.Thread(target=self._run, name="backuprr-log-forwarder", daemon=True)
            self.thread.start()

    def __call__(self, event: Dict[str, Any]) -> None:
        if not self.destinations:
            return
        try:
            self.queue.put_nowait(dict(event))
        except queue.Full:
            return

    def _run(self) -> None:
        while True:
            event = self.queue.get()
            for destination in self.destinations:
                if LEVEL_ORDER.get(str(event.get("level")), 0) >= LEVEL_ORDER.get(destination.min_level, 0):
                    try:
                        self._send(destination, event)
                    except Exception:
                        pass
            self.queue.task_done()

    def _send(self, destination: LogDestination, event: Dict[str, Any]) -> None:
        url = destination.url
        if not url:
            return
        payload, headers = build_payload(destination, event)
        req = request.Request(url, data=payload, headers=headers, method="POST")
        request.urlopen(req, timeout=destination.timeout_seconds).close()


def build_payload(destination: LogDestination, event: Dict[str, Any]) -> tuple[bytes, Dict[str, str]]:
    labels = {"app": "backuprr", "level": str(event.get("level", "")), "event_type": str(event.get("event_type", ""))}
    body = {
        "timestamp": event.get("ts"),
        "level": event.get("level"),
        "event_type": event.get("event_type"),
        "message": event.get("message"),
        "file_id": event.get("file_id"),
        "data": event.get("data") or "",
        "application": "backuprr",
    }
    headers = {"Content-Type": "application/json"}
    if destination.api_key:
        if destination.platform == "splunk_hec":
            headers["Authorization"] = f"Splunk {destination.api_key}"
        elif destination.platform == "seq":
            headers["X-Seq-ApiKey"] = destination.api_key
        elif destination.platform in {"elastic", "logstash", "graylog"}:
            headers["Authorization"] = f"Bearer {destination.api_key}"
    if destination.username or destination.password:
        raw = f"{destination.username}:{destination.password}".encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")

    if destination.platform == "loki":
        payload = {
            "streams": [
                {
                    "stream": labels,
                    "values": [[str(_ts_nanos(event.get("ts"))), json.dumps(body, separators=(",", ":"))]],
                }
            ]
        }
        return json.dumps(payload).encode("utf-8"), headers
    if destination.platform == "graylog":
        payload = {
            "version": "1.1",
            "host": "backuprr",
            "short_message": str(event.get("message", "")),
            "level": _syslog_level(str(event.get("level", ""))),
            "_event_type": event.get("event_type"),
            "_file_id": event.get("file_id"),
            "_data": event.get("data") or "",
        }
        return json.dumps(payload).encode("utf-8"), headers
    if destination.platform == "splunk_hec":
        return json.dumps({"event": body, "sourcetype": "backuprr:event"}).encode("utf-8"), headers
    return json.dumps(body).encode("utf-8"), headers


def _ts_nanos(value: Any) -> int:
    from datetime import datetime

    if not value:
        return 0
    text = str(value).replace("Z", "+00:00")
    try:
        return int(datetime.fromisoformat(text).timestamp() * 1_000_000_000)
    except ValueError:
        return 0


def _syslog_level(level: str) -> int:
    return {"error": 3, "warning": 4, "info": 6, "debug": 7, "verbose": 7}.get(level, 6)
