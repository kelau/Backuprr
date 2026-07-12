import json
import re
from datetime import datetime, timezone
from typing import Any, Dict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from . import __version__
from .config import Config
from .db import Database


META_KEY = "update_check_result"


def normalize_version(value: str) -> str:
    return str(value or "").strip().removeprefix("v").removeprefix("V")


def version_parts(value: str) -> list[int]:
    return [int(part) for part in re.findall(r"\d+", normalize_version(value))]


def compare_versions(left: str, right: str) -> int:
    left_parts = version_parts(left)
    right_parts = version_parts(right)
    for index in range(max(len(left_parts), len(right_parts))):
        delta = (left_parts[index] if index < len(left_parts) else 0) - (right_parts[index] if index < len(right_parts) else 0)
        if delta:
            return 1 if delta > 0 else -1
    return 0


def update_result(db: Database) -> Dict[str, Any]:
    raw = db.get_meta(META_KEY)
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"status": "error", "error": "stored update check result is invalid"}


def save_update_result(db: Database, result: Dict[str, Any]) -> None:
    db.set_meta(META_KEY, json.dumps(result, sort_keys=True))


def latest_release_url(config: Config) -> str:
    repo = str(config.update_github_repo or "").strip().strip("/")
    return f"https://api.github.com/repos/{repo}/releases/latest"


def check_for_updates(db: Database, config: Config, opener=urlopen) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    current = __version__
    if not config.update_check_enabled:
        result = {"status": "disabled", "checked_at": now, "current_version": current}
        save_update_result(db, result)
        return result
    url = latest_release_url(config)
    try:
        request = Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": f"Backuprr/{current}"})
        with opener(request, timeout=int(config.update_check_timeout_seconds)) as response:
            payload = json.loads(response.read().decode("utf-8"))
        latest = normalize_version(str(payload.get("tag_name") or payload.get("name") or ""))
        if not latest:
            raise ValueError("GitHub response did not include a release tag")
        available = compare_versions(latest, current) > 0
        result = {
            "status": "ok",
            "checked_at": now,
            "current_version": current,
            "latest_version": latest,
            "update_available": available,
            "html_url": payload.get("html_url") or f"https://github.com/{config.update_github_repo}/releases",
            "name": payload.get("name") or latest,
            "published_at": payload.get("published_at") or "",
            "body": payload.get("body") or "",
            "source": url,
        }
        db.log("info" if available else "debug", "update.check", f"Update check completed: latest={latest}, current={current}, available={available}")
    except (HTTPError, URLError, OSError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        result = {"status": "error", "checked_at": now, "current_version": current, "error": str(exc), "source": url}
        db.log("warning", "update.check", f"Update check failed: {exc}")
    save_update_result(db, result)
    return result
