import json
import os
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


def latest_tags_url(config: Config) -> str:
    repo = str(config.update_github_repo or "").strip().strip("/")
    return f"https://api.github.com/repos/{repo}/tags?per_page=1"


def github_token(config: Config) -> str:
    env_name = str(getattr(config, "update_github_token_env", "GITHUB_TOKEN") or "GITHUB_TOKEN").strip()
    return os.getenv(env_name) or os.getenv("GH_TOKEN") or ""


def github_json(url: str, current: str, timeout: int, config: Config, opener=urlopen) -> Dict[str, Any] | list[Any]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": f"Backuprr/{current}"}
    token = github_token(config)
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    request = Request(url, headers=headers)
    with opener(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def check_for_updates(db: Database, config: Config, opener=urlopen) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    current = __version__
    if not config.update_check_enabled:
        result = {"status": "disabled", "checked_at": now, "current_version": current}
        save_update_result(db, result)
        return result
    url = latest_release_url(config)
    try:
        timeout = int(config.update_check_timeout_seconds)
        source_kind = "release"
        try:
            payload = github_json(url, current, timeout, config, opener)
        except HTTPError as exc:
            if exc.code != 404:
                raise
            tag_url = latest_tags_url(config)
            tags = github_json(tag_url, current, timeout, config, opener)
            if not isinstance(tags, list) or not tags:
                raise ValueError("GitHub returned no releases or tags for the configured repository") from exc
            payload = tags[0]
            url = tag_url
            source_kind = "tag"
        if not isinstance(payload, dict):
            raise ValueError("GitHub response did not include a release object")
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
            "source_kind": source_kind,
        }
        db.log("info" if available else "debug", "update.check", f"Update check completed: latest={latest}, current={current}, available={available}")
    except (HTTPError, URLError, OSError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        error = str(exc)
        if isinstance(exc, HTTPError) and exc.code == 404 and not github_token(config):
            error = f"{exc}. If the repository is private, set {getattr(config, 'update_github_token_env', 'GITHUB_TOKEN')} or GH_TOKEN for update checks."
        result = {"status": "error", "checked_at": now, "current_version": current, "error": error, "source": url}
        db.log("warning", "update.check", f"Update check failed: {exc}")
    save_update_result(db, result)
    return result
