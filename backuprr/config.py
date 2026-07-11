import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class UsenetHost:
    name: str
    mode: str
    host: str
    port: int
    tls: str = "plain"
    username: Optional[str] = None
    password: Optional[str] = None
    priority: int = 100

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UsenetHost":
        supported = {key: data.get(key) for key in ("name", "mode", "host", "port", "tls", "username", "password", "priority")}
        if supported["priority"] is None:
            supported["priority"] = 100
        return cls(**supported)

    def resolved_username(self) -> Optional[str]:
        return self.username

    def resolved_password(self) -> Optional[str]:
        return self.password

    def public_dict(self) -> Dict[str, Any]:
        data = self.__dict__.copy()
        data["has_password"] = bool(data.get("password"))
        if data.get("password"):
            data["password"] = ""
        return data


@dataclass
class CloudBackupTarget:
    name: str
    provider: str = "local"
    target: str = ""
    command: str = ""
    enabled: bool = True

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CloudBackupTarget":
        supported = {key: data.get(key) for key in ("name", "provider", "target", "command", "enabled")}
        if supported["enabled"] is None:
            supported["enabled"] = True
        return cls(**supported)


@dataclass
class LogDestination:
    name: str
    platform: str = "loki"
    url: str = ""
    api_key: str = ""
    username: str = ""
    password: str = ""
    min_level: str = "info"
    timeout_seconds: int = 5
    enabled: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogDestination":
        supported = {
            key: data.get(key)
            for key in ("name", "platform", "url", "api_key", "username", "password", "min_level", "timeout_seconds", "enabled")
        }
        if supported["enabled"] is None:
            supported["enabled"] = False
        if supported["timeout_seconds"] is None:
            supported["timeout_seconds"] = 5
        return cls(**supported)

    def public_dict(self) -> Dict[str, Any]:
        data = self.__dict__.copy()
        data["has_api_key"] = bool(data.get("api_key"))
        data["has_password"] = bool(data.get("password"))
        if data.get("api_key"):
            data["api_key"] = ""
        if data.get("password"):
            data["password"] = ""
        return data


@dataclass
class Config:
    database: str = "backuprr.sqlite3"
    article_size: int = 768 * 1024
    newsgroup: str = "alt.binaries.backup"
    verification_interval_days: int = 90
    verification_task_interval_seconds: int = 3600
    verification_files_per_run: int = 1
    scan_interval_seconds: int = 300
    backup_interval_seconds: int = 300
    cloud_backup_interval_seconds: int = 3600
    maintenance_interval_seconds: int = 86400
    restore_drill_task_interval_seconds: int = 86400
    file_stability_seconds: int = 300
    nntp_threads: int = 4
    hourly_post_limit_bytes: int = 0
    usenet_retry_attempts: int = 2
    usenet_retry_backoff_seconds: int = 5
    log_retention_days: int = 30
    verbose_log_retention_days: int = 7
    restore_drill_interval_days: int = 30
    restore_drill_sample_bytes: int = 1024 * 1024
    log_web_access: bool = False
    log_chunk_events: bool = False
    compact_chunk_metadata: bool = True
    transfer_sample_bucket_seconds: int = 60
    auto_queue_exclude_patterns: List[str] = field(default_factory=list)
    ui_theme: str = "harbor_light"
    usenet_hosts: List[UsenetHost] = field(default_factory=list)
    cloud_backups: List[CloudBackupTarget] = field(default_factory=list)
    log_destinations: List[LogDestination] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    zip_subfolders: bool = False
    encrypt_bodies: bool = False
    encryption_passphrase_env: str = "BACKUPRR_ENCRYPTION_PASSPHRASE"
    par2: Dict[str, Any] = field(default_factory=lambda: {"enabled": False})
    base_dir: Path = field(default_factory=lambda: Path.cwd())
    source_path: Optional[Path] = None

    @classmethod
    def load(cls, path: str) -> "Config":
        config_path = Path(path)
        data: Dict[str, Any] = {}
        if config_path.exists():
            data = json.loads(config_path.read_text(encoding="utf-8-sig"))
        hosts = [UsenetHost.from_dict(item) for item in data.pop("usenet_hosts", [])]
        cloud_backups = [CloudBackupTarget.from_dict(item) for item in data.pop("cloud_backups", [])]
        log_destinations = [LogDestination.from_dict(item) for item in data.pop("log_destinations", [])]
        config = cls(**data)
        config.usenet_hosts = hosts
        config.cloud_backups = cloud_backups
        config.log_destinations = log_destinations
        config.base_dir = config_path.resolve().parent
        config.source_path = config_path.resolve()
        return config

    def save(self, path: str) -> None:
        data = self.to_dict()
        Path(path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def db_path(self) -> Path:
        path = Path(self.database)
        return path if path.is_absolute() else self.base_dir / path

    def encryption_passphrase(self) -> Optional[str]:
        return os.getenv(self.encryption_passphrase_env)

    def hosts_for_mode(self, mode: str) -> List[UsenetHost]:
        return sorted((host for host in self.usenet_hosts if host.mode == mode), key=lambda host: (-int(host.priority), host.name))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "database": self.database,
            "article_size": self.article_size,
            "newsgroup": self.newsgroup,
            "verification_interval_days": self.verification_interval_days,
            "verification_task_interval_seconds": self.verification_task_interval_seconds,
            "verification_files_per_run": self.verification_files_per_run,
            "scan_interval_seconds": self.scan_interval_seconds,
            "backup_interval_seconds": self.backup_interval_seconds,
            "cloud_backup_interval_seconds": self.cloud_backup_interval_seconds,
            "maintenance_interval_seconds": self.maintenance_interval_seconds,
            "restore_drill_task_interval_seconds": self.restore_drill_task_interval_seconds,
            "file_stability_seconds": self.file_stability_seconds,
            "nntp_threads": self.nntp_threads,
            "hourly_post_limit_bytes": self.hourly_post_limit_bytes,
            "usenet_retry_attempts": self.usenet_retry_attempts,
            "usenet_retry_backoff_seconds": self.usenet_retry_backoff_seconds,
            "log_retention_days": self.log_retention_days,
            "verbose_log_retention_days": self.verbose_log_retention_days,
            "restore_drill_interval_days": self.restore_drill_interval_days,
            "restore_drill_sample_bytes": self.restore_drill_sample_bytes,
            "log_web_access": self.log_web_access,
            "log_chunk_events": self.log_chunk_events,
            "compact_chunk_metadata": self.compact_chunk_metadata,
            "transfer_sample_bucket_seconds": self.transfer_sample_bucket_seconds,
            "auto_queue_exclude_patterns": self.auto_queue_exclude_patterns,
            "ui_theme": self.ui_theme,
            "usenet_hosts": [host.__dict__ for host in self.usenet_hosts],
            "cloud_backups": [target.__dict__ for target in self.cloud_backups],
            "log_destinations": [destination.__dict__ for destination in self.log_destinations],
            "endpoints": self.endpoints,
            "zip_subfolders": self.zip_subfolders,
            "encrypt_bodies": self.encrypt_bodies,
            "encryption_passphrase_env": self.encryption_passphrase_env,
            "par2": self.par2,
        }

    def public_dict(self) -> Dict[str, Any]:
        data = self.to_dict()
        data["usenet_hosts"] = [host.public_dict() for host in self.usenet_hosts]
        data["log_destinations"] = [destination.public_dict() for destination in self.log_destinations]
        return data


def update_config(config: Config, data: Dict[str, Any]) -> None:
    if "article_size" in data:
        article_size = int(data["article_size"])
        if article_size < 100 * 1024 or article_size > 5 * 1024 * 1024:
            raise ValueError("article_size must be between 100 KiB and 5 MiB")
        config.article_size = article_size
    if "newsgroup" in data:
        newsgroup = str(data["newsgroup"]).strip()
        if not newsgroup:
            raise ValueError("newsgroup is required")
        config.newsgroup = newsgroup
    if "verification_interval_days" in data:
        interval = int(data["verification_interval_days"])
        if interval < 1 or interval > 180:
            raise ValueError("verification_interval_days must be between 1 and 180")
        config.verification_interval_days = interval
    if "verification_task_interval_seconds" in data:
        interval = int(data["verification_task_interval_seconds"])
        if interval <= 0:
            raise ValueError("verification_task_interval_seconds must be greater than zero")
        config.verification_task_interval_seconds = interval
    if "verification_files_per_run" in data:
        files_per_run = int(data["verification_files_per_run"])
        if files_per_run <= 0:
            raise ValueError("verification_files_per_run must be greater than zero")
        config.verification_files_per_run = files_per_run
    if "scan_interval_seconds" in data:
        interval = int(data["scan_interval_seconds"])
        if interval <= 0:
            raise ValueError("scan_interval_seconds must be greater than zero")
        config.scan_interval_seconds = interval
    if "backup_interval_seconds" in data:
        interval = int(data["backup_interval_seconds"])
        if interval <= 0:
            raise ValueError("backup_interval_seconds must be greater than zero")
        config.backup_interval_seconds = interval
    if "cloud_backup_interval_seconds" in data:
        interval = int(data["cloud_backup_interval_seconds"])
        if interval <= 0:
            raise ValueError("cloud_backup_interval_seconds must be greater than zero")
        config.cloud_backup_interval_seconds = interval
    if "maintenance_interval_seconds" in data:
        interval = int(data["maintenance_interval_seconds"])
        if interval <= 0:
            raise ValueError("maintenance_interval_seconds must be greater than zero")
        config.maintenance_interval_seconds = interval
    if "restore_drill_task_interval_seconds" in data:
        interval = int(data["restore_drill_task_interval_seconds"])
        if interval <= 0:
            raise ValueError("restore_drill_task_interval_seconds must be greater than zero")
        config.restore_drill_task_interval_seconds = interval
    if "file_stability_seconds" in data:
        seconds = int(data["file_stability_seconds"])
        if seconds < 0 or seconds > 86400:
            raise ValueError("file_stability_seconds must be between 0 and 86400")
        config.file_stability_seconds = seconds
    if "nntp_threads" in data:
        threads = int(data["nntp_threads"])
        if threads < 1 or threads > 50:
            raise ValueError("nntp_threads must be between 1 and 50")
        config.nntp_threads = threads
    if "hourly_post_limit_bytes" in data:
        limit = int(data["hourly_post_limit_bytes"] or 0)
        if limit < 0:
            raise ValueError("hourly_post_limit_bytes cannot be negative")
        config.hourly_post_limit_bytes = limit
    if "usenet_retry_attempts" in data:
        attempts = int(data["usenet_retry_attempts"])
        if attempts < 1 or attempts > 10:
            raise ValueError("usenet_retry_attempts must be between 1 and 10")
        config.usenet_retry_attempts = attempts
    if "usenet_retry_backoff_seconds" in data:
        backoff = int(data["usenet_retry_backoff_seconds"])
        if backoff < 0 or backoff > 3600:
            raise ValueError("usenet_retry_backoff_seconds must be between 0 and 3600")
        config.usenet_retry_backoff_seconds = backoff
    if "log_retention_days" in data:
        days = int(data["log_retention_days"])
        if days < 1 or days > 3650:
            raise ValueError("log_retention_days must be between 1 and 3650")
        config.log_retention_days = days
    if "verbose_log_retention_days" in data:
        days = int(data["verbose_log_retention_days"])
        if days < 1 or days > 3650:
            raise ValueError("verbose_log_retention_days must be between 1 and 3650")
        config.verbose_log_retention_days = days
    if "restore_drill_interval_days" in data:
        days = int(data["restore_drill_interval_days"])
        if days < 1 or days > 3650:
            raise ValueError("restore_drill_interval_days must be between 1 and 3650")
        config.restore_drill_interval_days = days
    if "restore_drill_sample_bytes" in data:
        size = int(data["restore_drill_sample_bytes"])
        if size < 1:
            raise ValueError("restore_drill_sample_bytes must be greater than zero")
        config.restore_drill_sample_bytes = size
    if "log_web_access" in data:
        config.log_web_access = bool(data["log_web_access"])
    if "log_chunk_events" in data:
        config.log_chunk_events = bool(data["log_chunk_events"])
    if "compact_chunk_metadata" in data:
        config.compact_chunk_metadata = bool(data["compact_chunk_metadata"])
    if "transfer_sample_bucket_seconds" in data:
        seconds = int(data["transfer_sample_bucket_seconds"])
        if seconds < 1 or seconds > 3600:
            raise ValueError("transfer_sample_bucket_seconds must be between 1 and 3600")
        config.transfer_sample_bucket_seconds = seconds
    if "auto_queue_exclude_patterns" in data:
        config.auto_queue_exclude_patterns = [str(item).strip() for item in data["auto_queue_exclude_patterns"] if str(item).strip()]
    if "ui_theme" in data:
        theme = str(data["ui_theme"]).strip()
        if theme not in {"harbor_light", "emerald_console", "slate_cinema", "graphite", "nordic_mint"}:
            raise ValueError("ui_theme is not a supported template")
        config.ui_theme = theme
    if "zip_subfolders" in data:
        config.zip_subfolders = bool(data["zip_subfolders"])
    if "encrypt_bodies" in data:
        config.encrypt_bodies = bool(data["encrypt_bodies"])
    if "encryption_passphrase_env" in data:
        env_name = str(data["encryption_passphrase_env"]).strip()
        if not env_name:
            raise ValueError("encryption_passphrase_env is required")
        config.encryption_passphrase_env = env_name
    if "endpoints" in data:
        config.endpoints = [str(item).strip() for item in data["endpoints"] if str(item).strip()]
    if "usenet_hosts" in data:
        hosts = []
        existing_passwords = {host.name: host.password for host in config.usenet_hosts if host.password}
        for item in data["usenet_hosts"]:
            host = UsenetHost.from_dict(item)
            if host.password in {"", None} and host.name in existing_passwords:
                host.password = existing_passwords[host.name]
            if host.mode not in {"read", "post"}:
                raise ValueError("Usenet host mode must be read or post")
            if host.tls not in {"plain", "starttls", "implicit"}:
                raise ValueError("Usenet host tls must be plain, starttls, or implicit")
            if not host.name or not host.host:
                raise ValueError("Usenet host name and host are required")
            if host.port <= 0:
                raise ValueError("Usenet host port must be greater than zero")
            host.priority = max(0, int(host.priority))
            hosts.append(host)
        config.usenet_hosts = hosts
    if "cloud_backups" in data:
        targets = []
        for item in data["cloud_backups"]:
            target = CloudBackupTarget.from_dict(item)
            target.enabled = bool(target.enabled)
            target.name = str(target.name or "").strip()
            target.provider = str(target.provider or "local").strip()
            target.target = str(target.target or "").strip()
            target.command = str(target.command or "").strip()
            if not target.name:
                raise ValueError("Cloud backup target name is required")
            if target.provider not in {"local", "google_drive", "onedrive", "command"}:
                raise ValueError("Cloud backup provider must be local, google_drive, onedrive, or command")
            if target.provider == "command" and not target.command:
                raise ValueError("Command cloud backup targets require a command")
            if target.provider != "command" and not target.target:
                raise ValueError("Cloud backup targets require a destination path")
            targets.append(target)
        config.cloud_backups = targets
    if "log_destinations" in data:
        destinations = []
        existing_api_keys = {destination.name: destination.api_key for destination in config.log_destinations if destination.api_key}
        existing_passwords = {destination.name: destination.password for destination in config.log_destinations if destination.password}
        for item in data["log_destinations"]:
            destination = LogDestination.from_dict(item)
            destination.name = str(destination.name or "").strip()
            destination.platform = str(destination.platform or "loki").strip()
            destination.url = str(destination.url or "").strip()
            destination.api_key = str(destination.api_key or "")
            destination.username = str(destination.username or "").strip()
            destination.password = str(destination.password or "")
            destination.min_level = str(destination.min_level or "info").strip()
            destination.timeout_seconds = int(destination.timeout_seconds or 5)
            destination.enabled = bool(destination.enabled)
            if destination.api_key == "" and destination.name in existing_api_keys:
                destination.api_key = existing_api_keys[destination.name]
            if destination.password == "" and destination.name in existing_passwords:
                destination.password = existing_passwords[destination.name]
            if not destination.name:
                raise ValueError("Log destination name is required")
            if destination.platform not in {"loki", "seq", "graylog", "elastic", "logstash", "splunk_hec"}:
                raise ValueError("Log destination platform is not supported")
            if destination.min_level not in {"error", "warning", "info", "debug", "verbose"}:
                raise ValueError("Log destination min_level is not supported")
            if destination.timeout_seconds < 1 or destination.timeout_seconds > 60:
                raise ValueError("Log destination timeout_seconds must be between 1 and 60")
            if destination.enabled and not destination.url:
                raise ValueError("Enabled log destinations require a URL")
            destinations.append(destination)
        config.log_destinations = destinations
    if "par2" in data:
        par2 = dict(config.par2)
        par2.update(data["par2"] or {})
        par2["enabled"] = bool(par2.get("enabled"))
        par2["redundancy_percent"] = int(par2.get("redundancy_percent", 10))
        if par2["redundancy_percent"] < 1 or par2["redundancy_percent"] > 50:
            raise ValueError("PAR2 redundancy percent must be between 1 and 50")
        config.par2 = par2
