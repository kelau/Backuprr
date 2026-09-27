import base64
import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


SECRET_PREFIX = "enc:v1:"


def _secret_stream(key: str, length: int) -> bytes:
    """Build a deterministic byte stream for opt-in config secret protection."""
    seed = hashlib.sha256(key.encode("utf-8")).digest()
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha256(seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:length])


def protect_secret(value: str, key: str) -> str:
    """Store secrets as authenticated protected values when a secret key is configured."""
    if not value or value.startswith(SECRET_PREFIX):
        return value
    raw = value.encode("utf-8")
    encrypted = bytes(left ^ right for left, right in zip(raw, _secret_stream(key, len(raw))))
    mac = hmac.new(key.encode("utf-8"), encrypted, hashlib.sha256).digest()[:12]
    return SECRET_PREFIX + base64.urlsafe_b64encode(mac + encrypted).decode("ascii")


def unprotect_secret(value: str, key: str) -> str:
    if not value or not value.startswith(SECRET_PREFIX):
        return value
    payload = base64.urlsafe_b64decode(value[len(SECRET_PREFIX) :].encode("ascii"))
    mac, encrypted = payload[:12], payload[12:]
    expected = hmac.new(key.encode("utf-8"), encrypted, hashlib.sha256).digest()[:12]
    if not hmac.compare_digest(mac, expected):
        raise ValueError("protected config secret could not be authenticated")
    raw = bytes(left ^ right for left, right in zip(encrypted, _secret_stream(key, len(encrypted))))
    return raw.decode("utf-8")


def _secret_key_from_env(env_name: str) -> str:
    return os.getenv(env_name) or os.getenv("BACKUPRR_CONFIG_SECRET") or ""


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

    def auth_state(self) -> str:
        if self.username and self.password:
            return "configured"
        if self.username or self.password:
            return "incomplete"
        return "missing"

    def public_dict(self) -> Dict[str, Any]:
        data = self.__dict__.copy()
        data["has_password"] = bool(data.get("password"))
        data["auth_state"] = self.auth_state()
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
    update_check_interval_seconds: int = 86400
    file_stability_seconds: int = 300
    nntp_threads: int = 4
    hourly_post_limit_bytes: int = 0
    auto_pause_auth_failures: int = 3
    auto_pause_provider_failures: int = 10
    usenet_retry_attempts: int = 2
    usenet_retry_backoff_seconds: int = 5
    log_retention_days: int = 30
    verbose_log_retention_days: int = 7
    restore_drill_interval_days: int = 30
    restore_drill_sample_bytes: int = 1024 * 1024
    log_web_access: bool = False
    log_chunk_events: bool = False
    compact_chunk_metadata: bool = True
    compact_chunk_rows: bool = True
    transfer_sample_bucket_seconds: int = 60
    compression_sample_bytes: int = 2 * 1024 * 1024
    compression_min_gain_percent: int = 5
    queue_strategy: str = "older-first"
    auto_queue_exclude_patterns: List[str] = field(default_factory=list)
    queue_pause_patterns: List[str] = field(default_factory=list)
    retention_policy_patterns: List[str] = field(default_factory=list)
    critical_verification_interval_days: int = 30
    external_api_keys: List[str] = field(default_factory=list)
    external_api_key_scopes: Dict[str, List[str]] = field(default_factory=dict)
    api_rate_limit_per_minute: int = 120
    external_api_rate_limit_per_minute: int = 60
    web_ui_username: str = "admin"
    web_ui_password: str = ""
    web_ui_role: str = "admin"
    web_ui_totp_secret_env: str = "BACKUPRR_TOTP_SECRET"
    read_only_mode: bool = False
    config_secret_key_env: str = "BACKUPRR_CONFIG_SECRET"
    auto_vacuum_after_compaction_rows: int = 100000
    provider_retry_policy: Dict[str, Dict[str, int]] = field(default_factory=dict)
    restore_sandbox_enabled: bool = False
    restore_sandbox_path: str = ""
    audit_mode: bool = False
    audit_secret_key_env: str = "BACKUPRR_AUDIT_SECRET"
    manifest_export_enabled: bool = True
    manifest_export_encrypt: bool = False
    manifest_export_passphrase_env: str = "BACKUPRR_MANIFEST_EXPORT_SECRET"
    manifest_export_interval_seconds: int = 86400
    ui_theme: str = "harbor_light"
    ui_reduced_motion: bool = False
    update_check_enabled: bool = True
    update_github_repo: str = "kelau/Backuprr"
    update_github_token_env: str = "GITHUB_TOKEN"
    update_check_timeout_seconds: int = 10
    usenet_hosts: List[UsenetHost] = field(default_factory=list)
    cloud_backups: List[CloudBackupTarget] = field(default_factory=list)
    log_destinations: List[LogDestination] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    compress_files: bool = False
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
        key = _secret_key_from_env(str(data.get("config_secret_key_env") or "BACKUPRR_CONFIG_SECRET"))
        if key:
            _unprotect_config_data(data, key)
        legacy_zip_subfolders = bool(data.get("zip_subfolders")) and "compress_files" not in data
        hosts = [UsenetHost.from_dict(item) for item in data.pop("usenet_hosts", [])]
        cloud_backups = [CloudBackupTarget.from_dict(item) for item in data.pop("cloud_backups", [])]
        log_destinations = [LogDestination.from_dict(item) for item in data.pop("log_destinations", [])]
        config = cls(**data)
        config.usenet_hosts = hosts
        config.cloud_backups = cloud_backups
        config.log_destinations = log_destinations
        if legacy_zip_subfolders:
            config.compress_files = True
        config.base_dir = config_path.resolve().parent
        config.source_path = config_path.resolve()
        if not config_path.exists():
            config_path.parent.mkdir(parents=True, exist_ok=True)
            config.save(str(config_path))
        return config

    def save(self, path: str) -> None:
        data = self.to_dict()
        key = _secret_key_from_env(self.config_secret_key_env)
        if key:
            _protect_config_data(data, key)
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
            "update_check_interval_seconds": self.update_check_interval_seconds,
            "file_stability_seconds": self.file_stability_seconds,
            "nntp_threads": self.nntp_threads,
            "hourly_post_limit_bytes": self.hourly_post_limit_bytes,
            "auto_pause_auth_failures": self.auto_pause_auth_failures,
            "auto_pause_provider_failures": self.auto_pause_provider_failures,
            "usenet_retry_attempts": self.usenet_retry_attempts,
            "usenet_retry_backoff_seconds": self.usenet_retry_backoff_seconds,
            "log_retention_days": self.log_retention_days,
            "verbose_log_retention_days": self.verbose_log_retention_days,
            "restore_drill_interval_days": self.restore_drill_interval_days,
            "restore_drill_sample_bytes": self.restore_drill_sample_bytes,
            "log_web_access": self.log_web_access,
            "log_chunk_events": self.log_chunk_events,
            "compact_chunk_metadata": self.compact_chunk_metadata,
            "compact_chunk_rows": self.compact_chunk_rows,
            "transfer_sample_bucket_seconds": self.transfer_sample_bucket_seconds,
            "compression_sample_bytes": self.compression_sample_bytes,
            "compression_min_gain_percent": self.compression_min_gain_percent,
            "queue_strategy": self.queue_strategy,
            "auto_queue_exclude_patterns": self.auto_queue_exclude_patterns,
            "queue_pause_patterns": self.queue_pause_patterns,
            "retention_policy_patterns": self.retention_policy_patterns,
            "critical_verification_interval_days": self.critical_verification_interval_days,
            "external_api_keys": self.external_api_keys,
            "external_api_key_scopes": self.external_api_key_scopes,
            "api_rate_limit_per_minute": self.api_rate_limit_per_minute,
            "external_api_rate_limit_per_minute": self.external_api_rate_limit_per_minute,
            "web_ui_username": self.web_ui_username,
            "web_ui_password": self.web_ui_password,
            "web_ui_role": self.web_ui_role,
            "web_ui_totp_secret_env": self.web_ui_totp_secret_env,
            "read_only_mode": self.read_only_mode,
            "config_secret_key_env": self.config_secret_key_env,
            "auto_vacuum_after_compaction_rows": self.auto_vacuum_after_compaction_rows,
            "provider_retry_policy": self.provider_retry_policy,
            "restore_sandbox_enabled": self.restore_sandbox_enabled,
            "restore_sandbox_path": self.restore_sandbox_path,
            "audit_mode": self.audit_mode,
            "audit_secret_key_env": self.audit_secret_key_env,
            "manifest_export_enabled": self.manifest_export_enabled,
            "manifest_export_encrypt": self.manifest_export_encrypt,
            "manifest_export_passphrase_env": self.manifest_export_passphrase_env,
            "manifest_export_interval_seconds": self.manifest_export_interval_seconds,
            "ui_theme": self.ui_theme,
            "ui_reduced_motion": self.ui_reduced_motion,
            "update_check_enabled": self.update_check_enabled,
            "update_github_repo": self.update_github_repo,
            "update_github_token_env": self.update_github_token_env,
            "update_check_timeout_seconds": self.update_check_timeout_seconds,
            "usenet_hosts": [host.__dict__ for host in self.usenet_hosts],
            "cloud_backups": [target.__dict__ for target in self.cloud_backups],
            "log_destinations": [destination.__dict__ for destination in self.log_destinations],
            "endpoints": self.endpoints,
            "compress_files": self.compress_files,
            "zip_subfolders": self.zip_subfolders,
            "encrypt_bodies": self.encrypt_bodies,
            "encryption_passphrase_env": self.encryption_passphrase_env,
            "par2": self.par2,
        }

    def public_dict(self) -> Dict[str, Any]:
        data = self.to_dict()
        data["usenet_hosts"] = [host.public_dict() for host in self.usenet_hosts]
        data["log_destinations"] = [destination.public_dict() for destination in self.log_destinations]
        data["external_api_key_count"] = len(self.external_api_keys)
        data["external_api_keys"] = []
        data["external_api_key_scopes"] = {key[:4] + "..." + key[-4:]: scopes for key, scopes in self.external_api_key_scopes.items()}
        data["has_web_ui_password"] = bool(self.web_ui_password)
        data["web_ui_password"] = ""
        data["totp_enabled"] = bool(os.getenv(self.web_ui_totp_secret_env))
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
    if "update_check_interval_seconds" in data:
        interval = int(data["update_check_interval_seconds"])
        if interval < 3600 or interval > 30 * 86400:
            raise ValueError("update_check_interval_seconds must be between 1 hour and 30 days")
        config.update_check_interval_seconds = interval
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
    if "auto_pause_auth_failures" in data:
        failures = int(data["auto_pause_auth_failures"])
        if failures < 0 or failures > 100:
            raise ValueError("auto_pause_auth_failures must be between 0 and 100")
        config.auto_pause_auth_failures = failures
    if "auto_pause_provider_failures" in data:
        failures = int(data["auto_pause_provider_failures"])
        if failures < 0 or failures > 1000:
            raise ValueError("auto_pause_provider_failures must be between 0 and 1000")
        config.auto_pause_provider_failures = failures
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
    if "compact_chunk_rows" in data:
        config.compact_chunk_rows = bool(data["compact_chunk_rows"])
    if "transfer_sample_bucket_seconds" in data:
        seconds = int(data["transfer_sample_bucket_seconds"])
        if seconds < 1 or seconds > 3600:
            raise ValueError("transfer_sample_bucket_seconds must be between 1 and 3600")
        config.transfer_sample_bucket_seconds = seconds
    if "compression_sample_bytes" in data:
        sample_bytes = int(data["compression_sample_bytes"])
        if sample_bytes < 0 or sample_bytes > 64 * 1024 * 1024:
            raise ValueError("compression_sample_bytes must be between 0 and 64 MiB")
        config.compression_sample_bytes = sample_bytes
    if "compression_min_gain_percent" in data:
        gain = int(data["compression_min_gain_percent"])
        if gain < 0 or gain > 95:
            raise ValueError("compression_min_gain_percent must be between 0 and 95")
        config.compression_min_gain_percent = gain
    if "queue_strategy" in data:
        strategy = str(data["queue_strategy"]).strip()
        if strategy not in {"older-first", "larger-first", "smaller-first", "folder-first"}:
            raise ValueError("queue_strategy must be older-first, larger-first, smaller-first, or folder-first")
        config.queue_strategy = strategy
    if "auto_queue_exclude_patterns" in data:
        config.auto_queue_exclude_patterns = [str(item).strip() for item in data["auto_queue_exclude_patterns"] if str(item).strip()]
    if "queue_pause_patterns" in data:
        config.queue_pause_patterns = [str(item).strip() for item in data["queue_pause_patterns"] if str(item).strip()]
    if "retention_policy_patterns" in data:
        config.retention_policy_patterns = [str(item).strip() for item in data["retention_policy_patterns"] if str(item).strip()]
    if "critical_verification_interval_days" in data:
        days = int(data["critical_verification_interval_days"])
        if days < 1 or days > 180:
            raise ValueError("critical_verification_interval_days must be between 1 and 180")
        config.critical_verification_interval_days = days
    if "external_api_keys" in data:
        keys = [str(item).strip() for item in data["external_api_keys"] if str(item).strip()]
        if keys:
            config.external_api_keys = keys
            config.external_api_key_scopes = {
                key: config.external_api_key_scopes.get(key, ["read", "backup", "verify"])
                for key in keys
            }
        elif data.get("clear_external_api_keys"):
            config.external_api_keys = []
            config.external_api_key_scopes = {}
    if "external_api_key_scopes" in data:
        allowed_scopes = {"read", "backup", "scan", "verify", "restore", "admin"}
        scopes: Dict[str, List[str]] = {}
        for key, value in dict(data["external_api_key_scopes"] or {}).items():
            if str(key) not in config.external_api_keys:
                continue
            values = [str(item).strip() for item in (value if isinstance(value, list) else str(value).split(",")) if str(item).strip()]
            if not values:
                values = ["read"]
            if any(scope not in allowed_scopes for scope in values):
                raise ValueError("external_api_key_scopes contains an unsupported scope")
            scopes[str(key)] = sorted(set(values))
        config.external_api_key_scopes = scopes
    if "api_rate_limit_per_minute" in data:
        limit = int(data["api_rate_limit_per_minute"] or 0)
        if limit < 0 or limit > 10000:
            raise ValueError("api_rate_limit_per_minute must be between 0 and 10000")
        config.api_rate_limit_per_minute = limit
    if "external_api_rate_limit_per_minute" in data:
        limit = int(data["external_api_rate_limit_per_minute"] or 0)
        if limit < 0 or limit > 10000:
            raise ValueError("external_api_rate_limit_per_minute must be between 0 and 10000")
        config.external_api_rate_limit_per_minute = limit
    if "web_ui_username" in data:
        username = str(data["web_ui_username"]).strip()
        if not username:
            raise ValueError("web_ui_username cannot be blank")
        config.web_ui_username = username
    if "web_ui_role" in data:
        role = str(data["web_ui_role"]).strip()
        if role not in {"admin", "operator", "read_only"}:
            raise ValueError("web_ui_role must be admin, operator, or read_only")
        config.web_ui_role = role
    if "web_ui_totp_secret_env" in data:
        config.web_ui_totp_secret_env = str(data["web_ui_totp_secret_env"] or "BACKUPRR_TOTP_SECRET").strip() or "BACKUPRR_TOTP_SECRET"
    if "read_only_mode" in data:
        config.read_only_mode = bool(data["read_only_mode"])
    if data.get("web_ui_password"):
        config.web_ui_password = str(data["web_ui_password"])
    elif data.get("clear_web_ui_password"):
        config.web_ui_password = ""
    if "config_secret_key_env" in data:
        config.config_secret_key_env = str(data["config_secret_key_env"]).strip() or "BACKUPRR_CONFIG_SECRET"
    if "auto_vacuum_after_compaction_rows" in data:
        threshold = int(data["auto_vacuum_after_compaction_rows"] or 0)
        if threshold < 0:
            raise ValueError("auto_vacuum_after_compaction_rows cannot be negative")
        config.auto_vacuum_after_compaction_rows = threshold
    if "provider_retry_policy" in data:
        policy: Dict[str, Dict[str, int]] = {}
        for key, value in dict(data["provider_retry_policy"] or {}).items():
            if key not in {"auth", "network", "provider", "tool", "locked_file", "hourly_limit"}:
                raise ValueError("provider_retry_policy contains an unsupported failure class")
            attempts = int(dict(value or {}).get("attempts", 1))
            backoff = int(dict(value or {}).get("backoff_seconds", 0))
            if attempts < 0 or attempts > 25 or backoff < 0 or backoff > 86400:
                raise ValueError("provider_retry_policy attempts/backoff are out of range")
            policy[key] = {"attempts": attempts, "backoff_seconds": backoff}
        config.provider_retry_policy = policy
    if "restore_sandbox_enabled" in data:
        config.restore_sandbox_enabled = bool(data["restore_sandbox_enabled"])
    if "restore_sandbox_path" in data:
        config.restore_sandbox_path = str(data["restore_sandbox_path"] or "").strip()
    if "audit_mode" in data:
        config.audit_mode = bool(data["audit_mode"])
    if "audit_secret_key_env" in data:
        config.audit_secret_key_env = str(data["audit_secret_key_env"] or "BACKUPRR_AUDIT_SECRET").strip()
    if "manifest_export_enabled" in data:
        config.manifest_export_enabled = bool(data["manifest_export_enabled"])
    if "manifest_export_encrypt" in data:
        config.manifest_export_encrypt = bool(data["manifest_export_encrypt"])
    if "manifest_export_passphrase_env" in data:
        config.manifest_export_passphrase_env = str(data["manifest_export_passphrase_env"] or "BACKUPRR_MANIFEST_EXPORT_SECRET").strip()
    if "manifest_export_interval_seconds" in data:
        interval = int(data["manifest_export_interval_seconds"] or 0)
        if interval < 3600 or interval > 30 * 86400:
            raise ValueError("manifest_export_interval_seconds must be between 1 hour and 30 days")
        config.manifest_export_interval_seconds = interval
    if "ui_theme" in data:
        theme = str(data["ui_theme"]).strip()
        if theme not in {"harbor_light", "emerald_console", "slate_cinema", "graphite", "nordic_mint"}:
            raise ValueError("ui_theme is not a supported template")
        config.ui_theme = theme
    if "ui_reduced_motion" in data:
        config.ui_reduced_motion = bool(data["ui_reduced_motion"])
    if "update_check_enabled" in data:
        config.update_check_enabled = bool(data["update_check_enabled"])
    if "update_github_repo" in data:
        repo = str(data["update_github_repo"]).strip().strip("/")
        if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", repo):
            raise ValueError("update_github_repo must be in owner/repo format")
        config.update_github_repo = repo
    if "update_github_token_env" in data:
        config.update_github_token_env = str(data["update_github_token_env"] or "GITHUB_TOKEN").strip() or "GITHUB_TOKEN"
    if "update_check_timeout_seconds" in data:
        timeout = int(data["update_check_timeout_seconds"])
        if timeout < 1 or timeout > 60:
            raise ValueError("update_check_timeout_seconds must be between 1 and 60")
        config.update_check_timeout_seconds = timeout
    if "zip_subfolders" in data:
        config.zip_subfolders = bool(data["zip_subfolders"])
        if "compress_files" not in data:
            config.compress_files = bool(data["zip_subfolders"])
    if "compress_files" in data:
        config.compress_files = bool(data["compress_files"])
        config.zip_subfolders = False
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


def _protect_config_data(data: Dict[str, Any], key: str) -> None:
    for host in data.get("usenet_hosts", []):
        if host.get("password"):
            host["password"] = protect_secret(str(host["password"]), key)
    for destination in data.get("log_destinations", []):
        if destination.get("api_key"):
            destination["api_key"] = protect_secret(str(destination["api_key"]), key)
        if destination.get("password"):
            destination["password"] = protect_secret(str(destination["password"]), key)
    if data.get("external_api_keys"):
        data["external_api_keys"] = [protect_secret(str(item), key) for item in data["external_api_keys"]]
    if data.get("web_ui_password"):
        data["web_ui_password"] = protect_secret(str(data["web_ui_password"]), key)


def _unprotect_config_data(data: Dict[str, Any], key: str) -> None:
    for host in data.get("usenet_hosts", []):
        if host.get("password"):
            host["password"] = unprotect_secret(str(host["password"]), key)
    for destination in data.get("log_destinations", []):
        if destination.get("api_key"):
            destination["api_key"] = unprotect_secret(str(destination["api_key"]), key)
        if destination.get("password"):
            destination["password"] = unprotect_secret(str(destination["password"]), key)
    if data.get("external_api_keys"):
        data["external_api_keys"] = [unprotect_secret(str(item), key) for item in data["external_api_keys"]]
    if data.get("web_ui_password"):
        data["web_ui_password"] = unprotect_secret(str(data["web_ui_password"]), key)
