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

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UsenetHost":
        supported = {key: data.get(key) for key in ("name", "mode", "host", "port", "tls", "username", "password")}
        return cls(**supported)

    def resolved_username(self) -> Optional[str]:
        return self.username

    def resolved_password(self) -> Optional[str]:
        return self.password

    def public_dict(self) -> Dict[str, Any]:
        data = self.__dict__.copy()
        if data.get("password"):
            data["password"] = ""
        return data


@dataclass
class Config:
    database: str = "backuprr.sqlite3"
    article_size: int = 768 * 1024
    newsgroup: str = "alt.binaries.backup"
    verification_interval_days: int = 90
    usenet_hosts: List[UsenetHost] = field(default_factory=list)
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
            data = json.loads(config_path.read_text(encoding="utf-8"))
        hosts = [UsenetHost.from_dict(item) for item in data.pop("usenet_hosts", [])]
        config = cls(**data)
        config.usenet_hosts = hosts
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
        return [host for host in self.usenet_hosts if host.mode == mode]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "database": self.database,
            "article_size": self.article_size,
            "newsgroup": self.newsgroup,
            "verification_interval_days": self.verification_interval_days,
            "usenet_hosts": [host.__dict__ for host in self.usenet_hosts],
            "endpoints": self.endpoints,
            "zip_subfolders": self.zip_subfolders,
            "encrypt_bodies": self.encrypt_bodies,
            "encryption_passphrase_env": self.encryption_passphrase_env,
            "par2": self.par2,
        }

    def public_dict(self) -> Dict[str, Any]:
        data = self.to_dict()
        data["usenet_hosts"] = [host.public_dict() for host in self.usenet_hosts]
        return data


def update_config(config: Config, data: Dict[str, Any]) -> None:
    if "article_size" in data:
        article_size = int(data["article_size"])
        if article_size <= 0:
            raise ValueError("article_size must be greater than zero")
        config.article_size = article_size
    if "newsgroup" in data:
        newsgroup = str(data["newsgroup"]).strip()
        if not newsgroup:
            raise ValueError("newsgroup is required")
        config.newsgroup = newsgroup
    if "verification_interval_days" in data:
        interval = int(data["verification_interval_days"])
        if interval <= 0:
            raise ValueError("verification_interval_days must be greater than zero")
        config.verification_interval_days = interval
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
            if host.password == "" and host.name in existing_passwords:
                host.password = existing_passwords[host.name]
            if host.mode not in {"read", "post"}:
                raise ValueError("Usenet host mode must be read or post")
            if host.tls not in {"plain", "starttls", "implicit"}:
                raise ValueError("Usenet host tls must be plain, starttls, or implicit")
            if not host.name or not host.host:
                raise ValueError("Usenet host name and host are required")
            if host.port <= 0:
                raise ValueError("Usenet host port must be greater than zero")
            hosts.append(host)
        config.usenet_hosts = hosts
    if "par2" in data:
        par2 = dict(config.par2)
        par2.update(data["par2"] or {})
        par2["enabled"] = bool(par2.get("enabled"))
        par2["redundancy_percent"] = int(par2.get("redundancy_percent", 10))
        if par2["redundancy_percent"] < 0:
            raise ValueError("PAR2 redundancy percent cannot be negative")
        config.par2 = par2
