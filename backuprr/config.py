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
    username_env: Optional[str] = None
    password_env: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UsenetHost":
        return cls(**data)

    def resolved_username(self) -> Optional[str]:
        return os.getenv(self.username_env) if self.username_env else self.username

    def resolved_password(self) -> Optional[str]:
        return os.getenv(self.password_env) if self.password_env else self.password


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

