import email.message
import hashlib
import nntplib
import os
import ssl
import uuid
from dataclasses import dataclass
from typing import Iterable, Optional

from .config import Config, UsenetHost


@dataclass
class PostedArticle:
    message_id: str
    subject: str
    size: int
    sha256: str


class UsenetClient:
    def __init__(self, host: UsenetHost, timeout: int = 60):
        self.host = host
        self.timeout = timeout
        self.conn: Optional[nntplib.NNTP] = None

    def __enter__(self) -> "UsenetClient":
        username = self.host.resolved_username()
        password = self.host.resolved_password()
        if not username and not password:
            raise RuntimeError(f"NNTP host {self.host.name} is missing username and password")
        if bool(username) != bool(password):
            missing = "password" if username else "username"
            raise RuntimeError(f"NNTP host {self.host.name} has incomplete authentication: missing {missing}")
        if self.host.tls == "implicit":
            self.conn = nntplib.NNTP_SSL(self.host.host, self.host.port, timeout=self.timeout)
        else:
            self.conn = nntplib.NNTP(self.host.host, self.host.port, timeout=self.timeout)
            if self.host.tls == "starttls":
                context = ssl.create_default_context()
                self.conn.starttls(context=context)
        if username and password:
            self.conn.login(username, password)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.conn:
            self.conn.quit()

    def post(self, newsgroup: str, subject: str, body: bytes) -> str:
        if not self.conn:
            raise RuntimeError("NNTP connection not open")
        message_id = f"<{uuid.uuid4().hex}@backuprr.local>"
        msg = email.message.EmailMessage()
        msg["From"] = "Backuprr <backuprr@backuprr.local>"
        msg["Newsgroups"] = newsgroup
        msg["Subject"] = subject
        msg["Message-ID"] = message_id
        msg.set_content(body, maintype="application", subtype="octet-stream", cte="base64")
        self.conn.post(msg.as_bytes().splitlines())
        return message_id

    def article_exists(self, message_id: str) -> bool:
        if not self.conn:
            raise RuntimeError("NNTP connection not open")
        try:
            self.conn.stat(message_id)
            return True
        except nntplib.NNTPTemporaryError:
            raise
        except nntplib.NNTPPermanentError as exc:
            message = str(exc).lower()
            if message.startswith("430") or "no such article" in message or "not found" in message:
                return False
            raise


def obfuscated_subject(file_id: int, chunk_index: int, sha256_hex: str) -> str:
    token = hashlib.sha256(f"{file_id}:{chunk_index}:{sha256_hex}:{os.urandom(16).hex()}".encode()).hexdigest()
    return f"[{token[:32]}] ({chunk_index + 1})"


def select_host(config: Config, mode: str) -> UsenetHost:
    hosts = config.hosts_for_mode(mode)
    if not hosts:
        raise RuntimeError(f"No Usenet host configured for mode {mode}")
    return hosts[0]


class DryRunUsenetClient:
    def __init__(self):
        self.articles = {}

    def post_many(self, newsgroup: str, subjects_and_bodies: Iterable[tuple[str, bytes]]) -> list[PostedArticle]:
        posted = []
        for subject, body in subjects_and_bodies:
            digest = hashlib.sha256(body).hexdigest()
            article = PostedArticle(f"<dryrun-{digest}@backuprr.local>", subject, len(body), digest)
            self.articles[article.message_id] = body
            posted.append(article)
        return posted
