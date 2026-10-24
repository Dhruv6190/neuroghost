"""HMAC signing for verified memories, and SHA-256 fingerprints for the audit log."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_or_create_secret(data_dir: Path) -> bytes:
    """Secret key from NEUROGHOST_SECRET, else a key file in the data dir (never in the repo)."""
    env = os.environ.get("NEUROGHOST_SECRET")
    if env:
        return env.encode("utf-8")
    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / "secret.key"
    if path.exists():
        return path.read_bytes()
    key = secrets.token_bytes(32)
    path.write_bytes(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


class Signer:
    def __init__(self, key: bytes):
        self._key = key

    @staticmethod
    def _message(memory_id: str, text: str, source: str, created_at: str) -> bytes:
        return "\x1f".join([memory_id, text, source, created_at]).encode("utf-8")

    def sign(self, memory_id: str, text: str, source: str, created_at: str) -> str:
        return hmac.new(self._key, self._message(memory_id, text, source, created_at), hashlib.sha256).hexdigest()

    def verify(self, signature: str | None, memory_id: str, text: str, source: str, created_at: str) -> bool:
        if not signature:
            return False
        expected = self.sign(memory_id, text, source, created_at)
        return hmac.compare_digest(expected, signature)
