"""Exit check: scrubs secrets from anything leaving the agent, and watches for canary tokens."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(
        r"(?i)((?:private|secret|priv|signing)[\s_-]*key|seed|mnemonic)([^\n]{0,40}?)\b(0x)?[a-f0-9]{64}\b")),
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{40,}")),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

CANARY_RE = re.compile(r"ng-canary-[a-f0-9]{16}")


@dataclass
class EgressResult:
    text: str
    redactions: list[str] = field(default_factory=list)
    canaries: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.redactions and not self.canaries


class EgressGuard:
    def __init__(self):
        self._known_secrets: set[str] = set()

    def register_secret(self, secret: str) -> None:
        """Register an exact value that must never leave the system (e.g. the wallet's private key)."""
        if secret and len(secret) >= 8:
            self._known_secrets.add(secret)
            if secret.startswith("0x"):
                self._known_secrets.add(secret[2:])

    def scan(self, text: str, known_canaries: set[str] | None = None) -> EgressResult:
        out = text or ""
        redactions: list[str] = []

        for secret in sorted(self._known_secrets, key=len, reverse=True):
            if secret in out:
                out = out.replace(secret, "[REDACTED_SECRET]")
                redactions.append("registered_secret")

        for name, pattern in SECRET_PATTERNS:
            if name == "private_key":
                def _sub(m: re.Match) -> str:
                    return f"{m.group(1)}{m.group(2)}[REDACTED_PRIVATE_KEY]"
                out, n = pattern.subn(_sub, out)
            else:
                out, n = pattern.subn("[REDACTED_SECRET]", out)
            if n:
                redactions.extend([name] * n)

        canaries = []
        for token in CANARY_RE.findall(out):
            if known_canaries is None or token in known_canaries:
                canaries.append(token)
        return EgressResult(out, redactions, canaries)
