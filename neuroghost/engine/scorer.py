"""Layer 2 - Memory Guard. Combines the checks into one risk score.

    R = w_directive * H + w_drift * D + w_money * A        (default 0.50 / 0.30 / 0.20)

R >= threshold (0.55) -> QUARANTINE, otherwise COMMIT.
Trusted sources (the user typing directly) use a higher threshold (0.85).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import numpy as np

from .drift import DriftProfile
from .heuristics import DirectiveScanner
from .money import money_check
from .sanitizer import SanitizeResult, sanitize


@dataclass
class ScoreReport:
    clean_text: str
    risk: float
    directive: float
    drift: float
    money: float
    decision: str  # "COMMIT" or "QUARANTINE"
    threshold_used: float
    flags: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    new_addresses: list[str] = field(default_factory=list)
    all_addresses: list[str] = field(default_factory=list)
    sanitize_findings: list[str] = field(default_factory=list)
    elapsed_ms: float = 0.0
    embedding: np.ndarray | None = None

    def as_dict(self) -> dict:
        return {
            "risk_score": round(self.risk, 3),
            "components": {"H": round(self.directive, 3), "D": round(self.drift, 3), "A": round(self.money, 3)},
            "decision": self.decision,
            "threshold": self.threshold_used,
            "flags": self.flags,
            "categories": self.categories,
            "new_addresses": self.new_addresses,
            "sanitizer": self.sanitize_findings,
            "execution_time_ms": round(self.elapsed_ms, 2),
        }


class RiskScorer:
    def __init__(self, settings, embedder, profile: DriftProfile):
        self.settings = settings
        self.embedder = embedder
        self.profile = profile
        self.scanner = DirectiveScanner(settings.directive_rules)

    def score(self, raw_text: str, source: str, extra_known: dict[str, str] | None = None) -> ScoreReport:
        t0 = time.perf_counter()
        s: SanitizeResult = sanitize(raw_text)

        directive = self.scanner.scan(s.scan)
        H = 1.0 if directive.hit else 0.0
        flags = list(directive.matches)
        categories = list(directive.categories)
        if s.obfuscated:
            flags.extend(s.findings)
            categories.append("obfuscation")
            if self.settings.obfuscation_counts_as_directive:
                H = 1.0

        vec = self.embedder.embed([s.clean or " "])[0]
        D = self.profile.distance(vec)

        known = dict(self.settings.allowlist)
        if extra_known:
            known.update(extra_known)
        money = money_check(s.clean, known)
        A = 1.0 if money.hit else 0.0
        if money.hit:
            flags.append("new wallet address: " + ", ".join(a[:12] + ("..." if len(a) > 12 else "") for a in money.new_addresses))
            categories.append("new_payee")

        w = self.settings.weights
        risk = float(np.clip(w["directive"] * H + w["drift"] * D + w["money"] * A, 0.0, 1.0))
        threshold = self.settings.trusted_threshold if source in self.settings.trusted_sources else self.settings.threshold
        decision = "QUARANTINE" if risk >= threshold else "COMMIT"

        return ScoreReport(
            clean_text=s.clean,
            risk=risk,
            directive=H,
            drift=D,
            money=A,
            decision=decision,
            threshold_used=threshold,
            flags=flags,
            categories=categories,
            new_addresses=money.new_addresses,
            all_addresses=money.all_addresses,
            sanitize_findings=s.findings,
            elapsed_ms=(time.perf_counter() - t0) * 1000,
            embedding=vec,
        )
