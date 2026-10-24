"""NeuroGhost core: one object that runs all four layers.

    ingest()      Layer 1 + 2: clean, score, then commit to verified memory or quarantine
    retrieve()    agent's only way to read memory; verified store only, signatures checked
    check_tool()  Layer 3 + 4: tool lock, money rules, canary watch
    filter_egress() Layer 4: scrub secrets from outgoing text
    approve() / purge() / allowlist_add() / reset_session(): human decisions
"""

from __future__ import annotations

import json
import logging
import secrets
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from .chain.audit import AuditLog
from .config import Settings, load_settings
from .engine.crypto import Signer, load_or_create_secret, sha256_hex
from .engine.drift import DriftProfile
from .engine.embeddings import build_embedder
from .engine.money import normalize_address
from .engine.scorer import RiskScorer
from .guard.egress import EgressGuard
from .guard.policy import TransactionPolicy, today
from .storage.ledger import Ledger, now_iso
from .storage.vector_store import QUARANTINE, VERIFIED, build_store

log = logging.getLogger("neuroghost")


@dataclass
class IngestResult:
    status: str  # "SUCCESS" | "BLOCKED" | "REJECTED"
    action: str  # "COMMIT" | "ISOLATE" | "NONE"
    memory_id: str | None
    report: dict = field(default_factory=dict)

    @property
    def committed(self) -> bool:
        return self.action == "COMMIT"

    def as_dict(self) -> dict:
        return {"status": self.status, "action": self.action, "memory_id": self.memory_id, "report": self.report}


@dataclass
class ToolDecision:
    allowed: bool
    http_status: int
    code: str
    reason: str
    tool: str
    checks: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"allowed": self.allowed, "http_status": self.http_status, "code": self.code,
                "reason": self.reason, "tool": self.tool, "checks": self.checks}


class NeuroGhost:
    def __init__(self, settings: Settings | None = None, *, persist: bool = True):
        self.settings = settings or load_settings()
        data_dir = self.settings.data_dir if persist else None
        if data_dir:
            data_dir.mkdir(parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self._listeners: list[Callable[[dict], None]] = []
        self._halted: dict | None = None

        self.embedder = build_embedder(self.settings.embedding_backend, self.settings.embedding_model,
                                       self.settings.embedding_dimensions)
        self.profile = DriftProfile(self.embedder, self.settings.baseline_persona)
        self.scorer = RiskScorer(self.settings, self.embedder, self.profile)
        self.store = build_store(self.settings.vector_backend, data_dir)
        self.ledger = Ledger(data_dir / "ledger.db" if data_dir else None)
        self.signer = Signer(load_or_create_secret(data_dir) if data_dir else secrets.token_bytes(32))
        self.audit = AuditLog(self.ledger, self.settings.chain, on_anchored=lambda e: self._emit("AUDIT_ANCHORED", e))
        self.policy = TransactionPolicy(self.settings, self.ledger, self.allowlist)
        self.egress = EgressGuard()

        # Re-learn the drift profile from memories that were verified in earlier runs.
        for mid in self.store.ids(VERIFIED):
            row = self.store.get(VERIFIED, mid)
            if row is not None:
                self.profile.absorb(row["embedding"])

    # ------------------------------------------------------------------ events
    def subscribe(self, callback: Callable[[dict], None]) -> None:
        self._listeners.append(callback)

    def _emit(self, etype: str, payload: dict) -> dict:
        event = self.ledger.add_event(etype, payload)
        for cb in list(self._listeners):
            try:
                cb(event)
            except Exception as exc:  # a broken listener must never break the guard
                log.debug("listener error: %s", exc)
        return event

    # ------------------------------------------------------------------ helpers
    def allowlist(self) -> dict[str, str]:
        merged = dict(self.settings.allowlist)
        merged.update(self.ledger.allowlist())
        return merged

    def quarantine_count(self) -> int:
        return self.store.count(QUARANTINE)

    def is_locked(self) -> bool:
        return self._halted is not None or self.quarantine_count() > 0

    def _canary_set(self) -> set[str]:
        return set(self.ledger.canaries())

    def _halt(self, reason: str, detail: dict) -> None:
        with self._lock:
            if self._halted is None:
                self._halted = {"reason": reason, "at": now_iso(), **detail}
                self.audit.record("SESSION_HALTED", detail.get("memory_id"), None, "neuroghost")
                self._emit("SESSION_HALTED", self._halted)

    # ------------------------------------------------------------------ write path
    def ingest(self, raw_text: str, source: str = "external", metadata: dict | None = None) -> IngestResult:
        if not raw_text or not str(raw_text).strip():
            return IngestResult("REJECTED", "NONE", None, {"error": "empty text"})
        source = (source or "external").strip()
        with self._lock:
            report = self.scorer.score(raw_text, source, extra_known=self.ledger.allowlist())
            if not report.clean_text:
                return IngestResult("REJECTED", "NONE", None, {"error": "text is empty after cleaning",
                                                                 "sanitizer": report.sanitize_findings})
            created_at = now_iso()
            content_hash = sha256_hex(report.clean_text)
            untrusted = source not in self.settings.trusted_sources
            meta_common = {"source": source, "created_at": created_at, "risk": round(report.risk, 4),
                           "content_hash": content_hash, **{f"meta_{k}": str(v) for k, v in (metadata or {}).items()}}

            if report.decision == "COMMIT":
                memory_id = "mem_" + secrets.token_hex(6)
                signature = self.signer.sign(memory_id, report.clean_text, source, created_at)
                self.store.add(VERIFIED, memory_id, report.clean_text, report.embedding,
                               {**meta_common, "signature": signature})
                state = "COMMITTED"
            else:
                memory_id = "q_" + secrets.token_hex(6)
                canary = "ng-canary-" + secrets.token_hex(8)
                # The canary rides along with the quarantined text. If it ever shows up in a tool
                # call or outgoing message, quarantine isolation has been breached.
                self.store.add(QUARANTINE, memory_id, f"{report.clean_text}\n[{canary}]", report.embedding,
                               {**meta_common, "canary": canary})
                self.ledger.add_canary(canary, memory_id)
                state = "QUARANTINED"

            if untrusted:
                for addr in report.new_addresses:
                    self.ledger.taint(addr, memory_id, source)

            self.ledger.add_memory({
                "id": memory_id, "text": report.clean_text, "source": source, "state": state,
                "risk": report.risk, "h": report.directive, "d": report.drift, "a": report.money,
                "flags": report.flags, "categories": report.categories, "addresses": report.all_addresses,
                "content_hash": content_hash, "created_at": created_at,
            })

            rep = {"id": memory_id, "state_hash": content_hash[:16], **report.as_dict()}
            if state == "COMMITTED":
                self.profile.absorb(report.embedding)
                self._emit("MEMORY_COMMITTED", {"id": memory_id, "source": source, "risk_score": rep["risk_score"],
                                                "preview": report.clean_text[:140]})
                return IngestResult("SUCCESS", "COMMIT", memory_id, rep)

            self.audit.record("QUARANTINED", memory_id, content_hash, "neuroghost")
            self._emit("THREAT_QUARANTINED", {"id": memory_id, "source": source, "risk_score": rep["risk_score"],
                                              "components": rep["components"], "flags": report.flags,
                                              "preview": report.clean_text[:140]})
            self._emit("TOOLS_LOCKED", {"quarantine_count": self.quarantine_count()})
            return IngestResult("BLOCKED", "ISOLATE", memory_id, rep)

    # ------------------------------------------------------------------ read path
    def retrieve(self, query: str, k: int = 5) -> list[dict]:
        """The agent's only memory read. Searches verified memory and drops anything without a valid signature."""
        vec = self.embedder.embed([query or " "])[0]
        results = []
        for row in self.store.query(VERIFIED, vec, k):
            meta = row["metadata"]
            ok = self.signer.verify(meta.get("signature"), row["id"], row["text"], meta.get("source", ""),
                                    meta.get("created_at", ""))
            if not ok:
                self._emit("TAMPER_DETECTED", {"id": row["id"], "preview": row["text"][:140],
                                               "detail": "memory has no valid NeuroGhost signature; dropped"})
                continue
            results.append({"id": row["id"], "text": row["text"], "source": meta.get("source"),
                            "created_at": meta.get("created_at"), "similarity": round(row["similarity"], 4)})
        return results

    # ------------------------------------------------------------------ human decisions
    def list_quarantine(self) -> list[dict]:
        live = set(self.store.ids(QUARANTINE))
        return [m for m in self.ledger.list_memories("QUARANTINED", limit=500) if m["id"] in live]

    def approve(self, memory_id: str, actor: str = "admin") -> dict:
        with self._lock:
            row = self.store.get(QUARANTINE, memory_id)
            mem = self.ledger.get_memory(memory_id)
            if row is None or mem is None:
                raise KeyError(memory_id)
            text, source, created_at = mem["text"], mem["source"], mem["created_at"]
            signature = self.signer.sign(memory_id, text, source, created_at)
            self.store.delete(QUARANTINE, memory_id)
            self.store.add(VERIFIED, memory_id, text, row["embedding"],
                           {"source": source, "created_at": created_at, "risk": mem["risk"],
                            "content_hash": mem["content_hash"], "signature": signature, "approved_by": actor})
            self.ledger.set_state(memory_id, "APPROVED", actor)
            self.profile.absorb(row["embedding"])
            self.audit.record("APPROVED", memory_id, mem["content_hash"], actor)
            self._emit("MEMORY_APPROVED", {"id": memory_id, "by": actor,
                                           "note": "addresses in this memory stay blocked until added to the allowlist"})
            self._emit_lock_state()
            return {"id": memory_id, "state": "APPROVED"}

    def purge(self, memory_id: str, actor: str = "admin") -> dict:
        with self._lock:
            mem = self.ledger.get_memory(memory_id)
            if not self.store.delete(QUARANTINE, memory_id) or mem is None:
                raise KeyError(memory_id)
            self.ledger.set_state(memory_id, "PURGED", actor, wipe_text=True)
            self.audit.record("PURGED", memory_id, mem["content_hash"], actor)
            self._emit("MEMORY_PURGED", {"id": memory_id, "by": actor})
            self._emit_lock_state()
            return {"id": memory_id, "state": "PURGED"}

    def _emit_lock_state(self) -> None:
        if self.is_locked():
            self._emit("TOOLS_LOCKED", {"quarantine_count": self.quarantine_count(), "halted": self._halted})
        else:
            self._emit("TOOLS_UNLOCKED", {"quarantine_count": 0})

    def allowlist_add(self, address: str, label: str, actor: str = "admin") -> None:
        addr = normalize_address(address)
        self.ledger.allowlist_add(addr, label, actor)
        self.ledger.untaint(addr)
        self._emit("ALLOWLIST_ADDED", {"address": addr, "label": label, "by": actor})

    def allowlist_remove(self, address: str, actor: str = "admin") -> None:
        addr = normalize_address(address)
        self.ledger.allowlist_remove(addr)
        self._emit("ALLOWLIST_REMOVED", {"address": addr, "by": actor})

    def reset_session(self, actor: str = "admin") -> None:
        with self._lock:
            self._halted = None
            self.audit.record("SESSION_RESET", None, None, actor)
            self._emit("SESSION_RESET", {"by": actor})
            self._emit_lock_state()

    # ------------------------------------------------------------------ action path
    def check_tool(self, tool: str, args: dict | None = None, *, reserve: bool = True) -> ToolDecision:
        """Call before running any tool. If allowed and `reserve` is true, money spent is counted
        toward the daily limit."""
        args = args or {}
        tool = (tool or "").strip()
        privileged = tool in self.settings.privileged_tools
        is_money = tool in self.settings.money_tools
        checks: list[dict] = []

        # Canary in the arguments means quarantined text leaked into the action path: halt everything.
        canaries = self.egress.scan(json.dumps(args, default=str), self._canary_set()).canaries
        if canaries:
            self._halt("canary token found in tool arguments", {"tool": tool, "canary": canaries[0]})
            return self._deny(tool, "CANARY_TRIPPED", "Session halted: quarantined content reached a tool call.", checks)

        if self._halted is not None and privileged:
            return self._deny(tool, "SESSION_HALTED", f"Session halted: {self._halted['reason']}. An admin must reset it.", checks)

        q = self.quarantine_count()
        if privileged:
            checks.append({"name": "quarantine empty", "passed": q == 0, "detail": f"{q} waiting for review"})
            if q > 0:
                return self._deny(tool, "TOOLS_LOCKED",
                                  f"Tool '{tool}' is locked: {q} suspicious {'memory is' if q == 1 else 'memories are'} waiting for review in quarantine.",
                                  checks)

        if is_money:
            with self._lock:
                result = self.policy.check(tool, args)
                checks.extend(c.as_dict() for c in result.checks)
                if not result.allowed:
                    if result.attacker_address:
                        self.audit.record("TX_BLOCKED", None, sha256_hex(result.recipient or ""), "neuroghost")
                        self._emit("ATTACKER_PAYMENT_BLOCKED", {"tool": tool, "recipient": result.recipient,
                                                                "amount": result.amount})
                    return self._deny(tool, result.code, result.reason, checks)
                if reserve:
                    self.ledger.record_spend(today(), tool, result.recipient or "", float(result.amount or 0))

        decision = ToolDecision(True, 200, "OK", "Allowed.", tool, checks)
        self._emit("TOOL_ALLOWED", {"tool": tool, "args": self.egress.scan(json.dumps(args, default=str)).text})
        return decision

    def _deny(self, tool: str, code: str, reason: str, checks: list[dict]) -> ToolDecision:
        self._emit("TOOL_BLOCKED", {"tool": tool, "code": code, "reason": reason})
        return ToolDecision(False, 403, code, reason, tool, checks)

    def filter_egress(self, text: str) -> dict:
        res = self.egress.scan(text, self._canary_set())
        if res.canaries:
            self._halt("canary token found in outgoing text", {"canary": res.canaries[0]})
            res.text = res.text.replace(res.canaries[0], "[REDACTED_CANARY]")
        if res.redactions:
            self._emit("EGRESS_REDACTED", {"kinds": sorted(set(res.redactions)), "count": len(res.redactions)})
        return {"text": res.text, "redactions": res.redactions, "canary_tripped": bool(res.canaries)}

    def register_secret(self, secret: str) -> None:
        self.egress.register_secret(secret)

    # ------------------------------------------------------------------ status
    def status(self) -> dict[str, Any]:
        return {
            "locked": self.is_locked(),
            "halted": self._halted,
            "quarantine_count": self.quarantine_count(),
            "verified_count": self.store.count(VERIFIED),
            "tainted_addresses": self.ledger.tainted(),
            "allowlist": self.allowlist(),
            "spent_today": self.ledger.spent_today(today()),
            "limits": {"per_transaction": self.settings.per_transaction_limit,
                       "per_day": self.settings.per_day_limit, "currency": self.settings.currency},
            "backends": {"embedding": self.embedder.name, "vector_store": self.store.name},
            "chain": self.audit.chain_status,
            "threshold": self.settings.threshold,
            "weights": self.settings.weights,
        }
