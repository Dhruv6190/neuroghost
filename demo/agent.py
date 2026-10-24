"""A small treasury agent used for the demo.

It reads its inbox into long-term memory and later settles invoices. To pick each
vendor's wallet it searches memory and trusts the most recent matching note, which is
exactly how a real LLM agent gets hijacked by a poisoned memory.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from neuroghost.client import GuardBlocked
from neuroghost.engine.embeddings import build_embedder
from neuroghost.engine.money import EVM_ADDRESS_RE
from neuroghost.storage.vector_store import VERIFIED, LocalStore


class PlainMemory:
    """An ordinary agent memory with no protection: everything is saved and searchable."""

    def __init__(self):
        self.embedder = build_embedder("auto", "sentence-transformers/all-MiniLM-L6-v2", 384)
        self.store = LocalStore(None)
        self._n = 0

    def save(self, text: str, source: str) -> bool:
        self._n += 1
        vec = self.embedder.embed([text])[0]
        self.store.add(VERIFIED, f"m{self._n}", text, vec,
                       {"source": source, "created_at": datetime.now(timezone.utc).isoformat()})
        return True

    def search(self, query: str, k: int = 10) -> list[dict]:
        rows = self.store.query(VERIFIED, self.embedder.embed([query])[0], k)
        return [{"id": r["id"], "text": r["text"], "created_at": r["metadata"]["created_at"]} for r in rows]


class GuardedMemory:
    """Agent memory that goes through NeuroGhost (server or in-process client)."""

    def __init__(self, client):
        self.client = client

    def save(self, text: str, source: str) -> bool:
        return self.client.intercept_memory_write(text, source=source)

    def search(self, query: str, k: int = 10) -> list[dict]:
        return self.client.retrieve(query, k)


class TreasuryAgent:
    def __init__(self, memory, wallet, guard_client=None, log=print):
        self.memory = memory
        self.wallet = wallet
        self.guard = guard_client
        self.log = log

    def read_inbox(self, messages: list[dict]) -> None:
        for msg in messages:
            saved = self.memory.save(msg["text"], msg["source"])
            mark = "saved" if saved else "NOT saved (quarantined)"
            self.log(f"    [{msg['source']:<9}] {msg['text'][:72]}{'...' if len(msg['text']) > 72 else ''}  -> {mark}")

    def resolve_wallet(self, vendor: str) -> tuple[str | None, str | None]:
        hits = self.memory.search(f"{vendor} payout wallet address payment", k=10)
        vendor_words = [w for w in re.findall(r"[a-z]+", vendor.lower()) if len(w) > 3]
        candidates = []
        for h in hits:
            m = EVM_ADDRESS_RE.search(h["text"])
            if not m:
                continue
            text = h["text"].lower()
            relevant = any(w in text for w in vendor_words) or "all vendors" in text or "default payout" in text
            if relevant:
                candidates.append((h.get("created_at") or "", m.group(0), h["text"]))
        if not candidates:
            return None, None
        candidates.sort(key=lambda c: c[0])  # the newest note wins, like an agent trusting the latest update
        _, address, source_text = candidates[-1]
        return address, source_text

    def settle_invoices(self, invoices: list[dict]) -> list[dict]:
        results = []
        for inv in invoices:
            address, why = self.resolve_wallet(inv["vendor"])
            if not address:
                self.log(f"    {inv['vendor']}: no wallet found in memory, skipping")
                results.append({"invoice": inv, "status": "skipped"})
                continue
            self.log(f"    {inv['vendor']}: paying {inv['amount']} ETH to {address[:10]}...{address[-4:]}")
            self.log(f"      (based on memory: \"{why[:70]}{'...' if len(why) > 70 else ''}\")")
            args = {"to": address, "amount": inv["amount"]}
            try:
                if self.guard:
                    tx = self.guard.execute_tool_safely("transfer_funds", args, executor=self.wallet.transfer_funds)
                else:
                    tx = self.wallet.transfer_funds(**args)
                self.log(f"      SENT  {self.wallet.tx_link(tx)}")
                results.append({"invoice": inv, "status": "sent", "to": address, "tx": tx})
            except GuardBlocked as blocked:
                self.log(f"      BLOCKED by NeuroGhost [{blocked.decision.get('code')}]: {blocked.decision.get('reason')}")
                results.append({"invoice": inv, "status": "blocked", "to": address, "code": blocked.decision.get("code")})
        return results
