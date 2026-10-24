"""Audit log: a local hash chain of every decision, optionally anchored on an EVM testnet.

Every entry stores the SHA-256 of the previous entry, so editing or deleting any
past entry breaks the chain. When chain anchoring is enabled, the entry hash is
also written to the NeuroGhostAuditLog contract (contracts/NeuroGhostAuditLog.sol).
Only fingerprints go on-chain, never memory text.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
from typing import Callable

from ..storage.ledger import Ledger, now_iso

log = logging.getLogger("neuroghost.audit")

ACTION_CODES = {"QUARANTINED": 1, "APPROVED": 2, "PURGED": 3, "TX_BLOCKED": 4, "SESSION_HALTED": 5, "SESSION_RESET": 6}

AUDIT_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "entryHash", "type": "bytes32"},
            {"internalType": "bytes32", "name": "contentHash", "type": "bytes32"},
            {"internalType": "uint8", "name": "action", "type": "uint8"},
        ],
        "name": "record",
        "outputs": [{"internalType": "uint256", "name": "index", "type": "uint256"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {"inputs": [], "name": "count", "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
     "stateMutability": "view", "type": "function"},
]


def entry_digest(prev_hash: str, ts: str, action: str, memory_id: str | None, content_hash: str | None, actor: str | None) -> str:
    material = "|".join([prev_hash, ts, action, memory_id or "", content_hash or "", actor or ""])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class ChainAnchor:
    """Writes entry hashes to the audit contract. Disabled unless configured and web3 is installed."""

    def __init__(self, cfg: dict):
        self.enabled = False
        self.reason = "disabled in settings"
        if not cfg.get("enabled"):
            return
        rpc = os.environ.get(cfg.get("rpc_url_env", "NEUROGHOST_RPC_URL"), "")
        key = os.environ.get(cfg.get("private_key_env", "NEUROGHOST_CHAIN_KEY"), "")
        address = cfg.get("contract_address", "")
        if not (rpc and key and address):
            self.reason = "missing RPC URL, private key env var, or contract address"
            log.warning("Chain anchoring requested but %s", self.reason)
            return
        try:
            from web3 import Web3
        except ImportError:
            self.reason = "web3 is not installed (pip install web3)"
            log.warning("Chain anchoring requested but %s", self.reason)
            return
        self.w3 = Web3(Web3.HTTPProvider(rpc))
        self.account = self.w3.eth.account.from_key(key)
        self.contract = self.w3.eth.contract(address=Web3.to_checksum_address(address), abi=AUDIT_ABI)
        self.chain_id = int(cfg.get("chain_id", 11155111))
        self._lock = threading.Lock()
        self.enabled = True
        self.reason = "enabled"

    def anchor(self, entry_hash: str, content_hash: str | None, action: str) -> str | None:
        if not self.enabled:
            return None
        with self._lock:  # one transaction at a time keeps nonces in order
            tx = self.contract.functions.record(
                bytes.fromhex(entry_hash), bytes.fromhex(content_hash or "0" * 64), ACTION_CODES.get(action, 0)
            ).build_transaction({
                "from": self.account.address,
                "nonce": self.w3.eth.get_transaction_count(self.account.address, "pending"),
                "chainId": self.chain_id,
            })
            signed = self.account.sign_transaction(tx)
            raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction")
            tx_hash = self.w3.eth.send_raw_transaction(raw)
            return tx_hash.hex() if hasattr(tx_hash, "hex") else str(tx_hash)


class AuditLog:
    def __init__(self, ledger: Ledger, chain_cfg: dict, on_anchored: Callable[[dict], None] | None = None):
        self.ledger = ledger
        self.anchor = ChainAnchor(chain_cfg)
        self.on_anchored = on_anchored
        self._lock = threading.Lock()

    def record(self, action: str, memory_id: str | None, content_hash: str | None, actor: str) -> dict:
        with self._lock:
            prev = self.ledger.last_audit_hash()
            ts = now_iso()
            digest = entry_digest(prev, ts, action, memory_id, content_hash, actor)
            entry = {"ts": ts, "action": action, "memory_id": memory_id, "content_hash": content_hash,
                     "actor": actor, "prev_hash": prev, "entry_hash": digest}
            entry["seq"] = self.ledger.add_audit(entry)
        if self.anchor.enabled:
            threading.Thread(target=self._anchor_async, args=(entry,), daemon=True).start()
        return entry

    def _anchor_async(self, entry: dict) -> None:
        try:
            tx = self.anchor.anchor(entry["entry_hash"], entry.get("content_hash"), entry["action"])
            if tx:
                self.ledger.set_audit_chain_tx(entry["seq"], tx)
                if self.on_anchored:
                    self.on_anchored({**entry, "chain_tx": tx})
        except Exception as exc:
            log.error("On-chain anchoring failed for audit entry %s: %s", entry["seq"], exc)

    def verify(self) -> dict:
        """Recompute the whole chain. Returns {"ok": bool, "entries": n, "broken_at": seq|None}."""
        prev = "0" * 64
        entries = self.ledger.audit_entries(limit=10**9)
        for e in entries:
            expected = entry_digest(prev, e["ts"], e["action"], e["memory_id"], e["content_hash"], e["actor"])
            if e["prev_hash"] != prev or e["entry_hash"] != expected:
                return {"ok": False, "entries": len(entries), "broken_at": e["seq"]}
            prev = e["entry_hash"]
        return {"ok": True, "entries": len(entries), "broken_at": None}

    @property
    def chain_status(self) -> dict:
        return {"enabled": self.anchor.enabled, "reason": self.anchor.reason}
