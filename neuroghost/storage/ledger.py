"""SQLite ledger: the full history of every memory, decision, event and transaction check."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS memories (
    id TEXT PRIMARY KEY,
    text TEXT,
    source TEXT NOT NULL,
    state TEXT NOT NULL,              -- COMMITTED | QUARANTINED | APPROVED | PURGED
    risk REAL NOT NULL,
    h REAL, d REAL, a REAL,
    flags TEXT, categories TEXT, addresses TEXT,
    content_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    decided_by TEXT
);
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    type TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tainted_addresses (
    address TEXT PRIMARY KEY,
    first_seen_memory TEXT,
    source TEXT,
    first_seen_at TEXT
);
CREATE TABLE IF NOT EXISTS allowlist (
    address TEXT PRIMARY KEY,
    label TEXT,
    added_by TEXT,
    added_at TEXT
);
CREATE TABLE IF NOT EXISTS spending (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    day TEXT NOT NULL,
    tool TEXT NOT NULL,
    recipient TEXT,
    amount REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    action TEXT NOT NULL,
    memory_id TEXT,
    content_hash TEXT,
    actor TEXT,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    chain_tx TEXT
);
CREATE TABLE IF NOT EXISTS canaries (
    token TEXT PRIMARY KEY,
    memory_id TEXT,
    created_at TEXT
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Ledger:
    def __init__(self, path: Path | None):
        self._lock = threading.RLock()
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(str(path), check_same_thread=False)
            self.conn.execute("PRAGMA journal_mode=WAL")
        else:
            self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    # ---- generic helpers
    def _exec(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur

    def _all(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    # ---- memories
    def add_memory(self, mem: dict[str, Any]) -> None:
        ts = now_iso()
        self._exec(
            "INSERT INTO memories (id,text,source,state,risk,h,d,a,flags,categories,addresses,content_hash,created_at,updated_at,decided_by)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (mem["id"], mem["text"], mem["source"], mem["state"], mem["risk"], mem["h"], mem["d"], mem["a"],
             json.dumps(mem.get("flags", [])), json.dumps(mem.get("categories", [])),
             json.dumps(mem.get("addresses", [])), mem["content_hash"], mem.get("created_at", ts), ts,
             mem.get("decided_by", "neuroghost")),
        )

    def set_state(self, memory_id: str, state: str, actor: str, wipe_text: bool = False) -> None:
        if wipe_text:
            self._exec("UPDATE memories SET state=?, decided_by=?, updated_at=?, text=NULL WHERE id=?",
                       (state, actor, now_iso(), memory_id))
        else:
            self._exec("UPDATE memories SET state=?, decided_by=?, updated_at=? WHERE id=?",
                       (state, actor, now_iso(), memory_id))

    def get_memory(self, memory_id: str) -> dict | None:
        rows = self._all("SELECT * FROM memories WHERE id=?", (memory_id,))
        return self._decode(rows[0]) if rows else None

    def list_memories(self, state: str | None = None, limit: int = 100) -> list[dict]:
        if state:
            rows = self._all("SELECT * FROM memories WHERE state=? ORDER BY created_at DESC LIMIT ?", (state, limit))
        else:
            rows = self._all("SELECT * FROM memories ORDER BY created_at DESC LIMIT ?", (limit,))
        return [self._decode(r) for r in rows]

    @staticmethod
    def _decode(row: dict) -> dict:
        for key in ("flags", "categories", "addresses"):
            row[key] = json.loads(row[key]) if row.get(key) else []
        return row

    # ---- events
    def add_event(self, etype: str, payload: dict) -> dict:
        ts = now_iso()
        cur = self._exec("INSERT INTO events (ts,type,payload) VALUES (?,?,?)", (ts, etype, json.dumps(payload)))
        return {"seq": cur.lastrowid, "ts": ts, "type": etype, "payload": payload}

    def recent_events(self, limit: int = 50) -> list[dict]:
        rows = self._all("SELECT * FROM events ORDER BY seq DESC LIMIT ?", (limit,))
        for r in rows:
            r["payload"] = json.loads(r["payload"])
        return rows

    # ---- addresses
    def taint(self, address: str, memory_id: str, source: str) -> None:
        self._exec("INSERT OR IGNORE INTO tainted_addresses (address,first_seen_memory,source,first_seen_at) VALUES (?,?,?,?)",
                   (address, memory_id, source, now_iso()))

    def tainted(self) -> list[dict]:
        return self._all("SELECT * FROM tainted_addresses ORDER BY first_seen_at DESC")

    def is_tainted(self, address: str) -> bool:
        address = address.lower()
        if self._all("SELECT 1 FROM tainted_addresses WHERE address=?", (address,)):
            return True
        # a shortened tainted address (e.g. "0xdeadbeef") matches the full one it starts
        for row in self._all("SELECT address FROM tainted_addresses WHERE length(address) < 42"):
            if len(row["address"]) >= 8 and address.startswith(row["address"]):
                return True
        return False

    def untaint(self, address: str) -> None:
        self._exec("DELETE FROM tainted_addresses WHERE address=?", (address.lower(),))

    def allowlist_add(self, address: str, label: str, actor: str) -> None:
        self._exec("INSERT OR REPLACE INTO allowlist (address,label,added_by,added_at) VALUES (?,?,?,?)",
                   (address.lower(), label, actor, now_iso()))

    def allowlist_remove(self, address: str) -> None:
        self._exec("DELETE FROM allowlist WHERE address=?", (address.lower(),))

    def allowlist(self) -> dict[str, str]:
        return {r["address"]: r["label"] for r in self._all("SELECT address,label FROM allowlist")}

    # ---- spending
    def spent_today(self, day: str) -> float:
        rows = self._all("SELECT COALESCE(SUM(amount),0) AS s FROM spending WHERE day=?", (day,))
        return float(rows[0]["s"])

    def record_spend(self, day: str, tool: str, recipient: str, amount: float) -> None:
        self._exec("INSERT INTO spending (ts,day,tool,recipient,amount) VALUES (?,?,?,?,?)",
                   (now_iso(), day, tool, recipient, amount))

    # ---- audit chain
    def last_audit_hash(self) -> str:
        rows = self._all("SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1")
        return rows[0]["entry_hash"] if rows else "0" * 64

    def add_audit(self, entry: dict) -> int:
        cur = self._exec(
            "INSERT INTO audit_log (ts,action,memory_id,content_hash,actor,prev_hash,entry_hash,chain_tx) VALUES (?,?,?,?,?,?,?,?)",
            (entry["ts"], entry["action"], entry.get("memory_id"), entry.get("content_hash"), entry.get("actor"),
             entry["prev_hash"], entry["entry_hash"], entry.get("chain_tx")),
        )
        return int(cur.lastrowid)

    def set_audit_chain_tx(self, seq: int, tx: str) -> None:
        self._exec("UPDATE audit_log SET chain_tx=? WHERE seq=?", (tx, seq))

    def audit_entries(self, limit: int = 1000) -> list[dict]:
        return self._all("SELECT * FROM audit_log ORDER BY seq ASC LIMIT ?", (limit,))

    # ---- canaries
    def add_canary(self, token: str, memory_id: str) -> None:
        self._exec("INSERT OR IGNORE INTO canaries (token,memory_id,created_at) VALUES (?,?,?)", (token, memory_id, now_iso()))

    def canaries(self) -> list[str]:
        return [r["token"] for r in self._all("SELECT token FROM canaries")]
