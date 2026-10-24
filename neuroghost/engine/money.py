"""Money detail check (A in the score) and wallet-address helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Full EVM addresses, plus shortened forms like "0xDeadBeef..." that often appear in messages.
EVM_ADDRESS_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
EVM_PARTIAL_RE = re.compile(r"\b0x[a-fA-F0-9]{6,39}\b")
ENS_RE = re.compile(r"\b[a-z0-9-]{3,}\.eth\b", re.IGNORECASE)


def normalize_address(addr: str) -> str:
    return (addr or "").strip().lower()


def extract_addresses(text: str) -> list[str]:
    found: list[str] = []
    for m in EVM_ADDRESS_RE.finditer(text):
        found.append(normalize_address(m.group(0)))
    for m in EVM_PARTIAL_RE.finditer(text):
        a = normalize_address(m.group(0))
        if not any(full.startswith(a) for full in found):
            found.append(a)
    for m in ENS_RE.finditer(text):
        found.append(normalize_address(m.group(0)))
    # keep order, drop duplicates
    return list(dict.fromkeys(found))


@dataclass
class MoneyResult:
    hit: bool
    new_addresses: list[str] = field(default_factory=list)
    all_addresses: list[str] = field(default_factory=list)


def is_known(addr: str, allowlist: dict[str, str]) -> bool:
    a = normalize_address(addr)
    if a in allowlist:
        return True
    # a shortened address counts as known only if it is a prefix of an allowlisted one
    return len(a) >= 8 and any(full.startswith(a) for full in allowlist)


def money_check(text: str, allowlist: dict[str, str]) -> MoneyResult:
    addrs = extract_addresses(text)
    new = [a for a in addrs if not is_known(a, allowlist)]
    return MoneyResult(hit=bool(new), new_addresses=new, all_addresses=addrs)
