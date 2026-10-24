"""Layer 3/4 money rules: fixed checks on every money-moving tool call.

These rules do not depend on the risk score, so an attack that slips past
scoring still cannot pay a new or untrusted address.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from ..engine.money import extract_addresses, normalize_address

RECIPIENT_KEYS = ("to", "recipient", "address", "destination", "spender", "payee", "wallet")
AMOUNT_KEYS = ("amount", "value", "amount_eth", "qty", "quantity")


@dataclass
class Check:
    name: str
    passed: bool
    detail: str = ""

    def as_dict(self) -> dict:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


@dataclass
class PolicyResult:
    allowed: bool
    code: str  # machine-readable reason
    reason: str
    checks: list[Check] = field(default_factory=list)
    recipient: str | None = None
    amount: float | None = None
    attacker_address: bool = False


def _find_recipient(args: dict) -> str | None:
    for key in RECIPIENT_KEYS:
        if args.get(key):
            return normalize_address(str(args[key]))
    # fall back to any address-looking value anywhere in the arguments
    for value in args.values():
        if isinstance(value, str):
            found = extract_addresses(value)
            if found:
                return found[0]
    return None


def _find_amount(args: dict) -> float | None:
    for key in AMOUNT_KEYS:
        if key in args:
            try:
                return float(args[key])
            except (TypeError, ValueError):
                return None
    return None


def today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class TransactionPolicy:
    def __init__(self, settings, ledger, allowlist_provider):
        self.settings = settings
        self.ledger = ledger
        self.allowlist = allowlist_provider  # callable -> dict[address, label]

    def check(self, tool: str, args: dict) -> PolicyResult:
        checks: list[Check] = []
        recipient = _find_recipient(args or {})
        amount = _find_amount(args or {})
        allow = self.allowlist()

        if recipient is None:
            checks.append(Check("recipient present", False, "no recipient address in the tool arguments"))
            return PolicyResult(False, "NO_RECIPIENT", "Blocked: the payment has no recipient address.", checks)
        checks.append(Check("recipient present", True, recipient))

        if self.ledger.is_tainted(recipient) and recipient not in allow:
            checks.append(Check("address not from untrusted source", False,
                                "this address first appeared in an untrusted message"))
            return PolicyResult(False, "TAINTED_ADDRESS",
                                f"Blocked: {recipient} first appeared in an untrusted source and was never approved.",
                                checks, recipient, amount, attacker_address=True)
        checks.append(Check("address not from untrusted source", True))

        if recipient not in allow:
            checks.append(Check("address on allowlist", False, "not on the allowlist"))
            return PolicyResult(False, "NOT_ALLOWLISTED", f"Blocked: {recipient} is not on the allowlist.",
                                checks, recipient, amount)
        checks.append(Check("address on allowlist", True, allow[recipient]))

        if amount is None or amount <= 0:
            checks.append(Check("valid amount", False, "missing or non-positive amount"))
            return PolicyResult(False, "BAD_AMOUNT", "Blocked: the amount is missing or invalid.", checks, recipient, amount)
        checks.append(Check("valid amount", True, f"{amount} {self.settings.currency}"))

        if amount > self.settings.per_transaction_limit:
            checks.append(Check("per-transaction limit", False,
                                f"{amount} > {self.settings.per_transaction_limit} {self.settings.currency}"))
            return PolicyResult(False, "OVER_TX_LIMIT",
                                f"Blocked: {amount} {self.settings.currency} is above the per-transaction limit.",
                                checks, recipient, amount)
        checks.append(Check("per-transaction limit", True))

        spent = self.ledger.spent_today(today())
        if spent + amount > self.settings.per_day_limit:
            checks.append(Check("daily limit", False,
                                f"{spent} already spent today; limit {self.settings.per_day_limit}"))
            return PolicyResult(False, "OVER_DAY_LIMIT", "Blocked: this payment would exceed today's spending limit.",
                                checks, recipient, amount)
        checks.append(Check("daily limit", True, f"{spent + amount} of {self.settings.per_day_limit}"))

        return PolicyResult(True, "OK", "Allowed by all money rules.", checks, recipient, amount)
