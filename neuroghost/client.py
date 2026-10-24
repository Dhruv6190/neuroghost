"""Client SDK for agents.

    from neuroghost.client import NeuroGhostGuardClient
    guard = NeuroGhostGuardClient("http://127.0.0.1:8000")

    if guard.intercept_memory_write(email_text, source="email"):
        ...                                    # saved to verified memory
    facts = guard.retrieve("vendor payout wallet")
    result = guard.execute_tool_safely("transfer_funds", {"to": addr, "amount": 0.4}, executor=wallet.transfer)

Fail-closed: if the NeuroGhost server cannot be reached, memory writes are NOT saved
and privileged tools are NOT run.

`LocalGuardClient` offers the same interface around an in-process NeuroGhost object.
"""

from __future__ import annotations

from typing import Any, Callable

import requests


class GuardBlocked(PermissionError):
    def __init__(self, decision: dict):
        self.decision = decision
        super().__init__(decision.get("reason", "Blocked by NeuroGhost"))


class _GuardMixin:
    def check_tool(self, tool_name: str, arguments: dict | None = None) -> dict:  # pragma: no cover
        raise NotImplementedError

    def filter_egress(self, text: str) -> dict:  # pragma: no cover
        raise NotImplementedError

    def execute_tool_safely(self, tool_name: str, arguments: dict | None = None,
                            executor: Callable[..., Any] | None = None) -> Any:
        """Ask NeuroGhost first; run `executor(**arguments)` only if allowed. Raises GuardBlocked otherwise.
        Text results are passed through the exit check before being returned."""
        arguments = arguments or {}
        decision = self.check_tool(tool_name, arguments)
        if not decision.get("allowed"):
            raise GuardBlocked(decision)
        if executor is None:
            return decision
        result = executor(**arguments)
        if isinstance(result, str):
            return self.filter_egress(result)["text"]
        return result


class NeuroGhostGuardClient(_GuardMixin):
    def __init__(self, endpoint: str = "http://127.0.0.1:8000", timeout: float = 3.0, admin_token: str | None = None):
        self.endpoint = endpoint.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.admin_token = admin_token

    def _post(self, path: str, payload: dict) -> requests.Response:
        return self.session.post(self.endpoint + path, json=payload, timeout=self.timeout)

    def _admin_headers(self) -> dict:
        return {"X-NeuroGhost-Admin": self.admin_token} if self.admin_token else {}

    # write path
    def ingest(self, raw_text: str, source: str = "external", metadata: dict | None = None) -> dict:
        r = self._post("/api/v1/guard/memory/ingest", {"raw_text": raw_text, "source": source, "metadata": metadata})
        r.raise_for_status()
        return r.json()

    def intercept_memory_write(self, raw_text: str, source: str = "external", metadata: dict | None = None) -> bool:
        try:
            return self.ingest(raw_text, source, metadata).get("action") == "COMMIT"
        except requests.RequestException:
            return False  # fail closed: unverified data is never saved

    # read path
    def retrieve(self, query: str, k: int = 5) -> list[dict]:
        try:
            r = self._post("/api/v1/memory/query", {"query": query, "k": k})
            r.raise_for_status()
            return r.json()["results"]
        except requests.RequestException:
            return []

    # action path
    def check_tool(self, tool_name: str, arguments: dict | None = None) -> dict:
        try:
            r = self._post("/api/v1/guard/tool/execute", {"tool_name": tool_name, "arguments": arguments or {}})
            data = r.json()
            data["allowed"] = r.status_code == 200 and data.get("allowed", False)
            return data
        except (requests.RequestException, ValueError) as exc:
            return {"allowed": False, "http_status": 503, "code": "GUARD_UNREACHABLE",
                    "reason": f"NeuroGhost unreachable, failing closed: {exc}", "tool": tool_name, "checks": []}

    def filter_egress(self, text: str) -> dict:
        try:
            r = self._post("/api/v1/guard/egress", {"text": text})
            r.raise_for_status()
            return r.json()
        except requests.RequestException:
            return {"text": "[WITHHELD: NeuroGhost unreachable]", "redactions": ["guard_unreachable"],
                    "canary_tripped": False}

    # status and human actions
    def status(self) -> dict:
        return self.session.get(self.endpoint + "/api/v1/status", timeout=self.timeout).json()

    def quarantine(self) -> list[dict]:
        return self.session.get(self.endpoint + "/api/v1/guard/quarantine", timeout=self.timeout).json()["items"]

    def approve(self, memory_id: str) -> dict:
        r = self.session.post(f"{self.endpoint}/api/v1/guard/quarantine/{memory_id}/approve",
                              headers=self._admin_headers(), timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def purge(self, memory_id: str) -> dict:
        r = self.session.delete(f"{self.endpoint}/api/v1/guard/quarantine/{memory_id}",
                                headers=self._admin_headers(), timeout=self.timeout)
        r.raise_for_status()
        return r.json()


class LocalGuardClient(_GuardMixin):
    """Same interface as NeuroGhostGuardClient, but calls a NeuroGhost object directly (no server)."""

    def __init__(self, guard):
        self.guard = guard

    def ingest(self, raw_text: str, source: str = "external", metadata: dict | None = None) -> dict:
        return self.guard.ingest(raw_text, source, metadata).as_dict()

    def intercept_memory_write(self, raw_text: str, source: str = "external", metadata: dict | None = None) -> bool:
        return self.guard.ingest(raw_text, source, metadata).committed

    def retrieve(self, query: str, k: int = 5) -> list[dict]:
        return self.guard.retrieve(query, k)

    def check_tool(self, tool_name: str, arguments: dict | None = None) -> dict:
        return self.guard.check_tool(tool_name, arguments or {}).as_dict()

    def filter_egress(self, text: str) -> dict:
        return self.guard.filter_egress(text)

    def status(self) -> dict:
        return self.guard.status()

    def quarantine(self) -> list[dict]:
        return self.guard.list_quarantine()

    def approve(self, memory_id: str) -> dict:
        return self.guard.approve(memory_id, "admin")

    def purge(self, memory_id: str) -> dict:
        return self.guard.purge(memory_id, "admin")
