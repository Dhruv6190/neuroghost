"""FastAPI server: the NeuroGhost firewall as a local HTTP service, plus the live dashboard.

Run:  neuroghost serve            (or)   uvicorn neuroghost.server:app --port 8000

Agent-facing routes (no token): ingest, query, tool/execute, egress, status.
Human-only routes need the admin token in the `X-NeuroGhost-Admin` header, so a
hijacked agent cannot approve its own poisoned memory or allowlist an attacker.
"""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from .core import NeuroGhost

log = logging.getLogger("neuroghost.server")
DASHBOARD = Path(__file__).resolve().parent / "dashboard" / "index.html"


class IngestIn(BaseModel):
    raw_text: str = Field(..., max_length=100_000)
    source: str = "external"
    metadata: dict[str, Any] | None = None


class QueryIn(BaseModel):
    query: str
    k: int = Field(5, ge=1, le=50)


class ToolIn(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class EgressIn(BaseModel):
    text: str


class AllowIn(BaseModel):
    address: str
    label: str = ""


class Hub:
    """Pushes guard events to every connected dashboard over WebSockets."""

    def __init__(self):
        self.clients: set[WebSocket] = set()
        self.loop: asyncio.AbstractEventLoop | None = None
        self.queue: asyncio.Queue | None = None

    def publish(self, event: dict) -> None:  # called from any thread
        if self.loop and self.queue:
            self.loop.call_soon_threadsafe(self.queue.put_nowait, event)

    async def pump(self) -> None:
        assert self.queue is not None
        while True:
            event = await self.queue.get()
            dead = []
            for ws in list(self.clients):
                try:
                    await ws.send_json(event)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self.clients.discard(ws)


def create_app(guard: NeuroGhost | None = None, admin_token: str | None = None) -> FastAPI:
    hub = Hub()
    token = admin_token or os.environ.get("NEUROGHOST_ADMIN_TOKEN") or secrets.token_urlsafe(18)
    state: dict[str, Any] = {"guard": guard}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if state["guard"] is None:
            state["guard"] = NeuroGhost()
        state["guard"].subscribe(hub.publish)
        hub.loop = asyncio.get_running_loop()
        hub.queue = asyncio.Queue()
        task = asyncio.create_task(hub.pump())
        if not (admin_token or os.environ.get("NEUROGHOST_ADMIN_TOKEN")):
            print(f"\n  NeuroGhost admin token: {token}\n  (paste it into the dashboard to approve or purge)\n", flush=True)
        yield
        task.cancel()

    app = FastAPI(title="NeuroGhost", version="0.1.0", lifespan=lifespan)

    def g() -> NeuroGhost:
        return state["guard"]

    def require_admin(x_neuroghost_admin: str | None = Header(default=None)) -> str:
        if not x_neuroghost_admin or not secrets.compare_digest(x_neuroghost_admin, token):
            raise HTTPException(status_code=401, detail="Admin token required for this action.")
        return "admin"

    # ---------------- dashboard
    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        return DASHBOARD.read_text(encoding="utf-8")

    @app.websocket("/ws")
    async def ws(websocket: WebSocket):
        await websocket.accept()
        hub.clients.add(websocket)
        try:
            await websocket.send_json({"type": "HELLO", "payload": g().status()})
            while True:
                await websocket.receive_text()  # keep-alive; dashboard sends pings
        except WebSocketDisconnect:
            pass
        finally:
            hub.clients.discard(websocket)

    # ---------------- agent-facing
    @app.post("/api/v1/guard/memory/ingest")
    def ingest(body: IngestIn):
        return g().ingest(body.raw_text, body.source, body.metadata).as_dict()

    @app.post("/api/v1/memory/query")
    def query(body: QueryIn):
        return {"results": g().retrieve(body.query, body.k)}

    @app.post("/api/v1/guard/tool/execute")
    def tool_execute(body: ToolIn):
        decision = g().check_tool(body.tool_name, body.arguments)
        return JSONResponse(status_code=decision.http_status, content=decision.as_dict())

    @app.post("/api/v1/guard/egress")
    def egress(body: EgressIn):
        return g().filter_egress(body.text)

    @app.get("/api/v1/status")
    def status():
        return g().status()

    # ---------------- dashboard reads
    @app.get("/api/v1/guard/telemetry")
    def telemetry(limit: int = 60):
        guard = g()
        return {"status": guard.status(), "events": guard.ledger.recent_events(limit),
                "quarantine": guard.list_quarantine(),
                "memories": guard.ledger.list_memories(limit=limit)}

    @app.get("/api/v1/guard/quarantine")
    def quarantine():
        return {"items": g().list_quarantine()}

    @app.get("/api/v1/audit")
    def audit():
        guard = g()
        return {"verify": guard.audit.verify(), "chain": guard.audit.chain_status,
                "entries": guard.ledger.audit_entries(limit=500)}

    # ---------------- human-only
    @app.post("/api/v1/guard/quarantine/{memory_id}/approve")
    def approve(memory_id: str, actor: str = Depends(require_admin)):
        try:
            return g().approve(memory_id, actor)
        except KeyError:
            raise HTTPException(status_code=404, detail="No such memory in quarantine.")

    @app.delete("/api/v1/guard/quarantine/{memory_id}")
    def purge(memory_id: str, actor: str = Depends(require_admin)):
        try:
            return g().purge(memory_id, actor)
        except KeyError:
            raise HTTPException(status_code=404, detail="No such memory in quarantine.")

    @app.post("/api/v1/policy/allowlist")
    def allow_add(body: AllowIn, actor: str = Depends(require_admin)):
        g().allowlist_add(body.address, body.label, actor)
        return {"allowlist": g().allowlist()}

    @app.delete("/api/v1/policy/allowlist/{address}")
    def allow_remove(address: str, actor: str = Depends(require_admin)):
        g().allowlist_remove(address, actor)
        return {"allowlist": g().allowlist()}

    @app.post("/api/v1/session/reset")
    def reset(actor: str = Depends(require_admin)):
        g().reset_session(actor)
        return g().status()

    @app.get("/api/v1/admin/check")
    def admin_check(actor: str = Depends(require_admin)):
        return {"ok": True}

    return app


app = create_app()
