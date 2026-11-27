import json
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .database import (
    create_session,
    get_session_report,
    init_db,
    list_sessions,
    log_command,
)
from .illusion_engine import get_or_create_illusion_session
from .threat_profiler import analyze_command, generate_forensic_summary

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

app = FastAPI(
    title="MirageNet — AI-Powered Cyber Deception Platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class DashboardHub:
    """Manages live WebSocket connections for the Blue Team SOC Dashboard."""

    def __init__(self) -> None:
        self.connections: List[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.connections.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.connections:
            self.connections.remove(ws)

    async def broadcast(self, event: Dict[str, Any]) -> None:
        payload = json.dumps(event)
        stale: List[WebSocket] = []
        for ws in self.connections:
            try:
                await ws.send_text(payload)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.disconnect(ws)


hub = DashboardHub()


class StartSessionRequest(BaseModel):
    attacker_ip: str = "185.220.101.42"
    entry_vector: str = "SSH Decoy Port 22"


class CommandRequest(BaseModel):
    session_id: str
    command: str


class LLMConfigRequest(BaseModel):
    session_id: str
    api_key: str
    model: str = "gpt-4o-mini"


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/")
def serve_home() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.post("/api/session/start")
async def api_start_session(req: StartSessionRequest) -> Dict[str, Any]:
    session_id = f"TRAP-{uuid.uuid4().hex[:8].upper()}"
    sess = create_session(session_id, req.attacker_ip, req.entry_vector)
    get_or_create_illusion_session(session_id)
    await hub.broadcast({"type": "SESSION_STARTED", "session": sess})
    return sess


@app.post("/api/command")
async def api_execute_command(req: CommandRequest) -> Dict[str, Any]:
    report = get_session_report(req.session_id)
    if not report:
        raise HTTPException(status_code=404, detail="Session not found")

    illusion = get_or_create_illusion_session(req.session_id)
    current_score = report["session"]["threat_score"]
    prev_cwd = illusion.cwd

    output, new_cwd = illusion.execute(req.command)
    analysis = analyze_command(req.command, current_score)
    logged = log_command(req.session_id, prev_cwd, req.command, output, analysis)

    await hub.broadcast(
        {
            "type": "COMMAND_EXECUTED",
            "session_id": req.session_id,
            "cwd": prev_cwd,
            "new_cwd": new_cwd,
            "user": illusion.user,
            "hostname": illusion.hostname,
            "command": req.command,
            "output": output,
            "analysis": analysis,
            "evidence_hash": logged["evidence_hash"],
            "timestamp": logged["timestamp"],
        }
    )

    return {
        "session_id": req.session_id,
        "user": illusion.user,
        "hostname": illusion.hostname,
        "cwd": new_cwd,
        "output": output,
        "analysis": analysis,
        "evidence_hash": logged["evidence_hash"],
    }


@app.get("/api/sessions")
def api_list_sessions() -> List[Dict[str, Any]]:
    return list_sessions()


@app.get("/api/session/{session_id}/report")
def api_session_report(session_id: str) -> Dict[str, Any]:
    report = get_session_report(session_id)
    if not report:
        raise HTTPException(status_code=404, detail="Session not found")
    report["ai_summary"] = generate_forensic_summary(report)
    return report


@app.post("/api/config/llm")
def api_config_llm(req: LLMConfigRequest) -> Dict[str, str]:
    illusion = get_or_create_illusion_session(req.session_id)
    illusion.llm_api_key = req.api_key.strip() or None
    illusion.llm_model = req.model
    return {"status": "updated", "llm_enabled": str(bool(illusion.llm_api_key))}


@app.websocket("/ws/dashboard")
async def ws_dashboard(ws: WebSocket) -> None:
    await hub.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        hub.disconnect(ws)


if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
