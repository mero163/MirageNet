import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_PATH = Path(__file__).resolve().parent.parent / "miragenet.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize SQLite tables for sessions, forensic logs, and canary alerts."""
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                attacker_ip TEXT NOT NULL,
                entry_vector TEXT NOT NULL,
                started_at TEXT NOT NULL,
                threat_score INTEGER DEFAULT 0,
                status TEXT DEFAULT 'ACTIVE_TRAP',
                persona TEXT DEFAULT 'Unknown Intruder'
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS command_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                cwd TEXT NOT NULL,
                command TEXT NOT NULL,
                response TEXT NOT NULL,
                mitre_id TEXT,
                mitre_name TEXT,
                tactic TEXT,
                severity TEXT,
                canary_triggered TEXT,
                evidence_hash TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS canary_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                token_id TEXT NOT NULL,
                file_name TEXT NOT NULL,
                triggered_at TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                details TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
            """
        )
        conn.commit()


def compute_evidence_hash(
    session_id: str, timestamp: str, command: str, response: str, prev_hash: str = ""
) -> str:
    """Compute chained SHA-256 forensic hash to guarantee log integrity (Chain of Custody)."""
    payload = f"{prev_hash}|{session_id}|{timestamp}|{command}|{response}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def create_session(session_id: str, attacker_ip: str, entry_vector: str) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO sessions (id, attacker_ip, entry_vector, started_at, threat_score, status, persona)
            VALUES (?, ?, ?, ?, 10, 'ACTIVE_TRAP', 'Reconnaissance Probe')
            """,
            (session_id, attacker_ip, entry_vector, now),
        )
        conn.commit()
    return {
        "id": session_id,
        "attacker_ip": attacker_ip,
        "entry_vector": entry_vector,
        "started_at": now,
        "threat_score": 10,
        "status": "ACTIVE_TRAP",
        "persona": "Reconnaissance Probe",
    }


def log_command(
    session_id: str,
    cwd: str,
    command: str,
    response: str,
    analysis: Dict[str, Any],
) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT evidence_hash FROM command_logs WHERE session_id = ? ORDER BY id DESC LIMIT 1",
            (session_id,),
        ).fetchone()
        prev_hash = row["evidence_hash"] if row else "GENESIS"
        ev_hash = compute_evidence_hash(session_id, now, command, response, prev_hash)

        conn.execute(
            """
            INSERT INTO command_logs (
                session_id, timestamp, cwd, command, response,
                mitre_id, mitre_name, tactic, severity, canary_triggered, evidence_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                now,
                cwd,
                command,
                response,
                analysis.get("mitre_id"),
                analysis.get("mitre_name"),
                analysis.get("tactic"),
                analysis.get("severity"),
                analysis.get("canary_triggered"),
                ev_hash,
            ),
        )

        # Update session threat score and persona
        new_score = min(100, analysis.get("new_threat_score", 15))
        persona = analysis.get("persona", "Active Intruder")
        conn.execute(
            "UPDATE sessions SET threat_score = ?, persona = ? WHERE id = ?",
            (new_score, persona, session_id),
        )

        if analysis.get("canary_triggered"):
            conn.execute(
                """
                INSERT INTO canary_alerts (session_id, token_id, file_name, triggered_at, source_ip, details)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    analysis["canary_triggered"],
                    analysis.get("canary_file", "unknown"),
                    now,
                    "185.220.101.42",
                    f"Attacker accessed/exfiltrated honeyfile containing Canary Token {analysis['canary_triggered']}",
                ),
            )
        conn.commit()

    return {
        "session_id": session_id,
        "timestamp": now,
        "cwd": cwd,
        "command": command,
        "response": response,
        "analysis": analysis,
        "evidence_hash": ev_hash,
    }


def get_session_report(session_id: str) -> Optional[Dict[str, Any]]:
    with get_connection() as conn:
        sess = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if not sess:
            return None
        logs = conn.execute(
            "SELECT * FROM command_logs WHERE session_id = ? ORDER BY id ASC", (session_id,)
        ).fetchall()
        canaries = conn.execute(
            "SELECT * FROM canary_alerts WHERE session_id = ? ORDER BY id ASC", (session_id,)
        ).fetchall()

        # Verify chain of custody hashes
        integrity_valid = True
        prev_hash = "GENESIS"
        for log in logs:
            expected = compute_evidence_hash(
                log["session_id"], log["timestamp"], log["command"], log["response"], prev_hash
            )
            if expected != log["evidence_hash"]:
                integrity_valid = False
                break
            prev_hash = log["evidence_hash"]

        return {
            "session": dict(sess),
            "logs": [dict(r) for r in logs],
            "canary_alerts": [dict(c) for c in canaries],
            "integrity_verified": integrity_valid,
            "total_commands": len(logs),
        }


def list_sessions() -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM sessions ORDER BY started_at DESC LIMIT 20").fetchall()
        return [dict(r) for r in rows]
