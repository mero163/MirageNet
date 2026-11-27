"""MirageNet Isolated Honeypot Environment & Adaptive AI Engine."""

from __future__ import annotations

import copy
import posixpath
import uuid
from datetime import datetime, timezone
from typing import Any

from .canary import HONEYFILES, CanaryMonitor

BASE_FILESYSTEM: dict[str, str] = {
    "/home/admin/notes.txt": (
        "TODO Q4:\n"
        "- Rotate staging keys in /opt/secrets/\n"
        "- Verify nightly DB dump in /srv/backups/\n"
        "- Check app .env permissions\n"
    ),
    "/etc/miragenet/service.conf": (
        "service_name=mirage-core-api\n"
        "environment=production-deception\n"
        "listen_port=8443\n"
        "db_cluster=10.42.0.18:5432\n"
    ),
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "admin:x:1000:1000:Corporate Admin:/home/admin:/bin/bash\n"
        "mirage_svc:x:1001:1001:Mirage Service:/var/www/app:/usr/sbin/nologin\n"
    ),
    "/var/www/app/README.md": (
        "# MirageCorp Internal Portal\n"
        "API Gateway running on internal cluster 10.42.0.0/24.\n"
    ),
}

# Populate honeyfiles into the virtual filesystem
for _path, _hf in HONEYFILES.items():
    BASE_FILESYSTEM[_path] = _hf.content

SYNTHETIC_DB: dict[str, list[dict[str, Any]]] = {
    "users": [
        {"id": 1, "username": "sys_admin", "role": "superadmin", "email": "admin@miragecorp.local"},
        {"id": 2, "username": "finance_ops", "role": "billing", "email": "billing@miragecorp.local"},
        {"id": 3, "username": "devops_bot", "role": "automation", "email": "devops@miragecorp.local"},
    ],
    "transactions": [
        {"tx_id": "TX-9001", "account": "CORP-RESERVE", "amount_usd": 48200.00, "status": "SETTLED"},
        {"tx_id": "TX-9002", "account": "CLOUD-INFRA", "amount_usd": 12450.00, "status": "PENDING"},
    ],
    "api_tokens": [
        {"token_id": "TOK-01", "scope": "read:ledger", "prefix": "mir_live_decoy_881a"},
        {"token_id": "TOK-02", "scope": "admin:deploy", "prefix": "mir_live_decoy_994f"},
    ],
}


class HoneypotSession:
    """Stateful, strictly isolated virtual session inside MirageNet."""

    def __init__(self, session_id: str, tester_label: str, source_ip: str = "198.51.100.42") -> None:
        self.session_id = session_id
        self.tester_label = tester_label
        self.source_ip = source_ip
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.ended_at: str | None = None
        self.status = "ACTIVE"
        self.cwd = "/home/admin"
        self.files: dict[str, str] = copy.deepcopy(BASE_FILESYSTEM)
        self.command_history: list[str] = []
        self.accessed_resources: list[str] = []
        self.max_risk_score = 0
        self.events: list[dict[str, Any]] = []
        self.adaptive_notes: list[str] = []

    def resolve_path(self, target: str) -> str:
        if not target:
            return self.cwd
        if target.startswith("/"):
            return posixpath.normpath(target)
        return posixpath.normpath(posixpath.join(self.cwd, target))

    def list_dir(self, path: str) -> list[str]:
        norm = path.rstrip("/") or "/"
        entries: set[str] = set()
        prefix = "/" if norm == "/" else norm + "/"
        for fpath in self.files:
            if fpath.startswith(prefix):
                rest = fpath[len(prefix) :]
                first = rest.split("/", 1)[0]
                if first:
                    entries.add(first + ("/" if "/" in rest else ""))
        return sorted(entries)

    def dir_exists(self, path: str) -> bool:
        if path == "/":
            return True
        prefix = path.rstrip("/") + "/"
        return any(f.startswith(prefix) for f in self.files)


class HoneypotEnvironment:
    """Manages isolated deception sessions and the Adaptive AI response engine."""

    def __init__(self, canary_monitor: CanaryMonitor) -> None:
        self.canary_monitor = canary_monitor
        self.sessions: dict[str, HoneypotSession] = {}

    def create_session(self, tester_label: str = "Authorized-Tester-01", source_ip: str = "198.51.100.42") -> HoneypotSession:
        session_id = f"SES-{uuid.uuid4().hex[:8].upper()}"
        session = HoneypotSession(session_id=session_id, tester_label=tester_label, source_ip=source_ip)
        self.sessions[session_id] = session
        return session

    def get_session(self, session_id: str) -> HoneypotSession:
        if session_id not in self.sessions:
            raise KeyError(f"Session {session_id} not found")
        return self.sessions[session_id]

    def close_session(self, session_id: str) -> HoneypotSession:
        session = self.get_session(session_id)
        if session.status == "CLOSED":
            return session
        session.status = "CLOSED"
        session.ended_at = datetime.now(timezone.utc).isoformat()
        return session

    def execute_terminal_command(self, session_id: str, raw_command: str) -> dict[str, Any]:
        """Execute a command strictly inside the virtual sandbox (zero real OS execution)."""
        session = self.get_session(session_id)
        if session.status != "ACTIVE":
            raise RuntimeError("Session is closed")
        cmd = raw_command.strip()
        if not cmd:
            return {"output": "", "cwd": session.cwd, "canary_trigger": None, "resource": None}

        session.command_history.append(cmd)
        parts = cmd.split()
        verb = parts[0].lower()
        args = parts[1:]
        canary_trigger: dict[str, Any] | None = None
        accessed_resource: str | None = None
        output = ""

        if verb == "help":
            output = (
                "MirageNet Virtual Shell (Isolated Sandbox)\n"
                "Available commands: ls, cd, pwd, cat, find, grep, whoami, id, uname, ps, netstat, env, history, help"
            )
        elif verb == "pwd":
            output = session.cwd
        elif verb == "whoami":
            output = "admin"
        elif verb == "id":
            output = "uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)"
        elif verb == "uname":
            output = "Linux mirage-srv-01 6.8.0-mirage-deception #1 SMP x86_64 GNU/Linux"
        elif verb == "ps":
            output = (
                "  PID TTY          TIME CMD\n"
                "    1 ?        00:00:02 systemd\n"
                "  214 ?        00:00:11 mirage-core-api --port 8443\n"
                "  389 ?        00:00:05 postgres-decoy: writer process\n"
                "  412 pts/0    00:00:00 bash"
            )
        elif verb == "netstat":
            output = (
                "Proto Local Address           Foreign Address         State\n"
                "tcp   0.0.0.0:22              0.0.0.0:*               LISTEN\n"
                "tcp   0.0.0.0:8443            0.0.0.0:*               LISTEN\n"
                "tcp   10.42.0.18:5432         10.42.0.5:49112         ESTABLISHED"
            )
        elif verb == "env":
            output = "USER=admin\nHOME=/home/admin\nAPP_ENV=production-deception\nVAULT_HINT=/opt/secrets"
        elif verb == "history":
            output = "\n".join(f"{idx + 1:3d}  {c}" for idx, c in enumerate(session.command_history))
        elif verb == "ls":
            target = session.resolve_path(args[0]) if args and not args[0].startswith("-") else session.cwd
            entries = session.list_dir(target)
            output = "  ".join(entries) if entries else f"ls: cannot access '{target}': No such file or directory"
            accessed_resource = target
        elif verb == "cd":
            target = session.resolve_path(args[0] if args else "/home/admin")
            if session.dir_exists(target):
                session.cwd = target
                output = ""
            else:
                output = f"bash: cd: {target}: No such directory"
        elif verb == "find":
            root = session.resolve_path(args[0]) if args else "/"
            matches = sorted(p for p in session.files if p.startswith(root if root != "/" else "/"))
            output = "\n".join(matches)
            accessed_resource = root
        elif verb == "cat":
            if not args:
                output = "cat: missing file operand"
            else:
                target = session.resolve_path(args[0])
                accessed_resource = target
                if target in session.files:
                    output = session.files[target]
                    canary_trigger = self.canary_monitor.check_access(session_id, target, "cat")
                else:
                    output = f"cat: {target}: No such file or directory"
        elif verb == "grep":
            if len(args) < 2:
                output = "Usage: grep <pattern> <file>"
            else:
                pattern, target = args[0], session.resolve_path(args[1])
                accessed_resource = target
                if target in session.files:
                    lines = [ln for ln in session.files[target].splitlines() if pattern.lower() in ln.lower()]
                    output = "\n".join(lines) if lines else "(no matches)"
                    canary_trigger = self.canary_monitor.check_access(session_id, target, "grep")
                else:
                    output = f"grep: {target}: No such file or directory"
        else:
            # Adaptive AI Engine: maintain consistent virtual state for novel/unrecognized commands
            output = self._adaptive_ai_response(session, verb, args)

        if accessed_resource and accessed_resource not in session.accessed_resources:
            session.accessed_resources.append(accessed_resource)

        return {
            "output": output,
            "cwd": session.cwd,
            "canary_trigger": canary_trigger,
            "resource": accessed_resource,
        }

    def execute_decoy_admin_action(self, session_id: str, username: str, password: str, query: str = "") -> dict[str, Any]:
        """Simulate interaction with the Dummy Admin Interface & Synthetic Database."""
        session = self.get_session(session_id)
        if session.status != "ACTIVE":
            raise RuntimeError("Session is closed")
        lowered = f"{username} {password} {query}".lower()
        is_sqli = any(tok in lowered for tok in ("' or 1=1", "union select", "drop table", "--"))

        if query:
            table_name = "users" if "user" in query.lower() else ("transactions" if "trans" in query.lower() else "api_tokens")
            session.accessed_resources.append(f"synthetic_db:{table_name}")
            return {
                "authenticated": True,
                "sqli_detected": is_sqli,
                "table": table_name,
                "rows": SYNTHETIC_DB[table_name],
                "message": f"Decoy DB returned synthetic rows from '{table_name}' (session state preserved).",
            }

        if is_sqli or (username == "admin" and password == "admin123"):
            session.accessed_resources.append("decoy_admin:/login")
            return {
                "authenticated": True,
                "sqli_detected": is_sqli,
                "banner": "MirageCorp Internal Admin Portal (Deception Sandbox)",
                "tables": list(SYNTHETIC_DB.keys()),
                "message": "Decoy login accepted into isolated admin view to observe post-auth behavior.",
            }

        return {
            "authenticated": False,
            "sqli_detected": False,
            "message": "Invalid decoy credentials. Try SQLi probe or decoy creds (admin / admin123) to test detection.",
        }

    def _adaptive_ai_response(self, session: HoneypotSession, verb: str, args: list[str]) -> str:
        """AI Illusion Engine: Prompt-engineered stateful simulation (zero real OS or SSH execution)."""
        arg_str = " ".join(args)
        # Structured prompt context used when delegating novel commands to an LLM illusion layer
        _prompt_context = (
            f"SYSTEM: Simulate Linux deception host mirage-srv-01 in cwd={session.cwd}. "
            f"Never execute real OS commands. Preserve session_id={session.session_id} state. "
            f"INPUT: {verb} {arg_str}"
        )
        if verb in {"curl", "wget"}:
            note = f"AI Illusion Engine: Simulated outbound fetch ({verb} {arg_str}) in isolated network sinkhole."
            session.adaptive_notes.append(note)
            return (
                f"[MirageNet AI Illusion Sinkhole]\n"
                f"HTTP/1.1 200 OK (Simulated)\n"
                f"Content-Type: application/json\n"
                f'{{"status":"sandboxed","target":"{arg_str or "internal-api"}","note":"No real egress or SSH permitted"}}'
            )
        if verb in {"sudo", "su", "ssh"}:
            note = f"AI Illusion Engine: Simulated '{verb} {arg_str}' inside isolated sandbox (no real SSH/privilege execution)."
            session.adaptive_notes.append(note)
            return f"[{verb}] Simulated sandbox response for admin on mirage-srv-01: access restricted & logged."

        if verb in {"touch", "mkdir"} and args:
            target = session.resolve_path(args[0])
            session.files[target] = f"# Virtual artifact created during session {session.session_id}\n"
            note = f"AI Illusion Engine: Persisted virtual artifact '{target}' in session state."
            session.adaptive_notes.append(note)
            return f"[AI Illusion Sandbox] Created virtual resource: {target}"

        return f"bash: {verb}: simulated by MirageNet AI Illusion Engine (zero real OS execution; type 'help')"
