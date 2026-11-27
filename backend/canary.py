"""MirageNet Digital Canary & Honeyfile Registry."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class Honeyfile:
    path: str
    canary_id: str
    sensitivity: str
    description: str
    content: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()


HONEYFILES: dict[str, Honeyfile] = {
    "/opt/secrets/aws_credentials.txt": Honeyfile(
        path="/opt/secrets/aws_credentials.txt",
        canary_id="CNR-AWS-9041",
        sensitivity="CRITICAL",
        description="Decoy AWS IAM Access Key & Secret + Canary Tracking Beacon URL",
        content=(
            "# MirageNet Decoy Cloud Credentials [CANARY: CNR-AWS-9041]\n"
            "[default]\n"
            "aws_access_key_id = AKIAIOSFODNN7DECOY99\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYDECOYKEY\n"
            "region = us-east-1\n"
            "# Internal Auth Callback (Canary Beacon):\n"
            "sts_endpoint = http://127.0.0.1:8000/api/canary/beacon/CNR-AWS-9041\n"
        ),
    ),
    "/srv/backups/payroll_2026.csv": Honeyfile(
        path="/srv/backups/payroll_2026.csv",
        canary_id="CNR-HR-3318",
        sensitivity="HIGH",
        description="Synthetic Corporate Payroll Export",
        content=(
            "emp_id,full_name,department,salary_usd,iban_token\n"
            "E-101,Tariq Mansour,Engineering,9400,DECOY-IBAN-0011\n"
            "E-102,Nadia Hassan,Finance,11200,DECOY-IBAN-0022\n"
            "E-103,Karim Adel,Security,10800,DECOY-IBAN-0033\n"
        ),
    ),
    "/var/www/app/.env": Honeyfile(
        path="/var/www/app/.env",
        canary_id="CNR-ENV-5502",
        sensitivity="CRITICAL",
        description="Decoy Application Environment Secrets",
        content=(
            "APP_ENV=production\n"
            "DB_HOST=10.42.0.18\n"
            "DB_USER=mirage_svc\n"
            "DB_PASS=Decoy_S3cr3t_Pass_2026!\n"
            "JWT_SECRET=canary_jwt_5502_do_not_use\n"
        ),
    ),
    "/home/admin/.ssh/id_rsa": Honeyfile(
        path="/home/admin/.ssh/id_rsa",
        canary_id="CNR-SSH-7720",
        sensitivity="CRITICAL",
        description="Decoy SSH Private Key Honeyfile",
        content=(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAACmRlY295LWtleS1jYW5hcnktNzcyaDA=\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        ),
    ),
    "/srv/backups/db_backup.sql": Honeyfile(
        path="/srv/backups/db_backup.sql",
        canary_id="CNR-SQL-4410",
        sensitivity="HIGH",
        description="Synthetic SQL Database Dump",
        content=(
            "-- MirageNet Synthetic DB Dump [CNR-SQL-4410]\n"
            "INSERT INTO admin_users VALUES (1, 'sys_root', 'sha256$decoy$998877');\n"
            "INSERT INTO api_tokens VALUES (10, 'tok_live_decoy_4410', 'full_access');\n"
        ),
    ),
}


class CanaryMonitor:
    """Tracks honeyfile access events and generates canary trigger alerts."""

    def __init__(self) -> None:
        self._triggers: list[dict[str, Any]] = []

    def check_access(self, session_id: str, path: str, action: str) -> dict[str, Any] | None:
        hf = HONEYFILES.get(path)
        if not hf:
            return None
        return self._record_trigger(session_id=session_id, hf=hf, action=action, mechanism="internal_simulation_hook")

    def trigger_beacon(self, canary_id: str, session_id: str = "EXTERNAL-PROBE", source: str = "tracking_url") -> dict[str, Any] | None:
        """Record an active Canary Token hit via tracking URL / beacon callback."""
        hf = next((item for item in HONEYFILES.values() if item.canary_id == canary_id), None)
        if not hf:
            return None
        return self._record_trigger(session_id=session_id, hf=hf, action=f"beacon:{source}", mechanism="canary_tracking_url")

    def _record_trigger(self, session_id: str, hf: Honeyfile, action: str, mechanism: str) -> dict[str, Any]:
        trigger = {
            "canary_id": hf.canary_id,
            "session_id": session_id,
            "path": hf.path,
            "action": action,
            "mechanism": mechanism,
            "sensitivity": hf.sensitivity,
            "file_sha256": hf.sha256,
            "tracking_url": f"/api/canary/beacon/{hf.canary_id}?session_id={session_id}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": f"Canary {hf.canary_id} triggered via {mechanism} ({action}) on {hf.path}",
        }
        self._triggers.append(trigger)
        return trigger

    def list_honeyfiles(self) -> list[dict[str, str]]:
        return [
            {
                "canary_id": hf.canary_id,
                "path": hf.path,
                "sensitivity": hf.sensitivity,
                "description": hf.description,
                "sha256": hf.sha256,
            }
            for hf in HONEYFILES.values()
        ]

    def list_triggers(self, session_id: str | None = None) -> list[dict[str, Any]]:
        if session_id:
            return [t for t in self._triggers if t["session_id"] == session_id]
        return list(self._triggers)
