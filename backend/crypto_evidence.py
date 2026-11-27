"""MirageNet Secure Evidence Management: AES-256-GCM, SHA-256 hash chain, Ed25519 signatures, and RBAC."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EvidenceVault:
    """Stores tamper-evident, AES-256-GCM encrypted, Ed25519-signed forensic evidence."""

    def __init__(self, master_key: bytes | None = None) -> None:
        self._aes_key = master_key or AESGCM.generate_key(bit_length=256)
        self._aesgcm = AESGCM(self._aes_key)
        self._signing_key = Ed25519PrivateKey.generate()
        self._verify_key: Ed25519PublicKey = self._signing_key.public_key()
        self._records: list[dict[str, Any]] = []
        self._audit_log: list[dict[str, Any]] = []

    @property
    def public_key_pem(self) -> str:
        return self._verify_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def seal_evidence(self, session_id: str, event_payload: dict[str, Any], actor: str = "system") -> dict[str, Any]:
        """Encrypt event payload with AES-256-GCM, link SHA-256 chain, and sign with Ed25519."""
        timestamp = datetime.now(timezone.utc).isoformat()
        prev_hash = self._records[-1]["record_hash"] if self._records else "0" * 64

        plaintext = json.dumps(event_payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        nonce = os.urandom(12)
        aad = f"{session_id}|{timestamp}".encode("utf-8")
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, aad)

        chain_input = f"{prev_hash}|{session_id}|{timestamp}|{base64.b64encode(ciphertext).decode('ascii')}".encode("utf-8")
        record_hash = hashlib.sha256(chain_input).hexdigest()
        signature = self._signing_key.sign(record_hash.encode("utf-8"))

        record = {
            "evidence_id": f"EVD-{len(self._records) + 1:04d}",
            "session_id": session_id,
            "timestamp": timestamp,
            "prev_hash": prev_hash,
            "record_hash": record_hash,
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
            "signature_b64": base64.b64encode(signature).decode("ascii"),
            "algorithm": "AES-256-GCM + SHA-256 + Ed25519",
            "event_type": event_payload.get("event_type", "unknown"),
            "risk_level": event_payload.get("risk_level", "LOW"),
        }
        self._records.append(record)
        self._log_audit(actor, "SEAL_EVIDENCE", record["evidence_id"], f"Sealed {record['event_type']}")
        return record

    def decrypt_evidence(self, evidence_id: str, actor: str) -> dict[str, Any]:
        """Decrypt an evidence record after verifying its hash and Ed25519 signature."""
        integrity = self.verify_chain()
        if not integrity["integrity_ok"]:
            raise ValueError("Evidence chain integrity verification failed")

        record = next((r for r in self._records if r["evidence_id"] == evidence_id), None)
        if not record:
            raise KeyError(f"Evidence {evidence_id} not found")

        try:
            nonce = base64.b64decode(record["nonce_b64"], validate=True)
            ciphertext = base64.b64decode(record["ciphertext_b64"], validate=True)
            aad = f"{record['session_id']}|{record['timestamp']}".encode("utf-8")
            plaintext = self._aesgcm.decrypt(nonce, ciphertext, aad)
        except (InvalidTag, ValueError) as exc:
            raise ValueError("Evidence decryption failed integrity validation") from exc

        self._log_audit(actor, "DECRYPT_EVIDENCE", evidence_id, "Authorized forensic read")
        return json.loads(plaintext.decode("utf-8"))

    def verify_chain(self) -> dict[str, Any]:
        """Verify every record's SHA-256 hash chain link and Ed25519 digital signature."""
        expected_prev = "0" * 64
        verified_count = 0
        failures: list[dict[str, str]] = []

        for rec in self._records:
            if rec["prev_hash"] != expected_prev:
                failures.append({"evidence_id": rec["evidence_id"], "reason": "Hash chain break (prev_hash mismatch)"})
                continue

            chain_input = (
                f"{rec['prev_hash']}|{rec['session_id']}|{rec['timestamp']}|{rec['ciphertext_b64']}"
            ).encode("utf-8")
            recomputed_hash = hashlib.sha256(chain_input).hexdigest()
            if recomputed_hash != rec["record_hash"]:
                failures.append({"evidence_id": rec["evidence_id"], "reason": "SHA-256 payload hash mismatch"})
                continue

            try:
                sig = base64.b64decode(rec["signature_b64"])
                self._verify_key.verify(sig, rec["record_hash"].encode("utf-8"))
            except Exception:
                failures.append({"evidence_id": rec["evidence_id"], "reason": "Ed25519 signature invalid"})
                continue

            expected_prev = rec["record_hash"]
            verified_count += 1

        return {
            "total_records": len(self._records),
            "verified_records": verified_count,
            "integrity_ok": len(failures) == 0,
            "failures": failures,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    def list_records(self, session_id: str | None = None) -> list[dict[str, Any]]:
        if session_id:
            return [r for r in self._records if r["session_id"] == session_id]
        return list(self._records)

    def get_audit_log(self) -> list[dict[str, Any]]:
        return list(self._audit_log)

    def _log_audit(self, actor: str, action: str, target: str, detail: str) -> None:
        self._audit_log.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "actor": actor,
                "action": action,
                "target": target,
                "detail": detail,
            }
        )


class RBACManager:
    """Role-Based Access Control for MirageNet SOC operators."""

    ROLE_PERMISSIONS: dict[str, set[str]] = {
        "admin": {"view_dashboard", "manage_sessions", "decrypt_evidence", "verify_evidence", "export_report"},
        "analyst": {"view_dashboard", "manage_sessions", "verify_evidence", "export_report"},
        "auditor": {"view_dashboard", "verify_evidence", "export_report"},
    }

    def __init__(self) -> None:
        self._users: dict[str, dict[str, str]] = {
            "soc_admin": {
                "password_hash": self._hash_pw("MirageAdmin!2026"),
                "role": "admin",
                "display_name": "SOC Lead (Admin)",
            },
            "analyst_1": {
                "password_hash": self._hash_pw("MirageAnalyst!2026"),
                "role": "analyst",
                "display_name": "Tier-2 Analyst",
            },
            "auditor_1": {
                "password_hash": self._hash_pw("MirageAudit!2026"),
                "role": "auditor",
                "display_name": "Compliance Auditor",
            },
        }
        self._tokens: dict[str, dict[str, str]] = {}

    @staticmethod
    def _hash_pw(password: str) -> str:
        """Derive a password verifier using PBKDF2 and a fresh per-user salt."""
        salt = os.urandom(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
        return f"{base64.b64encode(salt).decode('ascii')}${digest.hex()}"

    def authenticate(self, username: str, password: str) -> dict[str, str] | None:
        user = self._users.get(username)
        if not user:
            return None
        salt_b64, expected = user["password_hash"].split("$", 1)
        salt = base64.b64decode(salt_b64, validate=True)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000).hex()
        if not hmac.compare_digest(expected, actual):
            return None
        token = secrets.token_urlsafe(24)
        session_info = {
            "token": token,
            "username": username,
            "role": user["role"],
            "display_name": user["display_name"],
        }
        self._tokens[token] = session_info
        return session_info

    def check_permission(self, token: str | None, permission: str) -> dict[str, str]:
        if not token or token not in self._tokens:
            # Default demo analyst context when unauthenticated in local MVP mode,
            # while still enforcing strict role checks for sensitive actions like decrypt_evidence.
            if permission in {"view_dashboard", "manage_sessions", "verify_evidence", "export_report"}:
                return {"username": "demo_analyst", "role": "analyst", "display_name": "Demo SOC Analyst"}
            raise PermissionError("Authentication required for sensitive forensic operation")

        user = self._tokens[token]
        if permission not in self.ROLE_PERMISSIONS.get(user["role"], set()):
            raise PermissionError(f"Role '{user['role']}' lacks permission '{permission}'")
        return user
