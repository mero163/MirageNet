"""Automated tests for MirageNet backend, cryptography, deception engine, and FastAPI endpoints."""

from fastapi.testclient import TestClient
import pytest

from backend.app import app
from backend.crypto_evidence import EvidenceVault, RBACManager


def test_evidence_vault_seal_verify_and_tamper_detection() -> None:
    vault = EvidenceVault()
    rec1 = vault.seal_evidence("SES-001", {"event_type": "terminal_command", "risk_level": "LOW", "cmd": "whoami"})
    rec2 = vault.seal_evidence("SES-001", {"event_type": "canary_hit", "risk_level": "CRITICAL", "cmd": "cat aws_credentials.txt"})

    assert rec1["evidence_id"] == "EVD-0001"
    assert rec2["prev_hash"] == rec1["record_hash"]

    verification = vault.verify_chain()
    assert verification["integrity_ok"] is True
    assert verification["verified_records"] == 2

    decrypted = vault.decrypt_evidence("EVD-0002", actor="soc_admin")
    assert decrypted["cmd"] == "cat aws_credentials.txt"

    # Simulate tampering with stored ciphertext
    vault._records[0]["ciphertext_b64"] = "tampered=="
    tamper_check = vault.verify_chain()
    assert tamper_check["integrity_ok"] is False
    assert len(tamper_check["failures"]) >= 1
    with pytest.raises(ValueError, match="integrity"):
        vault.decrypt_evidence("EVD-0001", actor="soc_admin")


def test_rbac_permissions() -> None:
    rbac = RBACManager()
    assert rbac.authenticate("soc_admin", "wrong") is None
    admin = rbac.authenticate("soc_admin", "MirageAdmin!2026")
    auditor = rbac.authenticate("auditor_1", "MirageAudit!2026")
    assert admin is not None and auditor is not None

    # Admin can decrypt, auditor cannot
    assert rbac.check_permission(admin["token"], "decrypt_evidence")["role"] == "admin"
    try:
        rbac.check_permission(auditor["token"], "decrypt_evidence")
        assert False, "Auditor should not have decrypt_evidence permission"
    except PermissionError:
        pass


def test_api_end_to_end_deception_flow() -> None:
    with TestClient(app) as client:
        invalid_scenario = client.post(
            "/api/sessions/SES-MISSING/scenario",
            json={"scenario_id": "recon"},
        )
        assert invalid_scenario.status_code == 404

        # 1. Create isolated session
        s_resp = client.post("/api/sessions", json={"tester_label": "Pytest-Tester", "source_ip": "198.51.100.99"})
        assert s_resp.status_code == 200
        session_id = s_resp.json()["session_id"]

        # 2. Trigger Digital Canary honeyfile
        t_resp = client.post(
            f"/api/sessions/{session_id}/terminal",
            json={"command": "cat /opt/secrets/aws_credentials.txt"},
        )
        assert t_resp.status_code == 200
        t_data = t_resp.json()
        assert t_data["terminal"]["canary_trigger"]["canary_id"] == "CNR-AWS-9041"
        assert t_data["event"]["mitre_id"] == "T1552.001"
        assert t_data["event"]["risk_level"] == "CRITICAL"

        # 2b. Trigger active Canary Tracking Beacon URL
        b_resp = client.get(f"/api/canary/beacon/CNR-ENV-5502?session_id={session_id}")
        assert b_resp.status_code == 200
        assert b_resp.json()["trigger"]["mechanism"] == "canary_tracking_url"

        # 3. Probe Decoy Admin with SQLi
        a_resp = client.post(
            f"/api/sessions/{session_id}/decoy-admin",
            json={"username": "admin' OR 1=1 --", "password": "x", "query": ""},
        )
        assert a_resp.status_code == 200
        assert a_resp.json()["admin_result"]["sqli_detected"] is True
        assert a_resp.json()["event"]["mitre_id"] == "T1190"

        # 4. Verify evidence chain
        v_resp = client.get("/api/evidence/verify")
        assert v_resp.status_code == 200
        assert v_resp.json()["integrity_ok"] is True

        # 5. RBAC-protected decrypt
        ev_id = t_data["event"]["evidence_id"]
        denied = client.get(f"/api/evidence/{ev_id}/decrypt")
        assert denied.status_code == 403

        login = client.post("/api/auth/login", json={"username": "soc_admin", "password": "MirageAdmin!2026"})
        token = login.json()["token"]
        allowed = client.get(f"/api/evidence/{ev_id}/decrypt", headers={"X-Auth-Token": token})
        assert allowed.status_code == 200
        assert allowed.json()["payload"]["raw_input"] == "cat /opt/secrets/aws_credentials.txt"

        # 6. Automated Incident Report
        r_resp = client.get(f"/api/sessions/{session_id}/report")
        assert r_resp.status_code == 200
        report = r_resp.json()
        assert report["overall_risk_level"] == "CRITICAL"
        assert len(report["canary_triggers"]) == 2
        assert report["cryptographic_evidence"]["integrity_verified"] is True


def test_api_redacts_decoy_password_and_rejects_closed_sessions() -> None:
    with TestClient(app) as client:
        session = client.post("/api/sessions", json={"tester_label": "Privacy-Check"}).json()
        session_id = session["session_id"]

        probe = client.post(
            f"/api/sessions/{session_id}/decoy-admin",
            json={"username": "operator", "password": "secret-value-should-not-leak"},
        )
        assert probe.status_code == 200
        assert probe.json()["event"]["raw_input"] == "login user=operator pass=[REDACTED]"
        report = client.get(f"/api/sessions/{session_id}/report").json()
        assert "secret-value-should-not-leak" not in str(report)

        closed = client.post(f"/api/sessions/{session_id}/close")
        assert closed.status_code == 200
        rejected = client.post(
            f"/api/sessions/{session_id}/terminal",
            json={"command": "whoami"},
        )
        assert rejected.status_code == 409
