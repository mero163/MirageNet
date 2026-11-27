"""MirageNet AI Threat Analysis Engine: Behavioral classification, MITRE ATT&CK mapping, risk scoring & Explainable AI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ThreatRule:
    pattern_tokens: tuple[str, ...]
    category: str
    mitre_tactic: str
    mitre_id: str
    mitre_name: str
    base_risk: int
    rationale: str
    recommendation: str


THREAT_RULES: list[ThreatRule] = [
    ThreatRule(
        pattern_tokens=("aws_credentials", "id_rsa", ".env", "db_backup", "payroll_2026"),
        category="Credential & Sensitive Data Access",
        mitre_tactic="Credential Access / Collection",
        mitre_id="T1552.001",
        mitre_name="Unsecured Credentials: Credentials In Files",
        base_risk=88,
        rationale="Attempted read/exfiltration of a monitored Digital Canary honeyfile containing decoy credentials or sensitive records.",
        recommendation="Rotate exposed service tokens immediately, enforce secrets vaulting, and isolate the source session.",
    ),
    ThreatRule(
        pattern_tokens=("' or 1=1", "union select", "drop table", "--", "admin'"),
        category="SQL Injection Probe",
        mitre_tactic="Initial Access",
        mitre_id="T1190",
        mitre_name="Exploit Public-Facing Application",
        base_risk=84,
        rationale="Input payload matches SQL injection tautology or union-based query manipulation against the decoy admin interface.",
        recommendation="Enforce parameterized queries, enable WAF SQLi ruleset, and audit authentication endpoints.",
    ),
    ThreatRule(
        pattern_tokens=("/etc/passwd", "/etc/shadow", "sudo", "chmod 777", "su "),
        category="Privilege Escalation & Account Discovery",
        mitre_tactic="Privilege Escalation",
        mitre_id="T1548",
        mitre_name="Abuse Elevation Control Mechanism",
        base_risk=76,
        rationale="Command sequence probes local user account files or attempts privilege elevation inside the isolated host.",
        recommendation="Audit sudoers policy, enforce least-privilege RBAC, and monitor /etc/passwd access.",
    ),
    ThreatRule(
        pattern_tokens=("curl", "wget", "nc ", "scp ", "base64"),
        category="Potential Exfiltration / Payload Fetch",
        mitre_tactic="Exfiltration",
        mitre_id="T1048",
        mitre_name="Exfiltration Over Alternative Protocol",
        base_risk=80,
        rationale="Outbound transfer or encoding utility invoked inside the sandbox, indicative of staging or data exfiltration.",
        recommendation="Restrict egress firewall rules to allowlisted destinations and inspect outbound DNS/HTTP traffic.",
    ),
    ThreatRule(
        pattern_tokens=("uname", "whoami", "id", "ps", "netstat", "env", "find", "ls"),
        category="System & Environment Discovery",
        mitre_tactic="Discovery",
        mitre_id="T1082",
        mitre_name="System Information Discovery",
        base_risk=32,
        rationale="Session enumerated host identity, running processes, network sockets, or directory structure.",
        recommendation="Continue passive observation in deception sandbox; correlate with subsequent lateral or credential activity.",
    ),
]


class AIThreatAnalyzer:
    """Explainable AI analyzer that scores events, maps MITRE ATT&CK, and produces human-readable SOC insights."""

    def analyze_event(
        self,
        event_type: str,
        raw_input: str,
        canary_trigger: dict[str, Any] | None,
        session_history_count: int,
        previous_risk: int,
    ) -> dict[str, Any]:
        lowered = raw_input.lower()
        matched_rule: ThreatRule | None = None

        for rule in THREAT_RULES:
            if any(tok in lowered for tok in rule.pattern_tokens):
                matched_rule = rule
                break

        if matched_rule is None:
            matched_rule = ThreatRule(
                pattern_tokens=(),
                category="Interactive Sandbox Activity",
                mitre_tactic="Execution",
                mitre_id="T1059",
                mitre_name="Command and Scripting Interpreter",
                base_risk=20,
                rationale=f"Routine or exploratory '{event_type}' interaction recorded inside the isolated deception environment.",
                recommendation="Maintain session monitoring and retain encrypted audit trail.",
            )

        # Dynamic behavioral risk calculation (anomaly boost for repeated actions & canary hits)
        risk_score = matched_rule.base_risk
        if canary_trigger:
            risk_score = max(risk_score, 92 if canary_trigger["sensitivity"] == "CRITICAL" else 82)
        if session_history_count >= 5:
            risk_score = min(100, risk_score + 6)
        if previous_risk >= 75 and risk_score >= 50:
            risk_score = min(100, risk_score + 5)

        if risk_score >= 85:
            risk_level = "CRITICAL"
        elif risk_score >= 65:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        explanation = (
            f"[{risk_level} | Score {risk_score}/100] {matched_rule.rationale} "
            f"Observed input: `{raw_input[:90]}`. "
            f"Note: Classified as a reviewable security indicator (MITRE {matched_rule.mitre_id}), not an automated attribution."
        )

        return {
            "category": matched_rule.category,
            "mitre_tactic": matched_rule.mitre_tactic,
            "mitre_id": matched_rule.mitre_id,
            "mitre_name": matched_rule.mitre_name,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "explanation": explanation,
            "recommendation": matched_rule.recommendation,
            "is_anomaly": risk_score >= 65 or canary_trigger is not None,
        }
