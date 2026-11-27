from typing import Any, Dict, List, Optional


CANARY_FILES = {
    "salaries_2026.csv": "CNRY-FIN-9941-X8A",
    "aws_credentials.env": "CNRY-AWS-7720-K3Z",
    "db_backup.sql": "CNRY-SQL-4410-M9P",
    "config.php": "CNRY-WEB-5512-Q1W",
}

MITRE_RULES: List[Dict[str, Any]] = [
    {
        "keywords": ["salaries_2026", "aws_credentials", "db_backup.sql", "config.php"],
        "mitre_id": "T1005",
        "mitre_name": "Data from Local System (Honeyfile Access)",
        "tactic": "Collection",
        "severity": "CRITICAL",
        "score_delta": 35,
        "persona": "Data Thief / Exfiltrator",
        "ai_note": "Attacker accessed decoy Honeyfile containing embedded Canary Token.",
    },
    {
        "keywords": ["curl", "wget", "scp", "nc ", "netcat"],
        "mitre_id": "T1041",
        "mitre_name": "Exfiltration / C2 Payload Transfer",
        "tactic": "Exfiltration & C2",
        "severity": "HIGH",
        "score_delta": 25,
        "persona": "Active Post-Exploitation Operator",
        "ai_note": "Attempted external network transfer or payload staging detected.",
    },
    {
        "keywords": ["sudo", "chmod +x", "su ", "passwd", "shadow"],
        "mitre_id": "T1548",
        "mitre_name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "severity": "HIGH",
        "score_delta": 25,
        "persona": "Privilege Escalation Seeker",
        "ai_note": "Attacker attempted to escalate privileges or access credential stores.",
    },
    {
        "keywords": ["nmap", "netstat", "ss ", "ifconfig", "ip ", "/etc/hosts"],
        "mitre_id": "T1046",
        "mitre_name": "Network Service Discovery",
        "tactic": "Discovery",
        "severity": "MEDIUM",
        "score_delta": 15,
        "persona": "Lateral Movement Scout",
        "ai_note": "Internal network topology and service enumeration detected.",
    },
    {
        "keywords": ["env", ".bash_history", "notes.txt", "deploy.sh"],
        "mitre_id": "T1552",
        "mitre_name": "Unsecured Credentials Discovery",
        "tactic": "Credential Access",
        "severity": "MEDIUM",
        "score_delta": 15,
        "persona": "Credential Harvester",
        "ai_note": "Attacker searched environment variables and user history for secrets.",
    },
    {
        "keywords": ["ls", "ll", "find", "cd", "pwd", "cat"],
        "mitre_id": "T1083",
        "mitre_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "severity": "LOW",
        "score_delta": 5,
        "persona": "Reconnaissance Probe",
        "ai_note": "Filesystem enumeration inside the illusion room.",
    },
    {
        "keywords": ["whoami", "id", "uname", "hostname", "ps", "history"],
        "mitre_id": "T1082",
        "mitre_name": "System Information Discovery",
        "tactic": "Discovery",
        "severity": "LOW",
        "score_delta": 5,
        "persona": "Reconnaissance Probe",
        "ai_note": "Host fingerprinting inside the sandboxed environment.",
    },
]


def analyze_command(command: str, current_score: int) -> Dict[str, Any]:
    """Analyze attacker command, map to MITRE ATT&CK, and detect Canary Token triggers."""
    cmd_lower = command.lower().strip()

    # Check if any Honeyfile / Canary Token was touched
    canary_triggered: Optional[str] = None
    canary_file: Optional[str] = None
    if any(op in cmd_lower for op in ("cat", "head", "tail", "more", "less", "curl", "scp", "grep")):
        for fname, token_id in CANARY_FILES.items():
            if fname in cmd_lower:
                canary_triggered = token_id
                canary_file = fname
                break

    matched_rule = None
    for rule in MITRE_RULES:
        if any(kw in cmd_lower for kw in rule["keywords"]):
            matched_rule = rule
            break

    if not matched_rule:
        matched_rule = {
            "mitre_id": "T1059",
            "mitre_name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "severity": "LOW",
            "score_delta": 5,
            "persona": "Interactive Intruder",
            "ai_note": "Unclassified shell command executed inside deception container.",
        }

    new_score = min(100, current_score + matched_rule["score_delta"])
    if canary_triggered:
        new_score = min(100, max(new_score, 85))

    return {
        "mitre_id": matched_rule["mitre_id"],
        "mitre_name": matched_rule["mitre_name"],
        "tactic": matched_rule["tactic"],
        "severity": "CRITICAL" if canary_triggered else matched_rule["severity"],
        "score_delta": matched_rule["score_delta"],
        "new_threat_score": new_score,
        "persona": matched_rule["persona"],
        "ai_note": matched_rule["ai_note"],
        "canary_triggered": canary_triggered,
        "canary_file": canary_file,
    }


def generate_forensic_summary(report: Dict[str, Any]) -> str:
    """Generate an executive AI-style forensic summary from the session logs."""
    sess = report["session"]
    logs = report["logs"]
    canaries = report["canary_alerts"]

    tactics = list({log["tactic"] for log in logs if log.get("tactic")})
    mitres = list({f"{log['mitre_id']} ({log['mitre_name']})" for log in logs if log.get("mitre_id")})

    summary = [
        f"Session {sess['id']} from IP {sess['attacker_ip']} entered via {sess['entry_vector']}.",
        f"The intruder executed {len(logs)} commands inside the MirageNet Illusion Room while the real infrastructure remained 100% isolated.",
        f"Classified Attacker Persona: {sess['persona']} (Threat Score: {sess['threat_score']}/100).",
    ]
    if tactics:
        summary.append(f"Observed MITRE ATT&CK Tactics: {', '.join(tactics)}.")
    if canaries:
        files = ", ".join(c["file_name"] for c in canaries)
        summary.append(
            f"CRITICAL DECEPTION WIN: Attacker fell for Honeyfile trap ({files}) and triggered {len(canaries)} Canary Token(s)."
        )
    if mitres:
        summary.append(f"Key Techniques: {'; '.join(mitres[:4])}.")
    summary.append(
        "Recommendation: Block source IP at perimeter firewall, audit real credentials matching decoy targets, "
        "and preserve SHA-256 chained evidence logs."
    )
    return " ".join(summary)
