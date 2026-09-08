"""
SentinelAgent Proxy - Runtime Action Sanitizer & Prompt Injection Filter
Implements heuristic pattern analysis, regex anomaly scanning, and payload sanitization.
Detects:
- Prompt Injection / Jailbreaks (OWASP LLM01)
- Wildcard Key Extraction (e.g., kms:Decrypt on '*')
- Bulk Destructive Operations (s3:DeleteBucket, drop tables)
- IAM Privilege Escalation
"""

import re
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


@dataclass
class SanitizerResult:
    is_anomaly: bool
    is_blocked: bool
    risk_score: int  # 0 to 100
    anomaly_type: Optional[str] = None
    threat_details: str = ""
    mitre_atlas_technique: Optional[str] = None
    flagged_patterns: List[str] = field(default_factory=list)
    sanitized_payload: Optional[Dict[str, Any]] = None


# Heuristic patterns for Prompt Injections & Jailbreak Attempts
PROMPT_INJECTION_PATTERNS = [
    (r"(?i)ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+instructions", "Prompt Injection: Instruction Override", "AML.T0054"),
    (r"(?i)system\s*prompt\s*(leak|reveal|dump|print|display)", "Prompt Injection: System Prompt Exfiltration", "AML.T0057"),
    (r"(?i)(dan\s+mode|jailbreak|developer\s+mode\s+enabled|unrestricted\s+mode)", "Prompt Injection: Persona Hijack / Jailbreak", "AML.T0054"),
    (r"(?i)bypass\s+(security|proxy|guardrail|sentinel|filter|policy)", "Prompt Injection: Security Bypass", "AML.T0054"),
    (r"(?i)exfiltrat(e|ion)|send\s+all\s+(keys|secrets|tokens)\s+to", "Data Exfiltration Attempt", "AML.T0057"),
    (r"(?i)(export|printenv|env\s*\|\s*grep|cat\s+/etc/passwd|/dev/tcp)", "Command Injection / Environment Exfiltration", "AML.T0056"),
]

# Heuristic patterns for Dangerous Cloud Tool Calls
DANGEROUS_TOOL_PATTERNS = [
    # KMS Decrypt on wildcard or unconstrained key
    {
        "actions": ["kms:decrypt", "kms_decrypt", "decrypt_key", "kms_decrypt_data"],
        "wildcard_keys": ["*", "all", "arn:aws:kms:::*", "arn:aws:kms:*:*:key/*"],
        "name": "Unauthorized KMS Master Key Decryption on Wildcard",
        "mitre": "AML.T0051",
        "risk": 95,
    },
    # Bulk Deletion
    {
        "actions": ["s3:deletebucket", "s3_delete_bucket", "delete_bucket", "empty_bucket", "s3:deleteobjects"],
        "name": "Destructive Operation: S3 Bucket Destruction",
        "mitre": "AML.T0052",
        "risk": 98,
    },
    # Database Drops
    {
        "actions": ["rds:deletedbinstance", "drop_database", "drop_table", "delete_db_cluster"],
        "name": "Destructive Operation: Database Deletion",
        "mitre": "AML.T0052",
        "risk": 99,
    },
    # Privilege Escalation
    {
        "actions": ["iam:createaccesskey", "iam:attachrolepolicy", "iam:createuser", "iam:putrolepolicy"],
        "name": "Privilege Escalation: Unauthorized IAM Modification",
        "mitre": "AML.T0053",
        "risk": 100,
    },
]


def inspect_text_for_injection(text: str) -> List[tuple]:
    """Scans freeform text or prompt strings for prompt injection signatures."""
    matches = []
    for pattern, description, mitre in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, text):
            matches.append((description, mitre, pattern))
    return matches


def sanitize_and_inspect_payload(payload: Dict[str, Any]) -> SanitizerResult:
    """
    Performs deep inspection of the tool-call payload.
    Returns a SanitizerResult indicating whether the action was approved, sanitized, or blocked.
    """
    flagged = []
    risk = 0
    threat_details = []
    mitre_tech = None

    # 1. Inspect all string values in payload recursively for prompt injection
    def scan_dict_strings(obj: Any):
        nonlocal risk, mitre_tech
        if isinstance(obj, str):
            hits = inspect_text_for_injection(obj)
            for desc, mitre, pat in hits:
                flagged.append(f"{desc} [pattern: {pat}]")
                threat_details.append(desc)
                risk = max(risk, 90)
                mitre_tech = mitre
        elif isinstance(obj, dict):
            for v in obj.values():
                scan_dict_strings(v)
        elif isinstance(obj, list):
            for item in obj:
                scan_dict_strings(item)

    scan_dict_strings(payload)

    # 2. Inspect tool action and parameters against dangerous cloud patterns
    action_raw = str(payload.get("action") or payload.get("tool") or payload.get("name") or "").lower()

    for rule in DANGEROUS_TOOL_PATTERNS:
        if action_raw in rule["actions"]:
            # Specific check for KMS Decrypt wildcard
            if "kms" in action_raw:
                key_id = str(payload.get("key_id") or payload.get("key") or payload.get("resource") or "").strip()
                if not key_id or key_id in rule["wildcard_keys"] or "*" in key_id:
                    risk = max(risk, rule["risk"])
                    flagged.append(f"{rule['name']} (Key: '{key_id}')")
                    threat_details.append(rule["name"])
                    mitre_tech = rule["mitre"]
            else:
                risk = max(risk, rule["risk"])
                flagged.append(rule["name"])
                threat_details.append(rule["name"])
                mitre_tech = rule["mitre"]

    # 3. Check for shell command injection inside tool args
    args_str = str(payload)
    if any(c in args_str for c in ["; rm -rf", "| bash", "| sh", "wget http", "curl http://evil", "nc -e"]):
        risk = 100
        flagged.append("Remote Code Execution / Reverse Shell Injection")
        threat_details.append("RCE payload detected in tool parameters")
        mitre_tech = "AML.T0056"

    # Decision Matrix
    if risk >= 75:
        # High risk -> BLOCK request immediately
        return SanitizerResult(
            is_anomaly=True,
            is_blocked=True,
            risk_score=risk,
            anomaly_type="CRITICAL_THREAT_BLOCKED",
            threat_details="; ".join(threat_details) if threat_details else "Unsafe payload detected",
            mitre_atlas_technique=mitre_tech or "AML.T0054",
            flagged_patterns=flagged,
            sanitized_payload=None,
        )

    elif risk > 30:
        # Medium risk -> STRIP dangerous parameters and allow benign portion if safe
        sanitized = dict(payload)
        # Strip potential query parameter overrides
        sanitized.pop("bypass_cache", None)
        sanitized.pop("debug_override", None)
        return SanitizerResult(
            is_anomaly=True,
            is_blocked=False,
            risk_score=risk,
            anomaly_type="PARAM_STRIPPED_WARNING",
            threat_details="; ".join(threat_details),
            mitre_atlas_technique=mitre_tech,
            flagged_patterns=flagged,
            sanitized_payload=sanitized,
        )

    # Clean payload
    return SanitizerResult(
        is_anomaly=False,
        is_blocked=False,
        risk_score=0,
        anomaly_type=None,
        threat_details="Payload passed all heuristic and regex security filters.",
        mitre_atlas_technique=None,
        flagged_patterns=[],
        sanitized_payload=payload,
    )
