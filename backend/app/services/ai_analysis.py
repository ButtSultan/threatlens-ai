"""
ThreatLens AI - AI Analysis Module
Generates threat summaries, severity assessments, attack explanations,
and recommended remediation actions using rule-based + template intelligence.
This module is designed to be swapped for an LLM when available.
"""

import logging
from typing import Dict, List, Optional

from app.models.models import SeverityLevel
from app.services.detection_engine import DetectionResult

logger = logging.getLogger(__name__)


# Detailed knowledge base for each detection type
THREAT_KNOWLEDGE_BASE: Dict[str, Dict] = {
    "brute_force_login": {
        "attack_explanation": (
            "A brute-force attack involves systematically trying many passwords or "
            "passphrases with the hope of eventually guessing correctly. The attacker "
            "typically automates this process, sending thousands of login attempts against "
            "target accounts. This can lead to account lockout, service disruption, or "
            "successful unauthorized access if a weak password is in use."
        ),
        "recommendations": [
            "Immediately block the source IP at the perimeter firewall and WAF.",
            "Enable account lockout policy (e.g., lock after 5 failed attempts).",
            "Force password reset for targeted accounts as a precaution.",
            "Enable multi-factor authentication (MFA) for all user accounts.",
            "Review authentication logs for any successful logins from the attacker IP.",
            "Consider deploying CAPTCHA or adaptive authentication.",
            "Alert the affected users and IT security team.",
        ],
        "analyst_notes": "Verify whether any login succeeded. Check for lateral movement post-compromise.",
    },
    "password_spraying": {
        "attack_explanation": (
            "Password spraying is a low-and-slow brute-force technique where the attacker "
            "uses a small number of commonly used passwords against many accounts, avoiding "
            "account lockout thresholds. This is effective in environments with weak password "
            "policies and without adaptive authentication controls."
        ),
        "recommendations": [
            "Enforce strong password policies and ban commonly used passwords.",
            "Deploy MFA for all accounts, especially privileged ones.",
            "Block or rate-limit authentication attempts from suspicious IPs.",
            "Review accounts for successful authentications matching spray window.",
            "Correlate with Azure AD / identity provider sign-in logs.",
            "Implement Conditional Access policies based on risk scores.",
        ],
        "analyst_notes": "Spray attacks are often the first stage of APT intrusions. Escalate if MFA is not enforced.",
    },
    "privilege_escalation": {
        "attack_explanation": (
            "Privilege escalation occurs when an attacker gains elevated permissions beyond "
            "what was initially granted. This may involve exploiting OS vulnerabilities, "
            "misconfigured sudo rules, unpatched services, or abusing legitimate admin tools. "
            "Once elevated, attackers can persist, move laterally, and access sensitive data."
        ),
        "recommendations": [
            "Immediately isolate the affected endpoint(s) from the network.",
            "Audit all privileged group memberships and recently added admin accounts.",
            "Review sudo/sudoers files and Windows privilege assignments.",
            "Apply principle of least privilege across all service and user accounts.",
            "Patch operating systems and applications to latest versions.",
            "Enable and review Windows Security Event ID 4672 (Special Logon).",
            "Deploy EDR solutions to detect and block escalation attempts.",
        ],
        "analyst_notes": "Check if escalation succeeded. Review subsequent actions of the account post-escalation.",
    },
    "suspicious_powershell": {
        "attack_explanation": (
            "Attackers frequently abuse PowerShell for fileless malware execution, "
            "downloading payloads from the internet (download cradles), and running encoded "
            "commands to evade AV detection. Common techniques include Invoke-Expression, "
            "-EncodedCommand flags, and reflective DLL injection via PowerShell scripts."
        ),
        "recommendations": [
            "Enable PowerShell Script Block Logging (Event ID 4104) and Transcription.",
            "Restrict PowerShell to Constrained Language Mode where possible.",
            "Block PowerShell execution for non-administrative users via AppLocker/WDAC.",
            "Submit suspicious PowerShell commands to threat intelligence platforms.",
            "Scan affected hosts with up-to-date AV/EDR for payload artifacts.",
            "Review network connections made during the PowerShell execution window.",
            "Isolate affected systems if active payload execution is confirmed.",
        ],
        "analyst_notes": "Decode any Base64-encoded commands for further analysis. Look for C2 callback indicators.",
    },
    "credential_access": {
        "attack_explanation": (
            "Credential dumping involves extracting authentication credentials (hashes, "
            "plaintext passwords, Kerberos tickets) from OS memory (LSASS), registry hives "
            "(SAM, SECURITY), or Active Directory (NTDS.dit). Tools like Mimikatz, "
            "Secretsdump, and ProcDump are commonly used. Compromised credentials enable "
            "lateral movement and domain compromise."
        ),
        "recommendations": [
            "Immediately reset passwords for all potentially compromised accounts.",
            "Enable Windows Credential Guard to protect LSASS.",
            "Deploy Protected Users security group for privileged accounts.",
            "Block LSASS access using Attack Surface Reduction (ASR) rules.",
            "Audit use of ProcDump, Mimikatz, and similar tools via EDR.",
            "Rotate all service account credentials and Kerberos tickets (krbtgt).",
            "Conduct a full Active Directory security assessment.",
            "Check for Golden/Silver Ticket indicators in Kerberos logs.",
        ],
        "analyst_notes": "CRITICAL: Assume domain compromise. Engage IR team immediately. Preserve forensic evidence.",
    },
    "reconnaissance": {
        "attack_explanation": (
            "Network reconnaissance involves scanning for open ports, running services, "
            "and potential vulnerabilities before launching an attack. Port scanning, "
            "OS fingerprinting, and service enumeration are hallmarks of this phase. "
            "This is typically the first phase of the cyber kill chain."
        ),
        "recommendations": [
            "Block the scanning IP at the firewall/IDS level.",
            "Review firewall rules and ensure unnecessary ports are closed.",
            "Enable IDS/IPS signatures for port scan detection (Nmap, Masscan).",
            "Conduct vulnerability assessment on discovered open services.",
            "Alert network operations team to monitor for follow-up exploitation attempts.",
            "Review exposed services for unnecessary internet-facing exposure.",
        ],
        "analyst_notes": "Reconnaissance often precedes exploitation. Monitor for follow-up attack activity from same IP ranges.",
    },
    "impossible_travel": {
        "attack_explanation": (
            "Impossible travel is an anomaly where a user account authenticates from "
            "geographically distant locations within a timeframe that is physically "
            "impossible. This strongly suggests account compromise or credential sharing. "
            "Common causes include VPN exits, proxy use, or actual account takeover."
        ),
        "recommendations": [
            "Immediately suspend the affected user account pending investigation.",
            "Contact the user through an out-of-band channel to verify legitimacy.",
            "Force MFA re-enrollment for the account.",
            "Review all actions performed by the account during the anomaly window.",
            "Check for OAuth token or session hijacking indicators.",
            "Audit connected third-party applications for the account.",
            "Enable Continuous Access Evaluation (CAE) if on Microsoft/Azure platform.",
        ],
        "analyst_notes": "Rule out VPN/proxy use before confirming compromise. Verify with the user directly.",
    },
}

SEVERITY_COLORS = {
    SeverityLevel.CRITICAL: "🔴",
    SeverityLevel.HIGH: "🟠",
    SeverityLevel.MEDIUM: "🟡",
    SeverityLevel.LOW: "🟢",
    SeverityLevel.INFO: "⚪",
}


class AIAnalysisService:
    """
    AI Analysis module that generates human-readable threat summaries,
    severity assessments, attack explanations, and remediation recommendations.
    """

    def analyze_detection(self, detection: DetectionResult) -> Dict:
        """
        Produce a full AI analysis report for a single detection.
        Returns dict with summary, explanation, recommendations, and analyst notes.
        """
        kb_entry = THREAT_KNOWLEDGE_BASE.get(detection.detection_type, {})

        summary = self._generate_summary(detection)
        explanation = kb_entry.get(
            "attack_explanation",
            f"Suspicious activity of type '{detection.detection_type}' was detected. "
            "Manual analysis is recommended to determine the full scope and impact.",
        )
        recommendations = kb_entry.get("recommendations", [
            "Investigate the affected systems immediately.",
            "Review authentication and system logs for the affected timeframe.",
            "Isolate affected assets if active compromise is suspected.",
            "Escalate to senior SOC analyst or incident response team.",
        ])
        analyst_notes = kb_entry.get(
            "analyst_notes",
            "Review detection context carefully before taking action.",
        )

        return {
            "threat_summary": summary,
            "severity": detection.severity.value,
            "severity_icon": SEVERITY_COLORS.get(detection.severity, "⚪"),
            "attack_explanation": explanation,
            "recommended_actions": recommendations,
            "analyst_notes": analyst_notes,
            "confidence_score": detection.confidence_score,
            "affected_scope": {
                "source_ips": detection.source_ips,
                "affected_users": detection.affected_users,
                "affected_hosts": detection.affected_hosts,
                "event_count": detection.event_count,
            },
            "mitre_techniques": detection.get_mitre_mappings(),
        }

    def _generate_summary(self, detection: DetectionResult) -> str:
        """Generate a concise executive summary for the detection."""
        severity_label = detection.severity.value.upper()
        detection_label = detection.detection_type.replace("_", " ").title()

        parts = [f"[{severity_label}] {detection_label} Detected."]

        if detection.source_ips:
            parts.append(f"Source: {', '.join(detection.source_ips[:3])}")
        if detection.affected_users:
            parts.append(f"Affected users: {', '.join(detection.affected_users[:3])}")
        if detection.event_count > 1:
            parts.append(f"Total events: {detection.event_count}")
        parts.append(f"Confidence: {detection.confidence_score:.0%}")

        return " | ".join(parts)

    def generate_executive_summary(self, detections: List[DetectionResult]) -> str:
        """Generate an executive-level summary for a collection of detections."""
        if not detections:
            return "No threat detections found in the analyzed log batch."

        critical = sum(1 for d in detections if d.severity == SeverityLevel.CRITICAL)
        high = sum(1 for d in detections if d.severity == SeverityLevel.HIGH)
        medium = sum(1 for d in detections if d.severity == SeverityLevel.MEDIUM)
        types = list({d.detection_type for d in detections})

        summary = (
            f"Security analysis of the submitted log batch identified {len(detections)} "
            f"threat detection(s): {critical} Critical, {high} High, {medium} Medium severity. "
            f"Detection types include: {', '.join(t.replace('_', ' ').title() for t in types)}. "
        )

        if critical > 0:
            summary += "IMMEDIATE ACTION REQUIRED: Critical severity detections indicate active or imminent compromise. "
        elif high > 0:
            summary += "Prompt investigation is strongly recommended for high-severity findings. "

        return summary
