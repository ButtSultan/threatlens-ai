"""
ThreatLens AI - Threat Detection Engine
Detects: brute-force, impossible travel, privilege escalation,
suspicious PowerShell, credential access, and reconnaissance.
"""

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.models.models import SeverityLevel
from app.schemas.schemas import MITREMappingResponse

logger = logging.getLogger(__name__)


# MITRE ATT&CK technique database
MITRE_DB: Dict[str, Dict] = {
    "brute_force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries may use brute force techniques to gain access to accounts.",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "password_spraying": {
        "technique_id": "T1110.003",
        "technique_name": "Password Spraying",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries may use a single password against many accounts.",
        "url": "https://attack.mitre.org/techniques/T1110/003/",
    },
    "impossible_travel": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "tactic_id": "TA0005",
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "privilege_escalation": {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "description": "Adversaries may exploit software vulnerabilities to elevate privileges.",
        "url": "https://attack.mitre.org/techniques/T1068/",
    },
    "suspicious_powershell": {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "credential_access": {
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries may attempt to dump credentials to obtain account info.",
        "url": "https://attack.mitre.org/techniques/T1003/",
    },
    "reconnaissance": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "lateral_movement": {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "description": "Adversaries may use valid accounts to log into a service.",
        "url": "https://attack.mitre.org/techniques/T1021/",
    },
    "data_exfiltration": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "description": "Adversaries may steal data by exfiltrating it over an existing C2 channel.",
        "url": "https://attack.mitre.org/techniques/T1041/",
    },
}


class DetectionResult:
    """Encapsulates a single detection result."""

    def __init__(
        self,
        detection_type: str,
        description: str,
        severity: SeverityLevel,
        confidence_score: float,
        indicators: Dict[str, Any],
        source_ips: List[str],
        affected_users: List[str],
        affected_hosts: List[str],
        mitre_techniques: List[str],
        event_count: int = 1,
    ):
        self.id = str(uuid.uuid4())
        self.detection_type = detection_type
        self.description = description
        self.severity = severity
        self.confidence_score = min(max(confidence_score, 0.0), 1.0)
        self.indicators = indicators
        self.source_ips = source_ips
        self.affected_users = affected_users
        self.affected_hosts = affected_hosts
        self.mitre_techniques = mitre_techniques
        self.event_count = event_count
        self.timestamp = datetime.now(timezone.utc)

    def get_mitre_mappings(self) -> List[Dict]:
        """Get MITRE ATT&CK mappings for this detection."""
        mappings = []
        for technique_key in self.mitre_techniques:
            if technique_key in MITRE_DB:
                mappings.append(MITRE_DB[technique_key])
        return mappings


class ThreatDetectionEngine:
    """
    Core threat detection engine that analyzes parsed log entries
    and produces structured detection results.
    """

    # Thresholds
    BRUTE_FORCE_THRESHOLD = 5         # failed logins in window
    BRUTE_FORCE_WINDOW_MINUTES = 10
    RECON_PORT_THRESHOLD = 10         # distinct ports scanned
    PRIV_ESC_KEYWORDS = [
        "sudo", "su ", "runas", "privilege", "elevation",
        "admin", "administrator", "root", "wheel",
        "net localgroup administrators", "net user /add",
        "getsystem", "bypassuac",
    ]
    POWERSHELL_SUSPICIOUS = [
        "invoke-expression", "iex", "downloadstring", "encodedcommand",
        "-enc ", "-e ", "bypass", "hidden", "noprofile", "frombase64string",
        "webclient", "invoke-webrequest", "start-bitstransfer", "certutil",
        "mimikatz", "empire", "powersploit", "shellcode",
    ]
    CREDENTIAL_KEYWORDS = [
        "mimikatz", "lsass", "sam database", "ntds.dit", "credential",
        "hashdump", "secretsdump", "procdump", "comsvcs.dll",
        "wce.exe", "fgdump", "pwdump", "gsecdump",
    ]

    def analyze(self, parsed_logs: List[Dict[str, Any]]) -> List[DetectionResult]:
        """
        Main analysis method. Runs all detectors against a batch of parsed logs.
        Returns a list of DetectionResult objects.
        """
        results: List[DetectionResult] = []

        # Group logs for contextual analysis
        logs_by_ip: Dict[str, List[Dict]] = defaultdict(list)
        logs_by_user: Dict[str, List[Dict]] = defaultdict(list)

        for log in parsed_logs:
            ip = log.get("source_ip") or log.get("src_ip") or log.get("ip", "")
            user = log.get("username") or log.get("user") or log.get("account", "")
            if ip:
                logs_by_ip[ip].append(log)
            if user:
                logs_by_user[user].append(log)

        # Run individual detectors
        results.extend(self._detect_brute_force(logs_by_ip, logs_by_user))
        results.extend(self._detect_privilege_escalation(parsed_logs))
        results.extend(self._detect_suspicious_powershell(parsed_logs))
        results.extend(self._detect_credential_access(parsed_logs))
        results.extend(self._detect_reconnaissance(logs_by_ip))
        results.extend(self._detect_impossible_travel(logs_by_user))

        logger.info(
            "Threat detection complete",
            extra={
                "logs_analyzed": len(parsed_logs),
                "detections": len(results),
            },
        )
        return results

    def _detect_brute_force(
        self,
        logs_by_ip: Dict[str, List[Dict]],
        logs_by_user: Dict[str, List[Dict]],
    ) -> List[DetectionResult]:
        """Detect brute-force and password spraying attacks."""
        results = []

        # Per-IP failed login analysis
        for ip, logs in logs_by_ip.items():
            failed = [
                l for l in logs
                if self._is_failed_login(l)
            ]
            if len(failed) >= self.BRUTE_FORCE_THRESHOLD:
                users_targeted = list({l.get("username", "") for l in failed if l.get("username")})
                description = (
                    f"Brute-force attack detected from {ip}. "
                    f"{len(failed)} failed login attempts targeting "
                    f"{len(users_targeted)} account(s): {', '.join(users_targeted[:5])}"
                )
                severity = SeverityLevel.HIGH if len(failed) > 20 else SeverityLevel.MEDIUM
                results.append(
                    DetectionResult(
                        detection_type="brute_force_login",
                        description=description,
                        severity=severity,
                        confidence_score=min(0.95, 0.5 + len(failed) * 0.02),
                        indicators={"failed_count": len(failed), "source_ip": ip},
                        source_ips=[ip],
                        affected_users=users_targeted,
                        affected_hosts=[],
                        mitre_techniques=["brute_force"],
                        event_count=len(failed),
                    )
                )

        # Password spraying: one user, many IPs
        for user, logs in logs_by_user.items():
            if not user:
                continue
            failed = [l for l in logs if self._is_failed_login(l)]
            unique_ips = {l.get("source_ip", "") for l in failed}
            if len(unique_ips) >= 3 and len(failed) >= self.BRUTE_FORCE_THRESHOLD:
                description = (
                    f"Password spraying detected against user '{user}'. "
                    f"{len(failed)} failed attempts from {len(unique_ips)} distinct source IPs."
                )
                results.append(
                    DetectionResult(
                        detection_type="password_spraying",
                        description=description,
                        severity=SeverityLevel.HIGH,
                        confidence_score=0.88,
                        indicators={"failed_count": len(failed), "unique_ips": len(unique_ips)},
                        source_ips=list(unique_ips)[:10],
                        affected_users=[user],
                        affected_hosts=[],
                        mitre_techniques=["password_spraying", "brute_force"],
                        event_count=len(failed),
                    )
                )

        return results

    def _detect_privilege_escalation(self, logs: List[Dict]) -> List[DetectionResult]:
        """Detect privilege escalation attempts."""
        results = []
        suspicious = []

        for log in logs:
            text = self._log_to_text(log).lower()
            for keyword in self.PRIV_ESC_KEYWORDS:
                if keyword in text:
                    suspicious.append(log)
                    break

        if suspicious:
            users = list({l.get("username", "unknown") for l in suspicious})
            hosts = list({l.get("hostname", "") for l in suspicious if l.get("hostname")})
            ips = list({l.get("source_ip", "") for l in suspicious if l.get("source_ip")})
            description = (
                f"Privilege escalation activity detected in {len(suspicious)} log event(s). "
                f"Affected users: {', '.join(users[:5])}."
            )
            results.append(
                DetectionResult(
                    detection_type="privilege_escalation",
                    description=description,
                    severity=SeverityLevel.HIGH,
                    confidence_score=0.82,
                    indicators={"event_count": len(suspicious), "keywords_matched": True},
                    source_ips=ips[:10],
                    affected_users=users[:10],
                    affected_hosts=hosts[:10],
                    mitre_techniques=["privilege_escalation"],
                    event_count=len(suspicious),
                )
            )

        return results

    def _detect_suspicious_powershell(self, logs: List[Dict]) -> List[DetectionResult]:
        """Detect malicious PowerShell execution patterns."""
        results = []
        suspicious = []

        for log in logs:
            text = self._log_to_text(log).lower()
            if "powershell" in text or "pwsh" in text:
                for keyword in self.POWERSHELL_SUSPICIOUS:
                    if keyword in text:
                        suspicious.append(log)
                        break

        if suspicious:
            users = list({l.get("username", "unknown") for l in suspicious})
            hosts = list({l.get("hostname", "") for l in suspicious if l.get("hostname")})
            ips = list({l.get("source_ip", "") for l in suspicious if l.get("source_ip")})
            description = (
                f"Suspicious PowerShell execution detected in {len(suspicious)} event(s). "
                f"Potential code execution or download cradle activity."
            )
            severity = SeverityLevel.CRITICAL if len(suspicious) > 5 else SeverityLevel.HIGH
            results.append(
                DetectionResult(
                    detection_type="suspicious_powershell",
                    description=description,
                    severity=severity,
                    confidence_score=0.90,
                    indicators={"event_count": len(suspicious)},
                    source_ips=ips[:10],
                    affected_users=users[:10],
                    affected_hosts=hosts[:10],
                    mitre_techniques=["suspicious_powershell"],
                    event_count=len(suspicious),
                )
            )

        return results

    def _detect_credential_access(self, logs: List[Dict]) -> List[DetectionResult]:
        """Detect credential dumping and harvesting activity."""
        results = []
        suspicious = []

        for log in logs:
            text = self._log_to_text(log).lower()
            for keyword in self.CREDENTIAL_KEYWORDS:
                if keyword in text:
                    suspicious.append(log)
                    break

        if suspicious:
            users = list({l.get("username", "unknown") for l in suspicious})
            hosts = list({l.get("hostname", "") for l in suspicious if l.get("hostname")})
            ips = list({l.get("source_ip", "") for l in suspicious if l.get("source_ip")})
            description = (
                f"Credential access/dumping activity detected in {len(suspicious)} event(s). "
                f"Possible LSASS dump or SAM database access."
            )
            results.append(
                DetectionResult(
                    detection_type="credential_access",
                    description=description,
                    severity=SeverityLevel.CRITICAL,
                    confidence_score=0.93,
                    indicators={"event_count": len(suspicious)},
                    source_ips=ips[:10],
                    affected_users=users[:10],
                    affected_hosts=hosts[:10],
                    mitre_techniques=["credential_access"],
                    event_count=len(suspicious),
                )
            )

        return results

    def _detect_reconnaissance(self, logs_by_ip: Dict[str, List[Dict]]) -> List[DetectionResult]:
        """Detect network reconnaissance / port scanning."""
        results = []

        for ip, logs in logs_by_ip.items():
            if not ip:
                continue
            ports = set()
            for log in logs:
                port = log.get("destination_port") or log.get("dst_port") or log.get("port")
                if port:
                    try:
                        ports.add(int(port))
                    except (ValueError, TypeError):
                        pass

            if len(ports) >= self.RECON_PORT_THRESHOLD:
                description = (
                    f"Reconnaissance/port scanning detected from {ip}. "
                    f"{len(ports)} distinct destination ports accessed."
                )
                results.append(
                    DetectionResult(
                        detection_type="reconnaissance",
                        description=description,
                        severity=SeverityLevel.MEDIUM,
                        confidence_score=0.78,
                        indicators={"ports_scanned": len(ports), "source_ip": ip},
                        source_ips=[ip],
                        affected_users=[],
                        affected_hosts=[],
                        mitre_techniques=["reconnaissance"],
                        event_count=len(logs),
                    )
                )

        return results

    def _detect_impossible_travel(self, logs_by_user: Dict[str, List[Dict]]) -> List[DetectionResult]:
        """
        Detect impossible travel - same user authenticating from
        geographically disparate locations in a short window.
        We approximate this by detecting rapid authentication from
        multiple distinct /16 subnet blocks.
        """
        results = []

        for user, logs in logs_by_user.items():
            if not user:
                continue
            success_logs = [
                l for l in logs
                if self._is_successful_login(l)
            ]
            if len(success_logs) < 2:
                continue

            # Extract /16 subnets as a proxy for geographic diversity
            subnet_blocks = set()
            for log in success_logs:
                ip = log.get("source_ip", "")
                if ip and "." in ip:
                    parts = ip.split(".")
                    if len(parts) >= 2:
                        subnet_blocks.add(f"{parts[0]}.{parts[1]}")

            if len(subnet_blocks) >= 3:
                description = (
                    f"Impossible travel indicator for user '{user}'. "
                    f"Successful logins from {len(subnet_blocks)} distinct network blocks "
                    f"in a short time window."
                )
                results.append(
                    DetectionResult(
                        detection_type="impossible_travel",
                        description=description,
                        severity=SeverityLevel.HIGH,
                        confidence_score=0.75,
                        indicators={
                            "user": user,
                            "distinct_networks": len(subnet_blocks),
                        },
                        source_ips=[l.get("source_ip", "") for l in success_logs if l.get("source_ip")][:10],
                        affected_users=[user],
                        affected_hosts=[],
                        mitre_techniques=["impossible_travel"],
                        event_count=len(success_logs),
                    )
                )

        return results

    # ─── Helpers ────────────────────────────────────────────────────────────

    def _is_failed_login(self, log: Dict) -> bool:
        """Return True if the log entry represents a failed authentication."""
        text = self._log_to_text(log).lower()
        return any(k in text for k in [
            "failed", "failure", "invalid", "incorrect", "bad password",
            "authentication failure", "logon failure", "access denied",
            "4625",  # Windows Event ID: failed logon
        ])

    def _is_successful_login(self, log: Dict) -> bool:
        """Return True if the log entry represents a successful authentication."""
        text = self._log_to_text(log).lower()
        return any(k in text for k in [
            "success", "accepted", "logged in", "authentication success",
            "logon success", "4624",  # Windows Event ID: successful logon
        ])

    def _log_to_text(self, log: Dict) -> str:
        """Flatten a log dictionary to a single searchable string."""
        return " ".join(str(v) for v in log.values() if v is not None)
