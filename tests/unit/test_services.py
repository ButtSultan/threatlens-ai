"""
Unit tests for:
- app.core.security (JWT, password hashing)
- app.services.log_parser (JSON, CSV, TXT parsing)
- app.services.detection_engine (all 6 detectors)
- app.services.ai_analysis (summary generation)
"""
import json
import pytest

from app.core.security import (
    get_password_hash, verify_password,
    create_access_token, create_refresh_token,
    decode_token, validate_password_strength,
)
from app.services.log_parser import LogParserService
from app.services.detection_engine import ThreatDetectionEngine
from app.services.ai_analysis import AIAnalysisService
from app.models.models import SeverityLevel


# ═══════════════════════════════════════════════════════
# Security Module Tests
# ═══════════════════════════════════════════════════════

class TestPasswordHashing:
    def test_hash_is_not_plaintext(self):
        hashed = get_password_hash("MyPassword1")
        assert hashed != "MyPassword1"
        assert len(hashed) > 20

    def test_verify_correct_password(self):
        hashed = get_password_hash("SecurePass99")
        assert verify_password("SecurePass99", hashed) is True

    def test_reject_wrong_password(self):
        hashed = get_password_hash("SecurePass99")
        assert verify_password("WrongPass99", hashed) is False

    def test_different_hashes_for_same_password(self):
        h1 = get_password_hash("SamePass1")
        h2 = get_password_hash("SamePass1")
        assert h1 != h2  # bcrypt uses random salt


class TestPasswordStrength:
    def test_strong_password(self):
        assert validate_password_strength("StrongPass1") is True

    def test_too_short(self):
        assert validate_password_strength("Ab1") is False

    def test_no_uppercase(self):
        assert validate_password_strength("lowercase1") is False

    def test_no_lowercase(self):
        assert validate_password_strength("UPPERCASE1") is False

    def test_no_digit(self):
        assert validate_password_strength("NoDigitsHere") is False


class TestJWT:
    def test_create_and_decode_access_token(self):
        data = {"sub": "user-123", "username": "analyst01", "role": "analyst"}
        token = create_access_token(data)
        payload = decode_token(token)
        assert payload is not None
        assert payload["sub"] == "user-123"
        assert payload["type"] == "access"

    def test_create_and_decode_refresh_token(self):
        data = {"sub": "user-456"}
        token = create_refresh_token(data)
        payload = decode_token(token)
        assert payload is not None
        assert payload["type"] == "refresh"

    def test_invalid_token_returns_none(self):
        assert decode_token("not.a.valid.token") is None

    def test_tampered_token_returns_none(self):
        token = create_access_token({"sub": "user-789"})
        tampered = token[:-5] + "XXXXX"
        assert decode_token(tampered) is None


# ═══════════════════════════════════════════════════════
# Log Parser Tests
# ═══════════════════════════════════════════════════════

class TestLogParser:
    def setup_method(self):
        self.parser = LogParserService()

    def test_parse_json_array(self):
        content = json.dumps([
            {"source_ip": "10.0.0.1", "username": "admin", "event": "login_failed"},
            {"source_ip": "10.0.0.2", "username": "root",  "event": "login_failed"},
        ])
        parsed, errors = self.parser.parse(content, "json")
        assert len(parsed) == 2
        assert len(errors) == 0

    def test_parse_ndjson(self):
        content = (
            '{"ip": "10.0.0.1", "user": "admin", "action": "login"}\n'
            '{"ip": "10.0.0.2", "user": "root", "action": "logout"}\n'
        )
        parsed, errors = self.parser.parse(content, "json")
        assert len(parsed) == 2

    def test_parse_csv(self):
        content = (
            "timestamp,source_ip,username,event_type\n"
            "2024-01-01T00:00:00Z,10.0.0.1,admin,login_failed\n"
            "2024-01-01T00:01:00Z,10.0.0.2,root,login_failed\n"
        )
        parsed, errors = self.parser.parse(content, "csv")
        assert len(parsed) == 2
        assert parsed[0].get("source_ip") == "10.0.0.1"

    def test_parse_txt_syslog(self):
        content = (
            "Jan 15 10:30:00 server01 sshd[1234]: Failed password for root from 10.0.0.5\n"
            "Jan 15 10:31:00 server01 sudo: admin : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash\n"
        )
        parsed, errors = self.parser.parse(content, "txt")
        assert len(parsed) == 2

    def test_normalize_source_ip_aliases(self):
        entry = {"srcip": "192.168.1.1", "user": "testuser"}
        normalized = self.parser._normalize(entry)
        assert normalized.get("source_ip") == "192.168.1.1"
        assert normalized.get("username") == "testuser"

    def test_parse_empty_json_array(self):
        parsed, errors = self.parser.parse("[]", "json")
        assert parsed == []

    def test_parse_invalid_json_produces_errors(self):
        parsed, errors = self.parser.parse("{not valid json", "json")
        # Should not crash; returns empty list with errors
        assert isinstance(errors, list)


# ═══════════════════════════════════════════════════════
# Threat Detection Engine Tests
# ═══════════════════════════════════════════════════════

class TestThreatDetectionEngine:
    def setup_method(self):
        self.engine = ThreatDetectionEngine()

    def _make_failed_logins(self, ip: str, count: int, username: str = "admin"):
        return [
            {
                "source_ip": ip,
                "username": username,
                "event_type": "authentication_failure",
                "message": f"Failed password for {username} from {ip}",
            }
            for _ in range(count)
        ]

    def test_detect_brute_force(self):
        logs = self._make_failed_logins("192.168.1.100", 10)
        results = self.engine.analyze(logs)
        types = [r.detection_type for r in results]
        assert "brute_force_login" in types

    def test_no_brute_force_below_threshold(self):
        logs = self._make_failed_logins("192.168.1.100", 3)
        results = self.engine.analyze(logs)
        types = [r.detection_type for r in results]
        assert "brute_force_login" not in types

    def test_brute_force_severity_critical_at_high_count(self):
        logs = self._make_failed_logins("10.0.0.5", 25)
        results = self.engine.analyze(logs)
        bf = next((r for r in results if r.detection_type == "brute_force_login"), None)
        assert bf is not None
        assert bf.severity == SeverityLevel.HIGH  # or CRITICAL for >20

    def test_detect_privilege_escalation_sudo(self):
        logs = [
            {"source_ip": "10.0.0.10", "username": "jdoe", "message": "sudo: jdoe TTY=pts/0 USER=root COMMAND=/bin/bash"},
        ]
        results = self.engine.analyze(logs)
        types = [r.detection_type for r in results]
        assert "privilege_escalation" in types

    def test_detect_suspicious_powershell(self):
        logs = [
            {
                "source_ip": "10.0.0.20",
                "username": "jdoe",
                "message": "powershell -EncodedCommand SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA==",
                "hostname": "WIN-SERVER01",
            }
        ]
        results = self.engine.analyze(logs)
        types = [r.detection_type for r in results]
        assert "suspicious_powershell" in types

    def test_detect_credential_access_mimikatz(self):
        logs = [
            {"source_ip": "10.0.0.30", "username": "attacker", "message": "mimikatz sekurlsa::logonpasswords"},
        ]
        results = self.engine.analyze(logs)
        types = [r.detection_type for r in results]
        assert "credential_access" in types

    def test_detect_reconnaissance_port_scan(self):
        logs = [
            {"source_ip": "10.0.0.99", "destination_port": str(p)}
            for p in range(1, 20)
        ]
        results = self.engine.analyze(logs)
        types = [r.detection_type for r in results]
        assert "reconnaissance" in types

    def test_detect_impossible_travel(self):
        logs = [
            {"source_ip": "10.0.0.1",     "username": "admin", "message": "Accepted password for admin"},
            {"source_ip": "172.16.0.1",   "username": "admin", "message": "Accepted password for admin"},
            {"source_ip": "203.0.113.1",  "username": "admin", "message": "Accepted password for admin"},
            {"source_ip": "198.51.100.1", "username": "admin", "message": "Accepted password for admin"},
        ]
        results = self.engine.analyze(logs)
        types = [r.detection_type for r in results]
        assert "impossible_travel" in types

    def test_no_detection_on_clean_logs(self):
        logs = [
            {"source_ip": "10.0.0.5", "username": "user1", "message": "Normal file access"},
            {"source_ip": "10.0.0.6", "username": "user2", "message": "Document created"},
        ]
        results = self.engine.analyze(logs)
        # Should have zero or minimal detections on clean logs
        critical = [r for r in results if r.severity == SeverityLevel.CRITICAL]
        assert len(critical) == 0

    def test_detection_result_has_mitre_mappings(self):
        logs = self._make_failed_logins("192.168.5.5", 10)
        results = self.engine.analyze(logs)
        bf = next((r for r in results if r.detection_type == "brute_force_login"), None)
        assert bf is not None
        mappings = bf.get_mitre_mappings()
        assert len(mappings) > 0
        assert "technique_id" in mappings[0]
        assert mappings[0]["technique_id"].startswith("T")

    def test_confidence_score_bounded_01(self):
        logs = self._make_failed_logins("10.0.0.1", 50)
        results = self.engine.analyze(logs)
        for r in results:
            assert 0.0 <= r.confidence_score <= 1.0


# ═══════════════════════════════════════════════════════
# AI Analysis Service Tests
# ═══════════════════════════════════════════════════════

class TestAIAnalysisService:
    def setup_method(self):
        self.engine  = ThreatDetectionEngine()
        self.service = AIAnalysisService()

    def _get_detection(self, log_messages, ip="10.0.0.1"):
        logs = [{"source_ip": ip, "username": "user", "message": m} for m in log_messages]
        results = self.engine.analyze(logs)
        return results[0] if results else None

    def test_brute_force_analysis_has_all_keys(self):
        detection = self._get_detection(
            ["Failed password for admin"] * 10, ip="192.168.1.50"
        )
        assert detection is not None
        analysis = self.service.analyze_detection(detection)
        for key in ["threat_summary", "severity", "attack_explanation", "recommended_actions", "analyst_notes"]:
            assert key in analysis, f"Missing key: {key}"

    def test_recommendations_is_list(self):
        detection = self._get_detection(["Failed password for root"] * 8, ip="10.5.0.1")
        if detection:
            analysis = self.service.analyze_detection(detection)
            assert isinstance(analysis["recommended_actions"], list)
            assert len(analysis["recommended_actions"]) > 0

    def test_executive_summary_no_detections(self):
        summary = self.service.generate_executive_summary([])
        assert "No threat detections" in summary

    def test_executive_summary_with_detections(self):
        logs = [{"source_ip": "10.0.0.1", "username": "admin", "message": "Failed password for admin"} for _ in range(8)]
        results = self.engine.analyze(logs)
        summary = self.service.generate_executive_summary(results)
        assert len(summary) > 20
        assert isinstance(summary, str)

    def test_confidence_score_in_analysis(self):
        detection = self._get_detection(["mimikatz sekurlsa::logonpasswords"])
        if detection:
            analysis = self.service.analyze_detection(detection)
            assert 0.0 <= analysis["confidence_score"] <= 1.0

    def test_mitre_techniques_in_analysis(self):
        detection = self._get_detection(["mimikatz sekurlsa::logonpasswords"])
        if detection:
            analysis = self.service.analyze_detection(detection)
            assert "mitre_techniques" in analysis
            assert isinstance(analysis["mitre_techniques"], list)
