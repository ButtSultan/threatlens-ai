"""
Unit tests for app.utils.helpers — pure utility functions.
No database or network calls required.
"""
import pytest
from app.utils.helpers import (
    generate_batch_id,
    generate_incident_number,
    is_valid_ip,
    is_private_ip,
    truncate_text,
    safe_json_loads,
    paginate,
    sanitize_filename,
    extract_ips_from_text,
    severity_to_priority,
    format_duration,
    mask_sensitive_field,
)


class TestGenerators:
    def test_batch_id_length(self):
        bid = generate_batch_id()
        assert len(bid) == 12
        assert bid.isalnum()

    def test_batch_id_unique(self):
        ids = {generate_batch_id() for _ in range(100)}
        assert len(ids) == 100  # All unique

    def test_incident_number_format(self):
        num = generate_incident_number()
        assert num.startswith("INC-")
        parts = num.split("-")
        assert len(parts) == 3
        assert len(parts[1]) == 8   # YYYYMMDD
        assert len(parts[2]) == 6   # hex suffix

    def test_incident_number_unique(self):
        nums = {generate_incident_number() for _ in range(50)}
        assert len(nums) == 50


class TestIPValidation:
    def test_valid_ipv4(self):
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("10.0.0.1") is True
        assert is_valid_ip("255.255.255.255") is True
        assert is_valid_ip("0.0.0.0") is True

    def test_valid_ipv6(self):
        assert is_valid_ip("::1") is True
        assert is_valid_ip("2001:db8::1") is True

    def test_invalid_ip(self):
        assert is_valid_ip("not-an-ip") is False
        assert is_valid_ip("256.0.0.1") is False
        assert is_valid_ip("") is False
        assert is_valid_ip("192.168.1") is False

    def test_private_ips(self):
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("127.0.0.1") is True

    def test_public_ips(self):
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("203.0.113.1") is False
        assert is_private_ip("1.1.1.1") is False

    def test_invalid_ip_not_private(self):
        assert is_private_ip("not-an-ip") is False


class TestTextUtilities:
    def test_truncate_short_text(self):
        text = "Short text"
        assert truncate_text(text, 100) == text

    def test_truncate_long_text(self):
        text = "A" * 600
        result = truncate_text(text, 500)
        assert len(result) == 500
        assert result.endswith("...")

    def test_truncate_empty_text(self):
        assert truncate_text("", 100) == ""
        assert truncate_text(None, 100) == ""

    def test_truncate_exact_length(self):
        text = "A" * 500
        assert truncate_text(text, 500) == text

    def test_safe_json_loads_valid(self):
        result = safe_json_loads('{"key": "value", "num": 42}')
        assert result == {"key": "value", "num": 42}

    def test_safe_json_loads_invalid(self):
        assert safe_json_loads("not json") is None
        assert safe_json_loads("{broken") is None
        assert safe_json_loads(None) is None
        assert safe_json_loads("") is None


class TestPagination:
    def test_single_page(self):
        result = paginate(10, 1, 50)
        assert result == {"total": 10, "page": 1, "page_size": 50, "pages": 1}

    def test_multiple_pages(self):
        result = paginate(105, 1, 50)
        assert result["pages"] == 3
        assert result["total"] == 105

    def test_exact_pages(self):
        result = paginate(100, 1, 50)
        assert result["pages"] == 2

    def test_zero_total(self):
        result = paginate(0, 1, 50)
        assert result["total"] == 0
        assert result["pages"] == 1  # At least 1 page

    def test_page_2(self):
        result = paginate(200, 2, 50)
        assert result["page"] == 2
        assert result["pages"] == 4


class TestFilenameUtils:
    def test_safe_filename_clean(self):
        assert sanitize_filename("security_logs.json") == "security_logs.json"

    def test_safe_filename_removes_special_chars(self):
        result = sanitize_filename("../../etc/passwd")
        assert ".." not in result
        assert "/" not in result

    def test_safe_filename_spaces(self):
        result = sanitize_filename("my log file.csv")
        assert " " not in result

    def test_safe_filename_max_length(self):
        long_name = "a" * 300 + ".txt"
        result = sanitize_filename(long_name)
        assert len(result) <= 255


class TestIPExtraction:
    def test_extract_single_ip(self):
        text = "Connection from 192.168.1.100 port 22"
        ips = extract_ips_from_text(text)
        assert "192.168.1.100" in ips

    def test_extract_multiple_ips(self):
        text = "Source: 10.0.0.1, Destination: 8.8.8.8, Gateway: 192.168.1.1"
        ips = extract_ips_from_text(text)
        assert len(ips) == 3
        assert "10.0.0.1" in ips
        assert "8.8.8.8" in ips

    def test_extract_no_ips(self):
        assert extract_ips_from_text("no IP addresses here") == []
        assert extract_ips_from_text("") == []

    def test_extract_deduplicates(self):
        text = "10.0.0.1 10.0.0.1 10.0.0.1"
        ips = extract_ips_from_text(text)
        assert len(ips) == 1


class TestSeverityPriority:
    def test_critical_is_highest_priority(self):
        assert severity_to_priority("critical") < severity_to_priority("high")
        assert severity_to_priority("high") < severity_to_priority("medium")
        assert severity_to_priority("medium") < severity_to_priority("low")
        assert severity_to_priority("low") < severity_to_priority("info")

    def test_case_insensitive(self):
        assert severity_to_priority("CRITICAL") == severity_to_priority("critical")
        assert severity_to_priority("HIGH") == severity_to_priority("high")

    def test_unknown_severity(self):
        assert severity_to_priority("unknown") == 99


class TestFormatDuration:
    def test_seconds(self):
        assert "s" in format_duration(45.5)
        assert "45.5s" == format_duration(45.5)

    def test_minutes(self):
        result = format_duration(90)
        assert "m" in result
        assert "1.5m" == result

    def test_hours(self):
        result = format_duration(7200)
        assert "h" in result
        assert "2.0h" == result


class TestMaskField:
    def test_mask_long_value(self):
        result = mask_sensitive_field("mysecretpassword", visible_chars=4)
        assert result.endswith("word")
        assert "*" in result

    def test_mask_short_value(self):
        result = mask_sensitive_field("ab", visible_chars=4)
        assert result == "****"

    def test_mask_empty(self):
        assert mask_sensitive_field("") == "****"
        assert mask_sensitive_field(None) == "****"
