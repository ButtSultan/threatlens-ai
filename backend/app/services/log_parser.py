"""
ThreatLens AI - Log Parser Service
Parses JSON, CSV, and TXT log files into normalized dictionaries.
"""

import csv
import io
import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class LogParserService:
    """
    Parses raw log content (JSON, CSV, TXT/Syslog) into
    normalized dictionaries for threat detection.
    """

    def parse(self, content: str, log_type: str) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Parse log content. Returns (parsed_logs, errors).
        log_type: 'json', 'csv', 'txt'
        """
        log_type = log_type.lower().strip(".")
        errors: List[str] = []

        try:
            if log_type == "json":
                return self._parse_json(content, errors)
            elif log_type == "csv":
                return self._parse_csv(content, errors)
            else:
                return self._parse_txt(content, errors)
        except Exception as e:
            logger.error("Log parsing failed", extra={"error": str(e), "log_type": log_type})
            errors.append(f"Fatal parsing error: {str(e)}")
            return [], errors

    def _parse_json(self, content: str, errors: List[str]) -> Tuple[List[Dict], List[str]]:
        """Parse JSON log files. Supports both JSON arrays and NDJSON (one JSON per line)."""
        parsed = []
        content = content.strip()

        # Try as JSON array first
        if content.startswith("["):
            try:
                entries = json.loads(content)
                if isinstance(entries, list):
                    for i, entry in enumerate(entries):
                        if isinstance(entry, dict):
                            parsed.append(self._normalize(entry))
                        else:
                            errors.append(f"Line {i}: Not a JSON object")
                    return parsed, errors
            except json.JSONDecodeError:
                pass

        # Try NDJSON (newline-delimited JSON)
        for i, line in enumerate(content.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if isinstance(entry, dict):
                    parsed.append(self._normalize(entry))
            except json.JSONDecodeError as e:
                errors.append(f"Line {i+1}: JSON parse error - {str(e)[:50]}")

        return parsed, errors

    def _parse_csv(self, content: str, errors: List[str]) -> Tuple[List[Dict], List[str]]:
        """Parse CSV log files with automatic header detection."""
        parsed = []
        reader = csv.DictReader(io.StringIO(content))
        try:
            for i, row in enumerate(reader):
                try:
                    parsed.append(self._normalize(dict(row)))
                except Exception as e:
                    errors.append(f"Row {i+2}: {str(e)[:50]}")
        except csv.Error as e:
            errors.append(f"CSV error: {str(e)}")
        return parsed, errors

    def _parse_txt(self, content: str, errors: List[str]) -> Tuple[List[Dict], List[str]]:
        """
        Parse plain text / syslog format.
        Extracts common syslog fields and key=value pairs.
        """
        parsed = []
        for i, line in enumerate(content.splitlines()):
            line = line.strip()
            if not line:
                continue
            entry = self._parse_syslog_line(line)
            if entry:
                parsed.append(self._normalize(entry))
            else:
                # Store raw line as minimal log entry
                parsed.append({"raw_message": line, "line_number": i + 1})
        return parsed, errors

    def _parse_syslog_line(self, line: str) -> Optional[Dict]:
        """Attempt to parse a syslog-format line."""
        # Standard syslog: Jan 15 10:30:00 hostname process[pid]: message
        syslog_pattern = re.compile(
            r'^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+'
            r'(?P<hostname>\S+)\s+'
            r'(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+'
            r'(?P<message>.+)$'
        )
        m = syslog_pattern.match(line)
        if m:
            entry = m.groupdict()
            # Extract key=value pairs from message
            kv_pairs = self._extract_kv_pairs(entry.get("message", ""))
            entry.update(kv_pairs)
            return entry

        # W3C / IIS log format
        if line.startswith("#"):
            return None

        # Generic key=value line
        kv = self._extract_kv_pairs(line)
        if kv:
            kv["raw_message"] = line
            return kv

        return {"raw_message": line}

    def _extract_kv_pairs(self, text: str) -> Dict[str, str]:
        """Extract key=value and key="value" pairs from text."""
        pattern = re.compile(r'(\w[\w\-\.]*)\s*=\s*"([^"]*?)"|(\w[\w\-\.]*)\s*=\s*(\S+)')
        result = {}
        for m in pattern.finditer(text):
            if m.group(1):
                result[m.group(1).lower()] = m.group(2)
            elif m.group(3):
                result[m.group(3).lower()] = m.group(4)
        return result

    def _normalize(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a parsed log entry to a common field schema.
        Maps vendor-specific field names to standard names.
        """
        normalized = dict(entry)

        # Source IP normalization
        for field in ["src_ip", "srcip", "source", "src", "clientip", "remote_addr", "remote_host"]:
            if field in entry and not normalized.get("source_ip"):
                normalized["source_ip"] = str(entry[field])

        # Username normalization
        for field in ["user", "account", "user_name", "login", "userid", "account_name", "subject_username"]:
            if field in entry and not normalized.get("username"):
                normalized["username"] = str(entry[field])

        # Hostname normalization
        for field in ["host", "computer", "machine", "workstation", "device", "computer_name"]:
            if field in entry and not normalized.get("hostname"):
                normalized["hostname"] = str(entry[field])

        # Destination IP
        for field in ["dst_ip", "dstip", "destination", "dest_ip", "server_ip"]:
            if field in entry and not normalized.get("destination_ip"):
                normalized["destination_ip"] = str(entry[field])

        # Event type
        for field in ["event", "action", "event_type", "type", "category", "eventid", "event_id"]:
            if field in entry and not normalized.get("event_type"):
                normalized["event_type"] = str(entry[field])

        # Timestamp normalization
        for field in ["time", "datetime", "@timestamp", "date", "timestamp", "log_time"]:
            if field in entry and not normalized.get("timestamp"):
                try:
                    ts = entry[field]
                    if isinstance(ts, str):
                        normalized["timestamp"] = ts
                except Exception:
                    pass

        return normalized
