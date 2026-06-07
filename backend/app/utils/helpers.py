"""
ThreatLens AI — Shared Utility Helpers
Reusable functions for pagination, date formatting, IP validation,
and other cross-cutting concerns.
"""

import ipaddress
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


def generate_batch_id() -> str:
    """Generate a short unique batch ID for log ingestion tracking."""
    return uuid.uuid4().hex[:12]


def generate_incident_number() -> str:
    """Generate a unique, human-readable incident number."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    short = uuid.uuid4().hex[:6].upper()
    return f"INC-{ts}-{short}"


def is_valid_ip(ip: str) -> bool:
    """Return True if the string is a valid IPv4 or IPv6 address."""
    if not ip:
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Return True if the IP address is in a private/RFC1918 range."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except ValueError:
        return False


def truncate_text(text: str, max_length: int = 500) -> str:
    """Truncate text to max_length characters, appending ellipsis if cut."""
    if not text:
        return ""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def safe_json_loads(text: str) -> Optional[Dict]:
    """Safely parse JSON text, returning None on failure."""
    import json
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def paginate(query_total: int, page: int, page_size: int) -> Dict[str, int]:
    """Compute pagination metadata from total count, page, and page size."""
    pages = max(1, (query_total + page_size - 1) // page_size)
    return {
        "total": query_total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    }


def sanitize_filename(filename: str) -> str:
    """Remove dangerous characters from a filename for safe storage."""
    # Keep only alphanumerics, dots, dashes, underscores
    safe = re.sub(r"[^\w\-_\.]", "_", filename)
    # Prevent directory traversal
    safe = safe.replace("..", "_")
    return safe[:255]  # Cap at filesystem limit


def extract_ips_from_text(text: str) -> List[str]:
    """Extract all IPv4 addresses found in a text string."""
    ipv4_pattern = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )
    return list(set(ipv4_pattern.findall(text)))


def severity_to_priority(severity: str) -> int:
    """Convert severity string to numeric priority (lower = more urgent)."""
    mapping = {
        "critical": 1,
        "high":     2,
        "medium":   3,
        "low":      4,
        "info":     5,
    }
    return mapping.get(severity.lower(), 99)


def format_duration(seconds: float) -> str:
    """Format a duration in seconds to a human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.1f}m"
    else:
        return f"{seconds / 3600:.1f}h"


def mask_sensitive_field(value: str, visible_chars: int = 4) -> str:
    """Mask a sensitive string, keeping only the last N characters visible."""
    if not value or len(value) <= visible_chars:
        return "****"
    return "*" * (len(value) - visible_chars) + value[-visible_chars:]
