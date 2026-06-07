"""
ThreatLens AI - SQLAlchemy Database Models
Normalized PostgreSQL schema for all entities.
native_enum=False ensures compatibility with SQLite in tests.
"""

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, Float, ForeignKey,
    Integer, JSON, String, Text
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.types import TypeDecorator, CHAR
import uuid as _uuid

from app.db.base import Base


# ── Portable UUID type (PostgreSQL native / SQLite CHAR) ─────────────────

class UUIDType(TypeDecorator):
    """Database-agnostic UUID: uses PG UUID on postgres, CHAR(36) elsewhere."""
    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if dialect.name == "postgresql":
            return str(value) if not isinstance(value, _uuid.UUID) else value
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if not isinstance(value, _uuid.UUID):
            try:
                value = _uuid.UUID(value)
            except (ValueError, AttributeError):
                pass
        return value


# ─────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class SeverityLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class LogType(str, enum.Enum):
    JSON = "json"
    CSV = "csv"
    TXT = "txt"
    SYSLOG = "syslog"
    WINDOWS_EVENT = "windows_event"


class IncidentStatus(str, enum.Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"


# Helper — non-native enum column (works with both PostgreSQL and SQLite)
def _enum_col(enum_class, **kwargs):
    return Column(
        Enum(enum_class, native_enum=False, length=50),
        **kwargs
    )


# ─────────────────────────────────────────
# USERS
# ─────────────────────────────────────────

class User(Base):
    """System users with role-based access control."""
    __tablename__ = "users"

    id = Column(UUIDType, primary_key=True, default=_uuid.uuid4)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=True)
    role = _enum_col(UserRole, default=UserRole.ANALYST, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    last_login = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())

    logs = relationship("LogEntry", back_populates="uploaded_by_user", lazy="select")
    alerts = relationship("Alert", back_populates="assigned_to_user", lazy="select")
    audit_logs = relationship("AuditLog", back_populates="user", lazy="select")


# ─────────────────────────────────────────
# LOGS
# ─────────────────────────────────────────

class LogEntry(Base):
    """Raw security log entries ingested from various sources."""
    __tablename__ = "log_entries"

    id = Column(UUIDType, primary_key=True, default=_uuid.uuid4)
    source_file = Column(String(255), nullable=True)
    log_type = _enum_col(LogType, default=LogType.JSON, nullable=False)
    raw_data = Column(Text, nullable=False)
    parsed_data = Column(JSON, nullable=True)
    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True)
    username = Column(String(100), nullable=True, index=True)
    event_type = Column(String(100), nullable=True, index=True)
    event_id = Column(String(50), nullable=True)
    hostname = Column(String(255), nullable=True)
    timestamp = Column(DateTime(timezone=True), nullable=True, index=True)
    uploaded_by = Column(UUIDType, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    batch_id = Column(String(50), nullable=True, index=True)

    uploaded_by_user = relationship("User", back_populates="logs")
    detections = relationship("ThreatDetection", back_populates="log_entry", lazy="select")


# ─────────────────────────────────────────
# THREAT DETECTIONS
# ─────────────────────────────────────────

class ThreatDetection(Base):
    """Results from the threat detection engine."""
    __tablename__ = "threat_detections"

    id = Column(UUIDType, primary_key=True, default=_uuid.uuid4)
    log_entry_id = Column(UUIDType, ForeignKey("log_entries.id"), nullable=True)
    detection_type = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=False)
    severity = _enum_col(SeverityLevel, nullable=False, index=True)
    confidence_score = Column(Float, default=0.0)
    raw_indicators = Column(JSON, nullable=True)
    source_ips = Column(JSON, nullable=True)
    affected_users = Column(JSON, nullable=True)
    affected_hosts = Column(JSON, nullable=True)
    first_seen = Column(DateTime(timezone=True), default=func.now())
    last_seen = Column(DateTime(timezone=True), default=func.now())
    event_count = Column(Integer, default=1)
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)

    log_entry = relationship("LogEntry", back_populates="detections")
    alert = relationship("Alert", back_populates="detection", uselist=False)
    mitre_mappings = relationship("MITREMapping", back_populates="detection", lazy="select")


# ─────────────────────────────────────────
# ALERTS
# ─────────────────────────────────────────

class Alert(Base):
    """Security alerts generated from threat detections."""
    __tablename__ = "alerts"

    id = Column(UUIDType, primary_key=True, default=_uuid.uuid4)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = _enum_col(SeverityLevel, nullable=False, index=True)
    status = _enum_col(AlertStatus, default=AlertStatus.OPEN, nullable=False, index=True)
    detection_id = Column(UUIDType, ForeignKey("threat_detections.id"), nullable=True)
    assigned_to = Column(UUIDType, ForeignKey("users.id"), nullable=True)
    ai_summary = Column(Text, nullable=True)
    ai_recommendations = Column(JSON, nullable=True)
    analyst_notes = Column(Text, nullable=True)
    false_positive = Column(Boolean, default=False)
    tags = Column(JSON, nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())

    detection = relationship("ThreatDetection", back_populates="alert")
    assigned_to_user = relationship("User", back_populates="alerts")
    incident = relationship("Incident", back_populates="alert", uselist=False)


# ─────────────────────────────────────────
# MITRE ATT&CK MAPPINGS
# ─────────────────────────────────────────

class MITREMapping(Base):
    """MITRE ATT&CK framework technique mappings."""
    __tablename__ = "mitre_mappings"

    id = Column(UUIDType, primary_key=True, default=_uuid.uuid4)
    detection_id = Column(UUIDType, ForeignKey("threat_detections.id"), nullable=False)
    technique_id = Column(String(20), nullable=False, index=True)
    technique_name = Column(String(255), nullable=False)
    tactic = Column(String(100), nullable=False, index=True)
    tactic_id = Column(String(20), nullable=True)
    description = Column(Text, nullable=True)
    url = Column(String(500), nullable=True)
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)

    detection = relationship("ThreatDetection", back_populates="mitre_mappings")


# ─────────────────────────────────────────
# INCIDENTS
# ─────────────────────────────────────────

class Incident(Base):
    """Security incidents aggregated from alerts."""
    __tablename__ = "incidents"

    id = Column(UUIDType, primary_key=True, default=_uuid.uuid4)
    incident_number = Column(String(20), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = _enum_col(SeverityLevel, nullable=False)
    status = _enum_col(IncidentStatus, default=IncidentStatus.NEW, nullable=False)
    alert_id = Column(UUIDType, ForeignKey("alerts.id"), nullable=True)
    affected_assets = Column(JSON, nullable=True)
    timeline = Column(JSON, nullable=True)
    containment_actions = Column(JSON, nullable=True)
    root_cause = Column(Text, nullable=True)
    lessons_learned = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    closed_at = Column(DateTime(timezone=True), nullable=True)

    alert = relationship("Alert", back_populates="incident")
    reports = relationship("Report", back_populates="incident", lazy="select")


# ─────────────────────────────────────────
# REPORTS
# ─────────────────────────────────────────

class Report(Base):
    """Generated PDF/HTML security reports."""
    __tablename__ = "reports"

    id = Column(UUIDType, primary_key=True, default=_uuid.uuid4)
    title = Column(String(255), nullable=False)
    report_type = Column(String(50), nullable=False)
    incident_id = Column(UUIDType, ForeignKey("incidents.id"), nullable=True)
    file_path = Column(String(500), nullable=True)
    content = Column(JSON, nullable=True)
    generated_by = Column(UUIDType, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False)

    incident = relationship("Incident", back_populates="reports")


# ─────────────────────────────────────────
# AUDIT LOGS
# ─────────────────────────────────────────

class AuditLog(Base):
    """Security audit trail for all user actions."""
    __tablename__ = "audit_logs"

    id = Column(UUIDType, primary_key=True, default=_uuid.uuid4)
    user_id = Column(UUIDType, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(100), nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    success = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=func.now(), nullable=False, index=True)

    user = relationship("User", back_populates="audit_logs")
