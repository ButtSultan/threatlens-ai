"""
ThreatLens AI - Pydantic Schemas for request/response validation.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, field_validator, ConfigDict

from app.models.models import (
    AlertStatus, IncidentStatus, LogType, SeverityLevel, UserRole
)


# ─────────────────────────────────────────
# BASE
# ─────────────────────────────────────────

class BaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ─────────────────────────────────────────
# USER SCHEMAS
# ─────────────────────────────────────────

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    role: UserRole = UserRole.ANALYST

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        if len(v) < 3 or len(v) > 50:
            raise ValueError("Username must be 3-50 characters")
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username must be alphanumeric (underscores/hyphens allowed)")
        return v.lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain an uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain a lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain a digit")
        return v


class UserResponse(BaseResponse):
    id: UUID
    username: str
    email: str
    full_name: Optional[str]
    role: UserRole
    is_active: bool
    last_login: Optional[datetime]
    created_at: datetime


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None


# ─────────────────────────────────────────
# AUTH SCHEMAS
# ─────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class RefreshRequest(BaseModel):
    refresh_token: str


# ─────────────────────────────────────────
# LOG SCHEMAS
# ─────────────────────────────────────────

class LogEntryResponse(BaseResponse):
    id: UUID
    source_file: Optional[str]
    log_type: LogType
    source_ip: Optional[str]
    destination_ip: Optional[str]
    username: Optional[str]
    event_type: Optional[str]
    event_id: Optional[str]
    hostname: Optional[str]
    timestamp: Optional[datetime]
    created_at: datetime
    batch_id: Optional[str]


class LogIngestionResponse(BaseModel):
    batch_id: str
    logs_processed: int
    logs_stored: int
    detections_created: int
    alerts_created: int
    message: str


# ─────────────────────────────────────────
# MITRE SCHEMAS
# ─────────────────────────────────────────

class MITREMappingResponse(BaseResponse):
    id: UUID
    technique_id: str
    technique_name: str
    tactic: str
    tactic_id: Optional[str]
    description: Optional[str]
    url: Optional[str]


# ─────────────────────────────────────────
# DETECTION SCHEMAS
# ─────────────────────────────────────────

class ThreatDetectionResponse(BaseResponse):
    id: UUID
    detection_type: str
    description: str
    severity: SeverityLevel
    confidence_score: float
    source_ips: Optional[List[str]]
    affected_users: Optional[List[str]]
    affected_hosts: Optional[List[str]]
    first_seen: datetime
    last_seen: datetime
    event_count: int
    created_at: datetime
    mitre_mappings: List[MITREMappingResponse] = []


# ─────────────────────────────────────────
# ALERT SCHEMAS
# ─────────────────────────────────────────

class AlertCreate(BaseModel):
    title: str
    description: str
    severity: SeverityLevel
    detection_id: Optional[UUID] = None
    tags: Optional[List[str]] = None


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    assigned_to: Optional[UUID] = None
    analyst_notes: Optional[str] = None
    false_positive: Optional[bool] = None
    tags: Optional[List[str]] = None


class AlertResponse(BaseResponse):
    id: UUID
    title: str
    description: str
    severity: SeverityLevel
    status: AlertStatus
    ai_summary: Optional[str]
    ai_recommendations: Optional[List[str]]
    analyst_notes: Optional[str]
    false_positive: bool
    tags: Optional[List[str]]
    created_at: datetime
    updated_at: Optional[datetime]
    resolved_at: Optional[datetime]
    detection: Optional[ThreatDetectionResponse] = None


# ─────────────────────────────────────────
# INCIDENT SCHEMAS
# ─────────────────────────────────────────

class IncidentCreate(BaseModel):
    title: str
    description: str
    severity: SeverityLevel
    alert_id: Optional[UUID] = None
    affected_assets: Optional[List[str]] = None


class IncidentUpdate(BaseModel):
    status: Optional[IncidentStatus] = None
    root_cause: Optional[str] = None
    lessons_learned: Optional[str] = None
    containment_actions: Optional[List[str]] = None


class IncidentResponse(BaseResponse):
    id: UUID
    incident_number: str
    title: str
    description: str
    severity: SeverityLevel
    status: IncidentStatus
    affected_assets: Optional[List[str]]
    root_cause: Optional[str]
    lessons_learned: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]
    closed_at: Optional[datetime]


# ─────────────────────────────────────────
# DASHBOARD SCHEMAS
# ─────────────────────────────────────────

class DashboardStats(BaseModel):
    total_logs: int
    total_alerts: int
    open_alerts: int
    high_severity_alerts: int
    critical_alerts: int
    total_incidents: int
    active_incidents: int
    detections_today: int
    logs_today: int


class SeverityDistribution(BaseModel):
    severity: str
    count: int


class DetectionTrend(BaseModel):
    date: str
    count: int
    severity: str


class MITRETacticCount(BaseModel):
    tactic: str
    count: int


class DashboardResponse(BaseModel):
    stats: DashboardStats
    severity_distribution: List[SeverityDistribution]
    detection_trends: List[DetectionTrend]
    mitre_distribution: List[MITRETacticCount]
    recent_alerts: List[AlertResponse]


# ─────────────────────────────────────────
# REPORT SCHEMAS
# ─────────────────────────────────────────

class ReportCreate(BaseModel):
    title: str
    report_type: str  # incident, executive, summary
    incident_id: Optional[UUID] = None


class ReportResponse(BaseResponse):
    id: UUID
    title: str
    report_type: str
    file_path: Optional[str]
    created_at: datetime


# ─────────────────────────────────────────
# SEARCH/FILTER SCHEMAS
# ─────────────────────────────────────────

class LogSearchParams(BaseModel):
    source_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    page: int = 1
    page_size: int = 50


class AlertSearchParams(BaseModel):
    severity: Optional[SeverityLevel] = None
    status: Optional[AlertStatus] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    assigned_to: Optional[UUID] = None
    page: int = 1
    page_size: int = 50


class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    page_size: int
    pages: int
