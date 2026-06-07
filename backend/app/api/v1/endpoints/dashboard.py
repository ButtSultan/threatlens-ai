"""Dashboard analytics endpoints."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_current_user
from app.db.session import get_db
from app.models.models import (
    Alert, AlertStatus, Incident, IncidentStatus,
    LogEntry, MITREMapping, SeverityLevel, ThreatDetection
)
from app.schemas.schemas import (
    AlertResponse, DashboardResponse, DashboardStats,
    DetectionTrend, MITRETacticCount, SeverityDistribution
)
from sqlalchemy.orm import selectinload

router = APIRouter()


@router.get("/", response_model=DashboardResponse)
async def get_dashboard(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Get complete dashboard statistics."""
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    last_7_days = now - timedelta(days=7)

    # Basic counts
    total_logs = (await db.execute(select(func.count(LogEntry.id)))).scalar() or 0
    total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
    open_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.status == AlertStatus.OPEN)
    )).scalar() or 0
    high_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.severity == SeverityLevel.HIGH)
    )).scalar() or 0
    critical_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.severity == SeverityLevel.CRITICAL)
    )).scalar() or 0
    total_incidents = (await db.execute(select(func.count(Incident.id)))).scalar() or 0
    active_incidents = (await db.execute(
        select(func.count(Incident.id)).where(
            Incident.status.in_([IncidentStatus.NEW, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED])
        )
    )).scalar() or 0
    detections_today = (await db.execute(
        select(func.count(ThreatDetection.id)).where(ThreatDetection.created_at >= today_start)
    )).scalar() or 0
    logs_today = (await db.execute(
        select(func.count(LogEntry.id)).where(LogEntry.created_at >= today_start)
    )).scalar() or 0

    # Severity distribution
    sev_result = await db.execute(
        select(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
    )
    severity_distribution = [
        SeverityDistribution(severity=row[0].value, count=row[1])
        for row in sev_result.fetchall()
    ]

    # Detection trends (last 7 days)
    trend_result = await db.execute(
        select(
            func.date_trunc("day", ThreatDetection.created_at).label("day"),
            ThreatDetection.severity,
            func.count(ThreatDetection.id).label("count"),
        )
        .where(ThreatDetection.created_at >= last_7_days)
        .group_by("day", ThreatDetection.severity)
        .order_by("day")
    )
    detection_trends = [
        DetectionTrend(
            date=str(row[0].date()) if row[0] else "unknown",
            severity=row[1].value,
            count=row[2],
        )
        for row in trend_result.fetchall()
    ]

    # MITRE distribution by tactic
    mitre_result = await db.execute(
        select(MITREMapping.tactic, func.count(MITREMapping.id))
        .group_by(MITREMapping.tactic)
        .order_by(func.count(MITREMapping.id).desc())
        .limit(10)
    )
    mitre_distribution = [
        MITRETacticCount(tactic=row[0], count=row[1])
        for row in mitre_result.fetchall()
    ]

    # Recent alerts
    recent_result = await db.execute(
        select(Alert)
        .options(selectinload(Alert.detection).selectinload(ThreatDetection.mitre_mappings))
        .order_by(Alert.created_at.desc())
        .limit(10)
    )
    recent_alerts = [AlertResponse.model_validate(a) for a in recent_result.scalars().all()]

    return DashboardResponse(
        stats=DashboardStats(
            total_logs=total_logs,
            total_alerts=total_alerts,
            open_alerts=open_alerts,
            high_severity_alerts=high_alerts,
            critical_alerts=critical_alerts,
            total_incidents=total_incidents,
            active_incidents=active_incidents,
            detections_today=detections_today,
            logs_today=logs_today,
        ),
        severity_distribution=severity_distribution,
        detection_trends=detection_trends,
        mitre_distribution=mitre_distribution,
        recent_alerts=recent_alerts,
    )
