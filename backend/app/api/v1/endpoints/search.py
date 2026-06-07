"""Search endpoints for logs and alerts."""

from typing import Optional
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.dependencies import get_current_user
from app.db.session import get_db
from app.models.models import Alert, AlertStatus, LogEntry, SeverityLevel, ThreatDetection
from app.schemas.schemas import AlertResponse, LogEntryResponse, PaginatedResponse

router = APIRouter()


@router.get("/logs", response_model=PaginatedResponse)
async def search_logs(
    q: Optional[str] = Query(None, description="Search in source_ip, username, event_type, hostname"),
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    event_type: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Full-text search across log entries."""
    query = select(LogEntry)

    if q:
        query = query.where(
            or_(
                LogEntry.source_ip.ilike(f"%{q}%"),
                LogEntry.username.ilike(f"%{q}%"),
                LogEntry.event_type.ilike(f"%{q}%"),
                LogEntry.hostname.ilike(f"%{q}%"),
            )
        )
    if source_ip:
        query = query.where(LogEntry.source_ip.ilike(f"%{source_ip}%"))
    if username:
        query = query.where(LogEntry.username.ilike(f"%{username}%"))
    if event_type:
        query = query.where(LogEntry.event_type.ilike(f"%{event_type}%"))
    if start_date:
        query = query.where(LogEntry.created_at >= start_date)
    if end_date:
        query = query.where(LogEntry.created_at <= end_date)

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar()
    query = query.order_by(LogEntry.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    items = (await db.execute(query)).scalars().all()

    return PaginatedResponse(
        items=[LogEntryResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/alerts", response_model=PaginatedResponse)
async def search_alerts(
    q: Optional[str] = Query(None, description="Search in title or description"),
    severity: Optional[SeverityLevel] = None,
    status_filter: Optional[AlertStatus] = Query(None, alias="status"),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Search and filter alerts."""
    query = select(Alert).options(
        selectinload(Alert.detection).selectinload(ThreatDetection.mitre_mappings)
    )
    if q:
        query = query.where(
            or_(Alert.title.ilike(f"%{q}%"), Alert.description.ilike(f"%{q}%"))
        )
    if severity:
        query = query.where(Alert.severity == severity)
    if status_filter:
        query = query.where(Alert.status == status_filter)
    if start_date:
        query = query.where(Alert.created_at >= start_date)
    if end_date:
        query = query.where(Alert.created_at <= end_date)

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar()
    query = query.order_by(Alert.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    items = (await db.execute(query)).scalars().all()

    return PaginatedResponse(
        items=[AlertResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )
