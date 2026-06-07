"""Alert management endpoints - CRUD with status transitions."""

from uuid import UUID
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_analyst_or_admin, get_current_user
from app.db.session import get_db
from app.models.models import Alert, AlertStatus, SeverityLevel, ThreatDetection, MITREMapping
from app.schemas.schemas import (
    AlertCreate, AlertResponse, AlertUpdate, PaginatedResponse
)

router = APIRouter()


@router.get("/", response_model=PaginatedResponse)
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[SeverityLevel] = None,
    status_filter: Optional[AlertStatus] = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """List alerts with filters and pagination."""
    query = select(Alert).options(
        selectinload(Alert.detection).selectinload(ThreatDetection.mitre_mappings)
    )
    if severity:
        query = query.where(Alert.severity == severity)
    if status_filter:
        query = query.where(Alert.status == status_filter)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar()

    query = query.order_by(Alert.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    items = result.scalars().all()

    return PaginatedResponse(
        items=[AlertResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Get a specific alert by ID with full detection details."""
    result = await db.execute(
        select(Alert)
        .options(selectinload(Alert.detection).selectinload(ThreatDetection.mitre_mappings))
        .where(Alert.id == str(alert_id))
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
async def create_alert(
    alert_data: AlertCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_analyst_or_admin),
):
    """Manually create a new alert."""
    alert = Alert(
        title=alert_data.title,
        description=alert_data.description,
        severity=alert_data.severity,
        detection_id=alert_data.detection_id,
        tags=alert_data.tags,
    )
    db.add(alert)
    await db.commit()
    await db.refresh(alert)
    return alert


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: UUID,
    update_data: AlertUpdate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_analyst_or_admin),
):
    """Update alert status, notes, or assignment."""
    result = await db.execute(select(Alert).where(Alert.id == str(alert_id)))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if update_data.status is not None:
        alert.status = update_data.status
        if update_data.status in (AlertStatus.RESOLVED, AlertStatus.CLOSED):
            alert.resolved_at = datetime.now(timezone.utc)
    if update_data.assigned_to is not None:
        alert.assigned_to = update_data.assigned_to
    if update_data.analyst_notes is not None:
        alert.analyst_notes = update_data.analyst_notes
    if update_data.false_positive is not None:
        alert.false_positive = update_data.false_positive
    if update_data.tags is not None:
        alert.tags = update_data.tags

    await db.commit()
    await db.refresh(alert)
    return alert


@router.delete("/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_alert(
    alert_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_analyst_or_admin),
):
    """Delete an alert."""
    result = await db.execute(select(Alert).where(Alert.id == str(alert_id)))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    await db.delete(alert)
    await db.commit()
