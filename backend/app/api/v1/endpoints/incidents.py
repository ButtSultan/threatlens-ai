"""Incident management endpoints."""

import uuid
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_analyst_or_admin, get_current_user
from app.db.session import get_db
from app.models.models import Incident, IncidentStatus, SeverityLevel
from app.schemas.schemas import IncidentCreate, IncidentResponse, IncidentUpdate, PaginatedResponse

router = APIRouter()


def generate_incident_number() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    short = uuid.uuid4().hex[:6].upper()
    return f"INC-{ts}-{short}"


@router.get("/", response_model=PaginatedResponse)
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: Optional[IncidentStatus] = Query(None, alias="status"),
    severity: Optional[SeverityLevel] = None,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """List incidents with optional filters."""
    query = select(Incident)
    if status_filter:
        query = query.where(Incident.status == status_filter)
    if severity:
        query = query.where(Incident.severity == severity)

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar()
    query = query.order_by(Incident.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    items = result.scalars().all()

    return PaginatedResponse(
        items=[IncidentResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    result = await db.execute(select(Incident).where(Incident.id == str(incident_id)))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.post("/", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    data: IncidentCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_analyst_or_admin),
):
    incident = Incident(
        incident_number=generate_incident_number(),
        title=data.title,
        description=data.description,
        severity=data.severity,
        alert_id=data.alert_id,
        affected_assets=data.affected_assets,
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    return incident


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: UUID,
    data: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_analyst_or_admin),
):
    result = await db.execute(select(Incident).where(Incident.id == str(incident_id)))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if data.status:
        incident.status = data.status
        if data.status == IncidentStatus.CLOSED:
            incident.closed_at = datetime.now(timezone.utc)
    if data.root_cause is not None:
        incident.root_cause = data.root_cause
    if data.lessons_learned is not None:
        incident.lessons_learned = data.lessons_learned
    if data.containment_actions is not None:
        incident.containment_actions = data.containment_actions

    await db.commit()
    await db.refresh(incident)
    return incident
