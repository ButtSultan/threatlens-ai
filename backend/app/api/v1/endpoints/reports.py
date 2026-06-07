"""Report generation endpoints."""

import os
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_analyst_or_admin, get_current_user
from app.db.session import get_db
from app.models.models import Alert, AlertStatus, Incident, MITREMapping, Report, ThreatDetection, SeverityLevel
from app.schemas.schemas import ReportCreate, ReportResponse
from app.services.report_service import ReportService
from app.services.ai_analysis import AIAnalysisService

router = APIRouter()
report_service = ReportService()
ai_service = AIAnalysisService()


@router.post("/generate", response_model=ReportResponse)
async def generate_report(
    data: ReportCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_analyst_or_admin),
):
    """Generate a PDF report (incident or executive summary)."""

    if data.report_type == "incident" and data.incident_id:
        # Fetch incident with related data
        inc_result = await db.execute(
            select(Incident).where(Incident.id == str(data).incident_id)
        )
        incident = inc_result.scalar_one_or_none()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        # Fetch related alert/detection for AI summary
        ai_summary = ""
        recommendations = []
        mitre_techniques = []

        if incident.alert_id:
            alert_result = await db.execute(
                select(Alert)
                .options(selectinload(Alert.detection).selectinload(ThreatDetection.mitre_mappings))
                .where(Alert.id == str(incident).alert_id)
            )
            alert = alert_result.scalar_one_or_none()
            if alert:
                ai_summary = alert.ai_summary or ""
                recommendations = alert.ai_recommendations or []
                if alert.detection and alert.detection.mitre_mappings:
                    mitre_techniques = [
                        {
                            "technique_id": m.technique_id,
                            "technique_name": m.technique_name,
                            "tactic": m.tactic,
                            "url": m.url,
                        }
                        for m in alert.detection.mitre_mappings
                    ]

        report_data = {
            "title": incident.title,
            "incident_number": incident.incident_number,
            "severity": incident.severity.value,
            "status": incident.status.value,
            "description": incident.description,
            "executive_summary": ai_summary or incident.description,
            "affected_assets": incident.affected_assets,
            "timeline": incident.timeline,
            "root_cause": incident.root_cause,
            "lessons_learned": incident.lessons_learned,
            "ai_summary": ai_summary,
            "recommendations": recommendations,
            "mitre_techniques": mitre_techniques,
            "created_at": str(incident.created_at),
            "updated_at": str(incident.updated_at),
        }
        filepath = report_service.generate_incident_report(report_data)

    else:
        # Executive summary
        total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
        critical = (await db.execute(
            select(func.count(Alert.id)).where(Alert.severity == SeverityLevel.CRITICAL)
        )).scalar() or 0
        high = (await db.execute(
            select(func.count(Alert.id)).where(Alert.severity == SeverityLevel.HIGH)
        )).scalar() or 0

        summary_data = {
            "period": "Last 30 Days",
            "stats": {
                "total_logs": 0,
                "total_alerts": total_alerts,
                "critical_alerts": critical,
                "high_severity_alerts": high,
                "active_incidents": 0,
                "resolved_incidents": 0,
            },
            "top_threats": ["Brute Force Attacks", "Privilege Escalation", "Suspicious PowerShell"],
            "narrative": "Security posture analysis for the reporting period.",
        }
        filepath = report_service.generate_executive_summary(summary_data)

    # Store report record
    report = Report(
        title=data.title,
        report_type=data.report_type,
        incident_id=data.incident_id,
        file_path=filepath,
        generated_by=current_user.id,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    return report


@router.get("/{report_id}/download")
async def download_report(
    report_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Download a generated PDF report."""
    result = await db.execute(select(Report).where(Report.id == str(report_id)))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not report.file_path or not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    return FileResponse(
        path=report.file_path,
        media_type="application/pdf",
        filename=os.path.basename(report.file_path),
    )


@router.get("/", response_model=list[ReportResponse])
async def list_reports(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    result = await db.execute(select(Report).order_by(Report.created_at.desc()).limit(50))
    return result.scalars().all()
