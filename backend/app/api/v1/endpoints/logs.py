"""
Log ingestion endpoints - handles file upload and API-based log ingestion.
Supports JSON, CSV, and TXT formats with automatic threat detection.
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.dependencies import get_analyst_or_admin, get_current_user
from app.db.session import get_db
from app.models.models import Alert, AlertStatus, LogEntry, LogType, MITREMapping, SeverityLevel, ThreatDetection
from app.schemas.schemas import LogEntryResponse, LogIngestionResponse, PaginatedResponse
from app.services.ai_analysis import AIAnalysisService
from app.services.detection_engine import ThreatDetectionEngine
from app.services.log_parser import LogParserService

router = APIRouter()
logger = logging.getLogger(__name__)

parser = LogParserService()
detector = ThreatDetectionEngine()
ai_service = AIAnalysisService()


@router.post("/upload", response_model=LogIngestionResponse)
async def upload_log_file(
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_analyst_or_admin),
):
    """
    Upload a log file (JSON, CSV, or TXT) for ingestion and analysis.
    Returns detection and alert counts.
    """
    # Validate file size
    max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    content = await file.read()
    if len(content) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum size is {settings.MAX_FILE_SIZE_MB}MB",
        )

    # Determine log type — reject unsupported formats
    filename = file.filename or "unknown"
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "txt"
    log_type_map = {"json": LogType.JSON, "csv": LogType.CSV, "txt": LogType.TXT}
    if ext not in log_type_map:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '.{ext}'. Accepted formats: JSON, CSV, TXT",
        )
    log_type = log_type_map[ext]

    # Parse logs
    try:
        text_content = content.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not decode file content as UTF-8")

    parsed_logs, parse_errors = parser.parse(text_content, ext)
    if not parsed_logs:
        raise HTTPException(
            status_code=400,
            detail=f"No valid log entries found. Errors: {'; '.join(parse_errors[:3])}",
        )

    batch_id = uuid.uuid4().hex[:12]
    logs_stored = 0
    detections_created = 0
    alerts_created = 0

    # Store log entries
    log_entries = []
    for log_dict in parsed_logs:
        entry = LogEntry(
            source_file=filename,
            log_type=log_type,
            raw_data=json.dumps(log_dict)[:10000],  # Truncate if needed
            parsed_data=log_dict,
            source_ip=log_dict.get("source_ip"),
            destination_ip=log_dict.get("destination_ip"),
            username=log_dict.get("username"),
            event_type=log_dict.get("event_type"),
            event_id=log_dict.get("event_id"),
            hostname=log_dict.get("hostname"),
            uploaded_by=current_user.id,
            batch_id=batch_id,
        )
        db.add(entry)
        log_entries.append(entry)
        logs_stored += 1

    await db.flush()

    # Run threat detection
    detection_results = detector.analyze(parsed_logs)

    for det_result in detection_results:
        # Get first matching log entry for FK
        log_entry_id = log_entries[0].id if log_entries else None

        # AI Analysis
        ai_analysis = ai_service.analyze_detection(det_result)

        # Create detection record
        detection = ThreatDetection(
            log_entry_id=log_entry_id,
            detection_type=det_result.detection_type,
            description=det_result.description,
            severity=det_result.severity,
            confidence_score=det_result.confidence_score,
            raw_indicators=det_result.indicators,
            source_ips=det_result.source_ips,
            affected_users=det_result.affected_users,
            affected_hosts=det_result.affected_hosts,
            event_count=det_result.event_count,
        )
        db.add(detection)
        await db.flush()
        detections_created += 1

        # MITRE mappings
        for mapping in det_result.get_mitre_mappings():
            mitre = MITREMapping(
                detection_id=detection.id,
                technique_id=mapping["technique_id"],
                technique_name=mapping["technique_name"],
                tactic=mapping["tactic"],
                tactic_id=mapping.get("tactic_id"),
                description=mapping.get("description"),
                url=mapping.get("url"),
            )
            db.add(mitre)

        # Create alert
        alert = Alert(
            title=f"{det_result.detection_type.replace('_', ' ').title()} - {det_result.severity.value.upper()}",
            description=det_result.description,
            severity=det_result.severity,
            status=AlertStatus.OPEN,
            detection_id=detection.id,
            ai_summary=ai_analysis["threat_summary"],
            ai_recommendations=ai_analysis["recommended_actions"],
        )
        db.add(alert)
        alerts_created += 1

    await db.commit()

    logger.info(
        "Log file ingested",
        extra={
            "batch_id": batch_id,
            "filename": filename,
            "logs_stored": logs_stored,
            "detections": detections_created,
            "alerts": alerts_created,
        },
    )

    return LogIngestionResponse(
        batch_id=batch_id,
        logs_processed=len(parsed_logs),
        logs_stored=logs_stored,
        detections_created=detections_created,
        alerts_created=alerts_created,
        message=f"Successfully ingested {logs_stored} log entries. {detections_created} threats detected, {alerts_created} alerts created.",
    )


@router.post("/ingest", response_model=LogIngestionResponse)
async def ingest_logs_api(
    logs: List[Dict[str, Any]],
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_analyst_or_admin),
):
    """
    Ingest logs via API (JSON body). Accepts an array of log objects.
    """
    if not logs:
        raise HTTPException(status_code=400, detail="No log entries provided")
    if len(logs) > 10000:
        raise HTTPException(status_code=400, detail="Maximum 10,000 logs per request")

    batch_id = uuid.uuid4().hex[:12]
    logs_stored = 0
    detections_created = 0
    alerts_created = 0

    normalized = [parser._normalize(l) for l in logs]

    for log_dict in normalized:
        entry = LogEntry(
            log_type=LogType.JSON,
            raw_data=json.dumps(log_dict)[:10000],
            parsed_data=log_dict,
            source_ip=log_dict.get("source_ip"),
            username=log_dict.get("username"),
            event_type=log_dict.get("event_type"),
            hostname=log_dict.get("hostname"),
            uploaded_by=current_user.id,
            batch_id=batch_id,
        )
        db.add(entry)
        logs_stored += 1

    await db.flush()

    detection_results = detector.analyze(normalized)
    for det_result in detection_results:
        ai_analysis = ai_service.analyze_detection(det_result)
        detection = ThreatDetection(
            detection_type=det_result.detection_type,
            description=det_result.description,
            severity=det_result.severity,
            confidence_score=det_result.confidence_score,
            raw_indicators=det_result.indicators,
            source_ips=det_result.source_ips,
            affected_users=det_result.affected_users,
            affected_hosts=det_result.affected_hosts,
            event_count=det_result.event_count,
        )
        db.add(detection)
        await db.flush()
        detections_created += 1

        for mapping in det_result.get_mitre_mappings():
            db.add(MITREMapping(
                detection_id=detection.id,
                technique_id=mapping["technique_id"],
                technique_name=mapping["technique_name"],
                tactic=mapping["tactic"],
                tactic_id=mapping.get("tactic_id"),
                url=mapping.get("url"),
            ))

        db.add(Alert(
            title=f"{det_result.detection_type.replace('_', ' ').title()} Detected",
            description=det_result.description,
            severity=det_result.severity,
            status=AlertStatus.OPEN,
            detection_id=detection.id,
            ai_summary=ai_analysis["threat_summary"],
            ai_recommendations=ai_analysis["recommended_actions"],
        ))
        alerts_created += 1

    await db.commit()
    return LogIngestionResponse(
        batch_id=batch_id,
        logs_processed=len(logs),
        logs_stored=logs_stored,
        detections_created=detections_created,
        alerts_created=alerts_created,
        message=f"Ingested {logs_stored} logs via API. {detections_created} detections, {alerts_created} alerts.",
    )


@router.get("/", response_model=PaginatedResponse)
async def list_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """List log entries with pagination and optional filters."""
    query = select(LogEntry)
    if source_ip:
        query = query.where(LogEntry.source_ip.ilike(f"%{source_ip}%"))
    if username:
        query = query.where(LogEntry.username.ilike(f"%{username}%"))

    count_result = await db.execute(select(func.count()).select_from(query.subquery()))
    total = count_result.scalar()

    query = query.order_by(LogEntry.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    items = result.scalars().all()

    return PaginatedResponse(
        items=[LogEntryResponse.model_validate(i) for i in items],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )
