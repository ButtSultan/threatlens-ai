"""
ThreatLens AI - Report Generation Service
Generates professional PDF incident and executive summary reports.
"""

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fpdf import FPDF

from app.core.config import settings

logger = logging.getLogger(__name__)


class ReportPDF(FPDF):
    """Custom FPDF class with ThreatLens branding."""

    def header(self):
        self.set_fill_color(15, 23, 42)  # Dark navy
        self.rect(0, 0, 210, 20, "F")
        self.set_text_color(99, 179, 237)  # Cyan
        self.set_font("Helvetica", "B", 14)
        self.set_xy(10, 5)
        self.cell(0, 10, "ThreatLens AI - Security Operations Center", align="L")
        self.set_text_color(148, 163, 184)
        self.set_font("Helvetica", "", 8)
        self.set_xy(140, 5)
        self.cell(0, 10, f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", align="R")
        self.ln(15)

    def footer(self):
        self.set_y(-15)
        self.set_fill_color(15, 23, 42)
        self.rect(0, self.get_y(), 210, 15, "F")
        self.set_text_color(148, 163, 184)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"ThreatLens AI | CONFIDENTIAL | Page {self.page_no()}", align="C")

    def chapter_title(self, title: str, bg_color=(30, 41, 59)):
        self.set_fill_color(*bg_color)
        self.set_text_color(99, 179, 237)
        self.set_font("Helvetica", "B", 12)
        self.set_x(10)
        self.cell(190, 8, f"  {title}", ln=True, fill=True)
        self.ln(2)

    def body_text(self, text: str, color=(203, 213, 225)):
        self.set_text_color(*color)
        self.set_font("Helvetica", "", 10)
        self.set_x(10)
        self.multi_cell(190, 5, text)
        self.ln(2)

    def severity_badge(self, severity: str):
        colors = {
            "critical": (239, 68, 68),
            "high": (249, 115, 22),
            "medium": (234, 179, 8),
            "low": (34, 197, 94),
            "info": (148, 163, 184),
        }
        color = colors.get(severity.lower(), (148, 163, 184))
        self.set_fill_color(*color)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 9)
        self.cell(30, 6, severity.upper(), fill=True, align="C")
        self.set_text_color(203, 213, 225)


class ReportService:
    """Generates PDF security reports."""

    def __init__(self):
        os.makedirs(settings.REPORTS_DIR, exist_ok=True)

    def generate_incident_report(self, report_data: Dict[str, Any]) -> str:
        """
        Generate a full incident report PDF.
        Returns the file path of the generated report.
        """
        pdf = ReportPDF()
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()
        pdf.set_fill_color(15, 23, 42)
        pdf.rect(0, 0, 210, 297, "F")  # Dark background

        # ── Title Page ──────────────────────────────────────────────────────
        pdf.set_y(30)
        pdf.set_text_color(99, 179, 237)
        pdf.set_font("Helvetica", "B", 24)
        pdf.cell(0, 12, "INCIDENT REPORT", align="C", ln=True)

        pdf.set_text_color(203, 213, 225)
        pdf.set_font("Helvetica", "", 14)
        pdf.cell(0, 8, report_data.get("title", "Security Incident"), align="C", ln=True)

        pdf.ln(5)
        pdf.set_text_color(148, 163, 184)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, f"Incident #: {report_data.get('incident_number', 'N/A')}", align="C", ln=True)
        pdf.cell(0, 6, f"Date: {datetime.now(timezone.utc).strftime('%B %d, %Y')}", align="C", ln=True)
        pdf.cell(0, 6, "Classification: CONFIDENTIAL", align="C", ln=True)

        # ── Severity Badge ───────────────────────────────────────────────────
        pdf.ln(5)
        pdf.set_x(90)
        severity = report_data.get("severity", "medium")
        pdf.severity_badge(severity)
        pdf.ln(10)

        # ── Executive Summary ────────────────────────────────────────────────
        pdf.chapter_title("1. EXECUTIVE SUMMARY")
        pdf.body_text(report_data.get("executive_summary", "No executive summary provided."))

        # ── Incident Details ─────────────────────────────────────────────────
        pdf.chapter_title("2. INCIDENT DETAILS")
        details = [
            ("Status", report_data.get("status", "N/A")),
            ("Severity", severity.upper()),
            ("First Detected", report_data.get("created_at", "N/A")),
            ("Last Updated", report_data.get("updated_at", "N/A")),
            ("Affected Assets", ", ".join(report_data.get("affected_assets", []) or ["N/A"])),
        ]
        for label, value in details:
            pdf.set_text_color(99, 179, 237)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_x(10)
            pdf.cell(50, 6, f"{label}:", ln=False)
            pdf.set_text_color(203, 213, 225)
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(140, 6, str(value), ln=True)

        # ── Threat Description ───────────────────────────────────────────────
        pdf.ln(3)
        pdf.chapter_title("3. THREAT DESCRIPTION")
        pdf.body_text(report_data.get("description", "No description provided."))

        # ── AI Analysis ──────────────────────────────────────────────────────
        if report_data.get("ai_summary"):
            pdf.chapter_title("4. AI THREAT ANALYSIS")
            pdf.body_text(report_data["ai_summary"])

        # ── MITRE ATT&CK Mappings ────────────────────────────────────────────
        if report_data.get("mitre_techniques"):
            pdf.chapter_title("5. MITRE ATT&CK MAPPINGS")
            for technique in report_data["mitre_techniques"]:
                pdf.set_text_color(99, 179, 237)
                pdf.set_font("Helvetica", "B", 10)
                pdf.set_x(10)
                pdf.cell(0, 6, f"  {technique.get('technique_id')} - {technique.get('technique_name')}", ln=True)
                pdf.set_text_color(148, 163, 184)
                pdf.set_font("Helvetica", "", 9)
                pdf.set_x(15)
                pdf.cell(0, 5, f"Tactic: {technique.get('tactic')} | {technique.get('url', '')}", ln=True)
                pdf.ln(2)

        # ── Recommendations ──────────────────────────────────────────────────
        if report_data.get("recommendations"):
            pdf.chapter_title("6. RECOMMENDED ACTIONS")
            for i, rec in enumerate(report_data["recommendations"], 1):
                pdf.set_text_color(99, 179, 237)
                pdf.set_font("Helvetica", "B", 10)
                pdf.set_x(10)
                pdf.cell(10, 6, f"{i}.", ln=False)
                pdf.set_text_color(203, 213, 225)
                pdf.set_font("Helvetica", "", 10)
                pdf.multi_cell(175, 6, rec)

        # ── Timeline ─────────────────────────────────────────────────────────
        if report_data.get("timeline"):
            pdf.chapter_title("7. INCIDENT TIMELINE")
            for event in report_data["timeline"]:
                pdf.set_text_color(99, 179, 237)
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_x(10)
                pdf.cell(50, 5, str(event.get("time", "")), ln=False)
                pdf.set_text_color(203, 213, 225)
                pdf.set_font("Helvetica", "", 9)
                pdf.cell(140, 5, str(event.get("event", "")), ln=True)

        # ── Root Cause ───────────────────────────────────────────────────────
        if report_data.get("root_cause"):
            pdf.chapter_title("8. ROOT CAUSE ANALYSIS")
            pdf.body_text(report_data["root_cause"])

        # ── Lessons Learned ──────────────────────────────────────────────────
        if report_data.get("lessons_learned"):
            pdf.chapter_title("9. LESSONS LEARNED")
            pdf.body_text(report_data["lessons_learned"])

        # Save PDF
        filename = f"incident_report_{report_data.get('incident_number', uuid.uuid4().hex[:8])}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(settings.REPORTS_DIR, filename)
        pdf.output(filepath)
        logger.info("Incident report generated", extra={"path": filepath})
        return filepath

    def generate_executive_summary(self, summary_data: Dict[str, Any]) -> str:
        """Generate a high-level executive summary PDF."""
        pdf = ReportPDF()
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()
        pdf.set_fill_color(15, 23, 42)
        pdf.rect(0, 0, 210, 297, "F")

        pdf.set_y(30)
        pdf.set_text_color(99, 179, 237)
        pdf.set_font("Helvetica", "B", 20)
        pdf.cell(0, 10, "EXECUTIVE SECURITY SUMMARY", align="C", ln=True)

        pdf.set_text_color(148, 163, 184)
        pdf.set_font("Helvetica", "", 10)
        period = summary_data.get("period", "Last 30 Days")
        pdf.cell(0, 6, f"Reporting Period: {period}", align="C", ln=True)
        pdf.ln(8)

        # Stats table
        pdf.chapter_title("KEY SECURITY METRICS")
        stats = summary_data.get("stats", {})
        metrics = [
            ("Total Logs Analyzed", str(stats.get("total_logs", 0))),
            ("Total Alerts Generated", str(stats.get("total_alerts", 0))),
            ("Critical Alerts", str(stats.get("critical_alerts", 0))),
            ("High Severity Alerts", str(stats.get("high_severity_alerts", 0))),
            ("Open Incidents", str(stats.get("active_incidents", 0))),
            ("Resolved This Period", str(stats.get("resolved_incidents", 0))),
        ]
        for label, value in metrics:
            pdf.set_fill_color(30, 41, 59)
            pdf.set_text_color(148, 163, 184)
            pdf.set_font("Helvetica", "", 10)
            pdf.set_x(10)
            pdf.cell(120, 7, f"  {label}", fill=True, ln=False)
            pdf.set_text_color(99, 179, 237)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(70, 7, value, fill=True, align="R", ln=True)
            pdf.ln(1)

        # Top threats
        if summary_data.get("top_threats"):
            pdf.ln(5)
            pdf.chapter_title("TOP THREAT CATEGORIES")
            for threat in summary_data["top_threats"]:
                pdf.set_text_color(203, 213, 225)
                pdf.set_font("Helvetica", "", 10)
                pdf.set_x(10)
                pdf.cell(0, 6, f"  • {threat}", ln=True)

        # Narrative summary
        if summary_data.get("narrative"):
            pdf.ln(5)
            pdf.chapter_title("SECURITY POSTURE SUMMARY")
            pdf.body_text(summary_data["narrative"])

        filename = f"executive_summary_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(settings.REPORTS_DIR, filename)
        pdf.output(filepath)
        logger.info("Executive summary generated", extra={"path": filepath})
        return filepath
