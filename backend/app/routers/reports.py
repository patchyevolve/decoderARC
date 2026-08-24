"""Reports management routes."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..models import User, Report, ReportSchedule
from ..schemas import ReportGenerate, ReportScheduleCreate

router = APIRouter(prefix="/api/reports", tags=["Reports"])


TEMPLATES = [
    {"id": "security_summary", "name": "Security Summary Report",
     "description": "Daily overview of all security events and alerts",
     "icon": "🛡️"},
    {"id": "alert_analysis", "name": "Alert Analysis Report",
     "description": "Detailed breakdown of alerts by category and severity",
     "icon": "🚨"},
    {"id": "network_traffic", "name": "Network Traffic Report",
     "description": "Traffic patterns, top talkers, protocol distribution",
     "icon": "📡"},
    {"id": "compliance", "name": "Compliance Report",
     "description": "NIST / ISO 27001 / PCI-DSS compliance status",
     "icon": "📋"},
    {"id": "threat_intel", "name": "Threat Intelligence Report",
     "description": "Known threat actors and attack source analysis",
     "icon": "🎯"},
]


@router.get("")
def list_reports(user: User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    recent = db.query(Report).filter(
        Report.user_id == user.id
    ).order_by(Report.generated_at.desc()).limit(10).all()
    schedules = db.query(ReportSchedule).filter(
        ReportSchedule.user_id == user.id
    ).all()
    return {
        "templates": TEMPLATES,
        "recent": [
            {
                "id": r.id, "name": r.name, "type": r.type,
                "format": r.format, "generated_at": r.generated_at.strftime("%Y-%m-%d %H:%M"),
            }
            for r in recent
        ],
        "scheduled": [
            {
                "id": s.id, "name": s.name, "schedule": s.schedule,
                "recipients": s.recipients, "active": s.active,
            }
            for s in schedules
        ],
    }


@router.post("")
def generate_report(req: ReportGenerate,
                    user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    template = next((t for t in TEMPLATES if t["id"] == req.template_id), None)
    name = template["name"] if template else f"Report - {req.template_id}"
    report = Report(
        user_id=user.id,
        name=f"{name} — {datetime.now(timezone.utc).strftime('%b %d %H:%M')}",
        type=name,
        format=req.format,
        template_id=req.template_id,
        file_path="",
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return {
        "id": report.id,
        "name": report.name,
        "message": f"Report '{name}' generated successfully",
    }


@router.delete("/{report_id}")
def delete_report(report_id: str,
                  user: User = Depends(get_current_user),
                  db: Session = Depends(get_db)):
    report = db.query(Report).filter(
        Report.id == report_id, Report.user_id == user.id
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    db.delete(report)
    db.commit()
    return {"message": "Report deleted"}


@router.get("/{report_id}/download")
def download_report(report_id: str,
                    user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    report = db.query(Report).filter(
        Report.id == report_id, Report.user_id == user.id
    ).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    # Generate content based on format
    fmt = report.format.lower()
    safe_name = report.name.replace("/", "_").replace("\\", "_")
    report_time = report.generated_at.strftime("%Y-%m-%d %H:%M UTC")
    if fmt == "json":
        import json
        data = {
            "report": report.name,
            "generated": report_time,
            "format": report.format,
            "summary": f"CoreIDS security report covering {report.type}",
        }
        content = json.dumps(data, indent=2)
        media_type = "application/json"
        ext = "json"
    elif fmt == "csv":
        content = f"Report,Generated,Format,Summary\n{safe_name},{report_time},{report.format},CoreIDS security report covering {report.type}\n"
        media_type = "text/csv"
        ext = "csv"
    else:
        content = (
            f"{'='*60}\n"
            f"  CoreIDS Security Report\n"
            f"{'='*60}\n\n"
            f"  Report:     {report.name}\n"
            f"  Generated:  {report_time}\n"
            f"  Format:     {report.format}\n"
            f"  Period:     {report.type}\n"
            f"{'='*60}\n\n"
            f"  This report was generated from your CoreIDS\n"
            f"  security monitoring system. It contains a\n"
            f"  summary of security events and alerts for\n"
            f"  the specified time period.\n\n"
            f"{'='*60}\n"
            f"  END OF REPORT\n"
            f"{'='*60}\n"
        )
        media_type = "text/plain"
        ext = "txt"
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{safe_name}.{ext}"'},
    )


@router.post("/schedule")
def schedule_report(req: ReportScheduleCreate,
                    user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    sched = ReportSchedule(
        user_id=user.id,
        name=req.name,
        schedule=req.schedule,
        recipients=req.recipients,
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)
    return {"id": sched.id, "message": f"Report '{req.name}' scheduled"}
