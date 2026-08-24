"""Log viewer routes."""


from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..models import User, LogEntry
from ..schemas import LogEntryResponse, LogListResponse

router = APIRouter(prefix="/api/logs", tags=["Logs"])


@router.get("", response_model=LogListResponse)
def list_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    type: str = "",
    protocol: str = "",
    severity: str = "",
    search: str = "",
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(LogEntry).filter(LogEntry.user_id == user.id)
    if type:
        q = q.filter(LogEntry.type == type)
    if protocol:
        q = q.filter(LogEntry.protocol == protocol)
    if severity:
        q = q.filter(LogEntry.severity == severity)
    if search:
        like = f"%{search}%"
        q = q.filter(
            LogEntry.src_ip.ilike(like)
            | LogEntry.dst_ip.ilike(like)
            | LogEntry.message.ilike(like)
        )
    total = q.count()
    q = q.order_by(LogEntry.time.desc()).offset((page - 1) * page_size).limit(page_size)
    logs = q.all()
    return LogListResponse(
        logs=[
            LogEntryResponse(
                id=log_entry.id, time=log_entry.time, type=log_entry.type or "",
                protocol=log_entry.protocol or "",
                src_ip=log_entry.src_ip or "", src_port=log_entry.src_port or 0,
                dst_ip=log_entry.dst_ip or "", dst_port=log_entry.dst_port or 0,
                severity=log_entry.severity or "info", message=log_entry.message or "",
                device=log_entry.device_name or "",
            )
            for log_entry in logs
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/stats")
def log_stats(user: User = Depends(get_current_user),
              db: Session = Depends(get_db)):
    q = db.query(LogEntry).filter(LogEntry.user_id == user.id)
    total = q.count()
    firewall = q.filter(LogEntry.type == "Firewall").count()
    dns = q.filter(LogEntry.type == "DNS").count()
    http = q.filter(LogEntry.type == "HTTP").count()
    system = q.filter(LogEntry.type == "System").count()
    return {
        "total": total, "firewall": firewall, "dns": dns,
        "http": http, "system": system,
    }


@router.get("/export")
def export_logs(user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    logs = db.query(LogEntry).filter(
        LogEntry.user_id == user.id
    ).order_by(LogEntry.time.desc()).limit(10000).all()
    lines = ["time,type,protocol,src_ip,src_port,dst_ip,dst_port,severity,message,device"]
    for log_entry in logs:
        msg = (log_entry.message or "").replace('"', '""')
        lines.append(
            f"{log_entry.time},{log_entry.type or ''},{log_entry.protocol or ''},{log_entry.src_ip or ''},{log_entry.src_port or 0},"
            f"{log_entry.dst_ip or ''},{log_entry.dst_port or 0},{log_entry.severity or 'info'},\"{msg}\",{log_entry.device_name or ''}"
        )
    csv = "\n".join(lines)
    return Response(
        content=csv,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="coreids_logs.csv"'},
    )
