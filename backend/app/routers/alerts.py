"""Alert ingestion (daemon-facing) + alert queries (user-facing)."""

import asyncio
import hashlib
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..broadcaster import broadcaster
from ..database import get_db
from ..models import User, Device, Alert, UsageMeter, LogEntry, TrafficEvent, Subscription, Metric
from ..schemas import (
    IngestAlertBatch, IngestMetrics, IngestLogBatch, IngestTrafficBatch, HeartbeatRequest,
    AlertListResponse, AlertResponse, Message,
)

router = APIRouter(tags=["Alerts"])

# Shared: daemon-facing ingestion routes
ingest_router = APIRouter(prefix="/api/v1", tags=["Ingestion"])

# Event loop for async broadcast from sync routes; set at startup by main.py
_event_loop = None


def _extract_api_key(request: Request, body_api_key: str = "") -> str:
    """Extract API key from Authorization header or request body."""
    if body_api_key:
        return body_api_key
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return ""


def _verify_device(device_id: str, api_key: str, db: Session) -> Device:
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    expected_hash = hashlib.sha256(api_key.encode()).hexdigest()
    if device.api_key_hash != expected_hash:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return device


def _check_usage_limit(user_id: str, db: Session):
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    meter = db.query(UsageMeter).filter(
        UsageMeter.user_id == user_id, UsageMeter.month == month
    ).first()
    if meter:
        sub = db.query(Subscription).filter(Subscription.user_id == user_id).first()
        if sub and meter.events_ingested >= sub.events_per_month_limit:
            raise HTTPException(
                status_code=429,
                detail=f"Monthly event limit ({sub.events_per_month_limit}) exceeded",
            )


# ─── Daemon-facing: batch alert ingestion ─────────────────────
@ingest_router.post("/ingest/alerts", response_model=Message)
def ingest_alerts(batch: IngestAlertBatch, request: Request, db: Session = Depends(get_db)):
    api_key = _extract_api_key(request, batch.api_key)
    device = _verify_device(batch.device_id, api_key, db)
    now = datetime.now(timezone.utc)

    # Check usage limit
    _check_usage_limit(device.user_id, db)

    alert_objs = []
    log_objs = []
    for a in batch.alerts:
        try:
            alert_time = datetime.fromisoformat(a.time.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            alert_time = now
        alert_objs.append(Alert(
            user_id=device.user_id, device_id=batch.device_id,
            time=alert_time, decision=a.decision, severity=a.severity,
            confidence=a.confidence, source_ip=a.source_ip, dest_ip=a.dest_ip,
            source_port=a.source_port, dest_port=a.dest_port,
            protocol=a.protocol, attack_class=a.attack_class,
            anomaly_score=a.anomaly_score, ae_score=a.ae_score,
            explanation=a.explanation,
        ))
        log_objs.append(LogEntry(
            user_id=device.user_id,
            device_id=batch.device_id,
            time=alert_time,
            type="Alert",
            protocol=a.protocol,
            src_ip=a.source_ip,
            src_port=a.source_port,
            dst_ip=a.dest_ip,
            dst_port=a.dest_port,
            severity=a.severity,
            message=a.explanation or a.attack_class or "IDS alert",
            device_name=device.name,
        ))
    db.add_all(alert_objs)
    db.add_all(log_objs)

    # Touch device heartbeat
    device.last_seen_at = now
    device.status = "online"
    ip = request.client.host if request.client else ""
    if ip:
        device.public_ip = ip
    db.commit()
    # Broadcast alerts to connected clients via shared event loop
    if alert_objs:
        loop = _event_loop
        for a_obj in alert_objs:
            try:
                coro = broadcaster.broadcast_alert(a_obj.user_id, {
                    "id": a_obj.id,
                    "time": str(a_obj.time),
                    "decision": a_obj.decision,
                    "severity": a_obj.severity,
                    "source_ip": a_obj.source_ip,
                    "dest_ip": a_obj.dest_ip,
                    "attack_class": a_obj.attack_class,
                })
                if loop is not None:
                    asyncio.run_coroutine_threadsafe(coro, loop)
            except Exception:
                pass
    return Message(message=f"Ingested {len(alert_objs)} alerts")


@ingest_router.post("/ingest/logs", response_model=Message)
def ingest_logs(batch: IngestLogBatch, request: Request, db: Session = Depends(get_db)):
    api_key = _extract_api_key(request, batch.api_key)
    device = _verify_device(batch.device_id, api_key, db)
    now = datetime.now(timezone.utc)

    log_objs = []
    for item in batch.logs:
        try:
            log_time = datetime.fromisoformat(item.time.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            log_time = now
        log_objs.append(LogEntry(
            user_id=device.user_id,
            device_id=batch.device_id,
            time=log_time,
            type=item.type or "System",
            protocol=item.protocol,
            src_ip=item.src_ip,
            src_port=item.src_port,
            dst_ip=item.dst_ip,
            dst_port=item.dst_port,
            severity=item.severity or "info",
            message=item.message,
            device_name=device.name,
        ))

    if log_objs:
        db.add_all(log_objs)

    device.last_seen_at = now
    device.status = "online"
    ip = request.client.host if request.client else ""
    if ip:
        device.public_ip = ip
    db.commit()
    return Message(message=f"Ingested {len(log_objs)} logs")


@ingest_router.post("/ingest/events", response_model=Message)
def ingest_events(batch: IngestTrafficBatch, request: Request, db: Session = Depends(get_db)):
    api_key = _extract_api_key(request, batch.api_key)
    device = _verify_device(batch.device_id, api_key, db)
    now = datetime.now(timezone.utc)

    traffic_objs = []
    log_objs = []
    for item in batch.events:
        try:
            event_time = datetime.fromisoformat(item.time.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            event_time = now

        protocol = (item.protocol or "").upper()
        traffic_objs.append(TrafficEvent(
            user_id=device.user_id,
            device_id=batch.device_id,
            time=event_time,
            src_ip=item.src_ip,
            src_port=item.src_port,
            dst_ip=item.dst_ip,
            dst_port=item.dst_port,
            protocol=protocol,
            bytes=max(0, int(item.bytes or 0)),
            event_type=item.event_type or "network",
            raw_event=item.metadata or {},
        ))
        log_objs.append(LogEntry(
            user_id=device.user_id,
            device_id=batch.device_id,
            time=event_time,
            type="Network",
            protocol=protocol,
            src_ip=item.src_ip,
            src_port=item.src_port,
            dst_ip=item.dst_ip,
            dst_port=item.dst_port,
            severity="info",
            message=f"{item.event_type or 'network'} bytes={max(0, int(item.bytes or 0))}",
            device_name=device.name,
        ))

    if traffic_objs:
        db.add_all(traffic_objs)
    if log_objs:
        db.add_all(log_objs)

    device.last_seen_at = now
    device.status = "online"
    ip = request.client.host if request.client else ""
    if ip:
        device.public_ip = ip
    db.commit()
    # Broadcast traffic events to connected clients via shared event loop
    if traffic_objs:
        loop = _event_loop
        for e_obj in traffic_objs:
            try:
                coro = broadcaster.broadcast_event(e_obj.user_id, {
                    "id": e_obj.id,
                    "time": str(e_obj.time),
                    "device_id": e_obj.device_id,
                    "src_ip": e_obj.src_ip,
                    "dst_ip": e_obj.dst_ip,
                    "bytes": e_obj.bytes,
                    "protocol": e_obj.protocol,
                })
                if loop is not None:
                    asyncio.run_coroutine_threadsafe(coro, loop)
            except Exception:
                pass
    return Message(message=f"Ingested {len(traffic_objs)} events")


# ─── Daemon-facing: metrics push ──────────────────────────────
@ingest_router.post("/ingest/metrics", response_model=Message)
def ingest_metrics(metrics: IngestMetrics, request: Request, db: Session = Depends(get_db)):
    api_key = _extract_api_key(request, metrics.api_key)
    device = _verify_device(metrics.device_id, api_key, db)

    try:
        metric_time = datetime.fromisoformat(metrics.time.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        metric_time = datetime.now(timezone.utc)

    m = Metric(
        device_id=metrics.device_id,
        user_id=device.user_id,
        time=metric_time,
        events_per_sec=metrics.events_per_sec,
        alerts_per_sec=metrics.alerts_per_sec,
        blocks_per_sec=metrics.blocks_per_sec,
        avg_latency_us=metrics.avg_latency_us,
        p99_latency_us=metrics.p99_latency_us,
        drift_score=metrics.drift_score,
        memory_usage_pct=metrics.memory_usage_pct,
        cpu_usage_pct=metrics.cpu_usage_pct,
        online_updates=metrics.online_updates,
    )
    db.add(m)
    device.last_seen_at = datetime.now(timezone.utc)
    device.status = "online"
    db.commit()
    return Message(message="Metrics recorded")


# ─── Daemon-facing: heartbeat ─────────────────────────────────
@ingest_router.post("/device/heartbeat", response_model=Message)
def device_heartbeat(req: HeartbeatRequest, request: Request, db: Session = Depends(get_db)):
    api_key = _extract_api_key(request, req.api_key)
    device = _verify_device(req.device_id, api_key, db)
    device.last_seen_at = datetime.now(timezone.utc)
    device.status = "online"
    if req.version:
        device.version = req.version
    ip = request.client.host if request.client else ""
    if ip:
        device.public_ip = ip
    db.commit()
    return Message(message="OK")


# ─── Daemon-facing: status check (no JWT needed) ───────────────
@ingest_router.get("/device/{device_id}/status", response_model=dict)
def device_status(device_id: str, api_key: str = Query(...),
                  db: Session = Depends(get_db)):
    device = _verify_device(device_id, api_key, db)
    now = datetime.now(timezone.utc)
    delta_s = 9999
    if device.last_seen_at:
        last = device.last_seen_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        delta_s = (now - last).total_seconds()
    online = delta_s < 120
    since = ""
    if device.last_seen_at:
        mins = int(delta_s // 60)
        if mins < 1:
            since = "just now"
        elif mins < 60:
            since = f"{mins} minutes ago"
        else:
            since = f"{mins // 60}h {mins % 60}m ago"
    return {
        "online": online,
        "status": "online" if online else "offline",
        "last_seen_human": since,
        "last_seen_at": device.last_seen_at.isoformat() if device.last_seen_at else None,
    }


# ─── Daemon-facing: pull config ───────────────────────────────
@ingest_router.get("/device/config", response_model=dict)
def device_config(device_id: str = Query(...), api_key: str = Query(...),
                  db: Session = Depends(get_db)):
    device = _verify_device(device_id, api_key, db)
    return {
        "device_id": device.id,
        "config": device.config_json or {},
    }


# ─── User-facing: list alerts ─────────────────────────────────
@router.get("/api/alerts", response_model=AlertListResponse)
def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    device_id: str | None = None,
    severity: str | None = None,
    attack_class: str | None = None,
    source_ip: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Alert).filter(Alert.user_id == user.id)

    if device_id:
        q = q.filter(Alert.device_id == device_id)
    if severity:
        q = q.filter(Alert.severity == severity)
    if attack_class:
        q = q.filter(Alert.attack_class == attack_class)
    if source_ip:
        q = q.filter(Alert.source_ip == source_ip)
    if time_from:
        try:
            q = q.filter(Alert.time >= datetime.fromisoformat(time_from))
        except ValueError:
            pass
    if time_to:
        try:
            q = q.filter(Alert.time <= datetime.fromisoformat(time_to))
        except ValueError:
            pass

    total = q.count()
    alerts = q.order_by(Alert.time.desc()).offset((page - 1) * page_size).limit(page_size).all()

    return AlertListResponse(
        alerts=[AlertResponse.model_validate(a) for a in alerts],
        total=total, page=page, page_size=page_size,
    )


# ─── User-facing: alert categories (donut chart) ──────────────
@router.get("/api/alerts/categories", response_model=dict)
def alert_categories(
    time_from: str | None = None,
    time_to: str | None = None,
    device_id: str | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Alert.attack_class, func.count(Alert.id)).filter(
        Alert.user_id == user.id
    )
    if device_id:
        q = q.filter(Alert.device_id == device_id)
    if time_from:
        try:
            q = q.filter(Alert.time >= datetime.fromisoformat(time_from))
        except ValueError:
            pass
    if time_to:
        try:
            q = q.filter(Alert.time <= datetime.fromisoformat(time_to))
        except ValueError:
            pass

    rows = q.group_by(Alert.attack_class).order_by(func.count(Alert.id).desc()).all()
    total = sum(r[1] for r in rows) or 1
    return {
        "categories": [
            {"name": r[0] or "unknown", "count": r[1],
             "percentage": round(r[1] / total * 100, 1)}
            for r in rows
        ]
    }
