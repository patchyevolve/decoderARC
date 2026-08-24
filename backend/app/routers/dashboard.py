"""Dashboard overview + analytics endpoints.

These directly map to the stat cards and charts in your wireframe.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from fastapi import HTTPException

from ..auth import get_current_user
from ..database import get_db
from ..models import User, Alert, Device, Metric, TrafficEvent

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


def _time_range(from_str: Optional[str], to_str: Optional[str],
                default_minutes: int = 15):
    now = datetime.now(timezone.utc)
    if to_str:
        try:
            to = datetime.fromisoformat(to_str)
        except ValueError:
            to = now
    else:
        to = now
    if from_str:
        try:
            from_dt = datetime.fromisoformat(from_str)
        except ValueError:
            from_dt = now - timedelta(minutes=default_minutes)
    else:
        from_dt = now - timedelta(minutes=default_minutes)
    return from_dt, to


def _previous_period(from_dt: datetime, to_dt: datetime):
    """Return the same-length period before from_dt."""
    duration = to_dt - from_dt
    prev_to = from_dt
    prev_from = prev_to - duration
    return prev_from, prev_to


@router.get("/overview")
def overview_stats(
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
    device_id: Optional[str] = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Returns the 5 stat cards + trends for the Overview page."""
    from_dt, to_dt = _time_range(time_from, time_to)
    prev_from, prev_to = _previous_period(from_dt, to_dt)

    # Current period counts
    q_base = db.query(Alert).filter(
        Alert.user_id == user.id,
        Alert.time >= from_dt, Alert.time < to_dt,
    )
    if device_id:
        q_base = q_base.filter(Alert.device_id == device_id)
    current_q = q_base
    total_alerts = current_q.count()
    high = current_q.filter(Alert.severity == "high").count()
    medium = current_q.filter(Alert.severity == "medium").count()
    low = current_q.filter(Alert.severity == "low").count()
    blocked = current_q.filter(Alert.decision == "block").count()

    # Previous period (for trend)
    prev_q = db.query(Alert).filter(
        Alert.user_id == user.id,
        Alert.time >= prev_from, Alert.time < prev_to,
    )
    if device_id:
        prev_q = prev_q.filter(Alert.device_id == device_id)
    prev_total = prev_q.count()

    # Trend: % change
    trend = 0.0
    if prev_total > 0:
        trend = round((total_alerts - prev_total) / prev_total * 100, 1)

    # Previous high count for high trend
    prev_high = prev_q.filter(Alert.severity == "high").count()
    high_trend = 0.0
    if prev_high > 0:
        high_trend = round((high - prev_high) / prev_high * 100, 1)

    # Device counts + online status (based on fresh heartbeat)
    stale_seconds = 120
    now_utc = datetime.now(timezone.utc)
    if device_id:
        devices = db.query(Device).filter(
            Device.user_id == user.id,
            Device.id == device_id,
        ).all()
    else:
        devices = db.query(Device).filter(Device.user_id == user.id).all()

    all_devices = len(devices)
    online = 0
    for d in devices:
        if not d.last_seen_at:
            continue
        last = d.last_seen_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        if (now_utc - last).total_seconds() < stale_seconds:
            online += 1

    # Traffic and event volume from raw ingested events
    duration_s = max((to_dt - from_dt).total_seconds(), 1.0)
    events_q = db.query(func.count(TrafficEvent.id), func.coalesce(func.sum(TrafficEvent.bytes), 0)).filter(
        TrafficEvent.user_id == user.id,
        TrafficEvent.time >= from_dt,
        TrafficEvent.time < to_dt,
    )
    if device_id:
        events_q = events_q.filter(TrafficEvent.device_id == device_id)
    events_row = events_q.first()
    events_count = int(events_row[0] or 0) if events_row else 0
    bytes_total = int(events_row[1] or 0) if events_row else 0

    # Traffic from latest metric (fallback if no raw event stream)
    metric_q = db.query(Metric).filter(Metric.user_id == user.id)
    if device_id:
        metric_q = metric_q.filter(Metric.device_id == device_id)
    latest_metric = metric_q.order_by(Metric.time.desc()).first()
    traffic_gbps = 0.0
    traffic_in_gbps = 0.0
    traffic_out_gbps = 0.0
    events_per_sec = 0.0
    avg_latency_us = 0.0
    total_events = events_count
    if latest_metric:
        events_ps = latest_metric.events_per_sec or 0
        if events_count == 0:
            events_per_sec = round(events_ps, 2)
            total_events = int(events_ps * duration_s)
            traffic_gbps = round(events_ps * 1024 / 1e9, 2)
            traffic_in_gbps = round(traffic_gbps * 0.6, 2)
            traffic_out_gbps = round(traffic_gbps * 0.4, 2)
        avg_latency_us = latest_metric.avg_latency_us or 0

    if events_count > 0:
        events_per_sec = round(events_count / duration_s, 2)
        traffic_bps = (bytes_total * 8) / duration_s
        traffic_gbps = round(traffic_bps / 1e9, 4)
        traffic_in_gbps = round(traffic_gbps * 0.6, 4)
        traffic_out_gbps = round(traffic_gbps * 0.4, 4)

    # Alert rate and benign %
    total_events_for_rate = max(total_events, total_alerts)
    alert_rate = round(total_alerts / total_events_for_rate * 100, 1) if total_events_for_rate > 0 else 0.0
    benign_pct = round(100.0 - alert_rate, 1)

    return {
        "total_alerts": total_alerts,
        "total_events": total_events,
        "events_per_sec": events_per_sec,
        "high_severity": high,
        "medium_severity": medium,
        "low_severity": low,
        "blocked_events": blocked,
        "alerts_trend": trend,
        "high_trend": high_trend,
        "traffic_gbps": traffic_gbps,
        "traffic_in_gbps": traffic_in_gbps,
        "traffic_out_gbps": traffic_out_gbps,
        "avg_latency_us": avg_latency_us,
        "alert_rate": alert_rate,
        "benign_pct": benign_pct,
        "active_devices": all_devices,
        "devices_online": online,
    }


@router.get("/top-talkers")
def top_talkers(
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
    limit: int = Query(10, ge=1, le=50),
    device_id: Optional[str] = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from_dt, to_dt = _time_range(time_from, time_to)
    q = db.query(Alert.source_ip, func.count(Alert.id), func.max(Alert.time)).filter(
        Alert.user_id == user.id,
        Alert.time >= from_dt, Alert.time < to_dt,
    )
    if device_id:
        q = q.filter(Alert.device_id == device_id)
    rows = q.group_by(Alert.source_ip).order_by(func.count(Alert.id).desc()).limit(limit).all()
    return {
        "talkers": [
            {"ip": r[0] or "unknown", "alert_count": r[1], "last_seen": r[2],
             "threat_score": min(100, round(r[1] * 5))}
            for r in rows
        ]
    }


@router.get("/alert-timeline")
def alert_timeline(
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
    interval: str = "1 minute",
    device_id: Optional[str] = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Time-series of alert counts for the traffic sparkline chart."""
    from_dt, to_dt = _time_range(time_from, time_to)

    # Validate interval against allowlist — prevents SQL injection
    VALID_INTERVALS = {"1 minute", "1 hour", "1 day"}
    if interval not in VALID_INTERVALS:
        raise HTTPException(status_code=400, detail="Invalid interval")

    engine = db.get_bind()
    is_sqlite = "sqlite" in str(engine.url)

    bucket_expr = func.date_trunc(interval, Alert.time)
    if is_sqlite:
        # SQLite doesn't have date_trunc; use strftime
        fmt_map = {"1 minute": "%Y-%m-%d %H:%M:00", "1 hour": "%Y-%m-%d %H:00:00",
                   "1 day": "%Y-%m-%d 00:00:00"}
        bucket_expr = func.strftime(fmt_map[interval], Alert.time)

    query = db.query(
        bucket_expr.label("bucket"),
        func.count(Alert.id).label("cnt")
    ).filter(
        Alert.user_id == user.id,
        Alert.time >= from_dt,
        Alert.time < to_dt,
    )
    if device_id:
        query = query.filter(Alert.device_id == device_id)

    rows = query.group_by("bucket").order_by("bucket").all()

    return {
        "points": [
            {"time": r[0] if isinstance(r[0], str) else r[0].isoformat(), "value": r[1]}
            for r in rows
        ]
    }
