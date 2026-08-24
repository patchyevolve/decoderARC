"""Pydantic schemas for request/response validation."""

from datetime import datetime
from pydantic import BaseModel, EmailStr


# ─── Auth ────────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: str = ""
    company: str = ""


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class AuthResponse(BaseModel):
    token: str
    user_id: str
    email: str
    name: str
    plan: str


# ─── User ─────────────────────────────────────────────────────
class UserProfile(BaseModel):
    id: str
    email: str
    name: str
    company: str
    role: str
    created_at: datetime


# ─── Subscription ─────────────────────────────────────────────
class SubscriptionInfo(BaseModel):
    plan: str
    status: str
    sensors_allowed: int
    retention_days: int
    events_per_month_limit: int
    current_period_end: datetime | None = None


class PlanInfo(BaseModel):
    id: str
    name: str
    sensors: int
    retention_days: int
    events_per_month: int
    price_monthly: int  # cents
    price_yearly: int   # cents


# ─── Device ───────────────────────────────────────────────────
class DeviceCreate(BaseModel):
    name: str = ""


class DeviceResponse(BaseModel):
    id: str
    name: str
    api_key: str  # only shown once on creation
    status: str
    last_seen_at: datetime | None = None
    version: str
    location: str
    created_at: datetime


class DeviceUpdate(BaseModel):
    name: str | None = None
    location: str | None = None
    config_json: dict | None = None


class DeviceListItem(BaseModel):
    id: str
    name: str
    status: str
    last_seen_at: datetime | None = None
    version: str
    ip: str

    class Config:
        from_attributes = True


# ─── Alert ────────────────────────────────────────────────────
class AlertResponse(BaseModel):
    id: str
    time: datetime
    decision: str
    severity: str
    confidence: float
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    attack_class: str
    anomaly_score: float
    ae_score: float
    explanation: str
    acknowledged_at: datetime | None = None

    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    alerts: list[AlertResponse]
    total: int
    page: int
    page_size: int


# ─── Dashboard ────────────────────────────────────────────────
class OverviewStats(BaseModel):
    total_alerts: int
    high_severity: int
    medium_severity: int
    low_severity: int
    blocked_events: int
    alerts_trend: float   # % change
    high_trend: float
    traffic_gbps: float
    active_devices: int
    devices_online: int


class CategoryItem(BaseModel):
    name: str
    count: int
    percentage: float


class CategoryBreakdown(BaseModel):
    categories: list[CategoryItem]


class TalkerItem(BaseModel):
    ip: str
    alert_count: int
    last_seen: datetime


class TopTalkers(BaseModel):
    talkers: list[TalkerItem]


class TimelinePoint(BaseModel):
    time: str
    value: int


class AlertTimeline(BaseModel):
    points: list[TimelinePoint]


# ─── Ingestion (daemon-facing) ─────────────────────────────────
class IngestAlert(BaseModel):
    time: str
    decision: str
    severity: str
    confidence: float
    source_ip: str
    dest_ip: str
    source_port: int = 0
    dest_port: int = 0
    protocol: str = ""
    attack_class: str = ""
    anomaly_score: float = 0.0
    ae_score: float = 0.0
    explanation: str = ""
    raw_event: dict = {}


class IngestAlertBatch(BaseModel):
    device_id: str
    api_key: str = ""
    alerts: list[IngestAlert]


class IngestMetrics(BaseModel):
    device_id: str
    api_key: str = ""
    time: str
    events_per_sec: float = 0.0
    alerts_per_sec: float = 0.0
    blocks_per_sec: float = 0.0
    avg_latency_us: float = 0.0
    p99_latency_us: float = 0.0
    drift_score: float = 0.0
    memory_usage_pct: float = 0.0
    cpu_usage_pct: float = 0.0
    online_updates: int = 0


class IngestLog(BaseModel):
    time: str
    type: str = "Alert"
    protocol: str = ""
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    severity: str = "info"
    message: str = ""


class IngestLogBatch(BaseModel):
    device_id: str
    api_key: str = ""
    logs: list[IngestLog]


class IngestTrafficEvent(BaseModel):
    time: str
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = ""
    bytes: int = 0
    event_type: str = "network"
    metadata: dict = {}


class IngestTrafficBatch(BaseModel):
    device_id: str
    api_key: str = ""
    events: list[IngestTrafficEvent]


class HeartbeatRequest(BaseModel):
    device_id: str
    api_key: str = ""
    version: str = ""
    load: float = 0.0


# ─── Logs ─────────────────────────────────────────────────────
class LogEntryResponse(BaseModel):
    id: str
    time: datetime
    type: str
    protocol: str | None = ""
    src_ip: str | None = ""
    src_port: int = 0
    dst_ip: str | None = ""
    dst_port: int = 0
    severity: str | None = "info"
    message: str | None = ""
    device: str | None = ""

    class Config:
        from_attributes = True


class LogListResponse(BaseModel):
    logs: list[LogEntryResponse]
    total: int
    page: int
    page_size: int


# ─── Rules ────────────────────────────────────────────────────
class RuleCreate(BaseModel):
    name: str
    category: str = "Web Attack"
    severity: str = "medium"
    action: str = "Alert"
    protocol: str = "TCP"
    condition: str = ""


class RuleResponse(BaseModel):
    id: str
    sid: int
    name: str
    category: str
    severity: str
    protocol: str
    action: str
    enabled: bool
    triggers: int
    last_hit: str | None = ""

    class Config:
        from_attributes = True


class RuleListResponse(BaseModel):
    rules: list[dict]
    total: int
    active: int
    disabled: int
    triggered_today: int
    triggered_trend: float


# ─── Reports ──────────────────────────────────────────────────
class ReportGenerate(BaseModel):
    template_id: str
    range: str = "24h"
    format: str = "PDF"


class ReportScheduleCreate(BaseModel):
    name: str
    schedule: str = "0 0 * * *"
    recipients: str = ""


class ReportsResponse(BaseModel):
    templates: list[dict]
    recent: list[dict]
    scheduled: list[dict]


# ─── Generic ──────────────────────────────────────────────────
class Message(BaseModel):
    message: str
