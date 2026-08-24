"""SQLAlchemy ORM models."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, Float, Integer, BigInteger, Boolean,
    DateTime, ForeignKey, Text, JSON, Index, UniqueConstraint,
)
from sqlalchemy.orm import relationship

from .database import Base


def _utcnow():
    return datetime.now(timezone.utc)


def _uuid():
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    name = Column(String(255), default="")
    company = Column(String(255), default="")
    role = Column(String(50), default="customer")  # customer | admin
    created_at = Column(DateTime, default=_utcnow)
    last_login = Column(DateTime, nullable=True)

    subscription = relationship("Subscription", uselist=False, back_populates="user")
    devices = relationship("Device", back_populates="user")


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id"), unique=True, nullable=False)
    plan = Column(String(50), default="free")  # free | pro | enterprise
    status = Column(String(50), default="active")  # active | past_due | cancelled
    stripe_subscription_id = Column(String(255), default="")
    current_period_start = Column(DateTime, nullable=True)
    current_period_end = Column(DateTime, nullable=True)
    sensors_allowed = Column(Integer, default=1)
    retention_days = Column(Integer, default=7)
    events_per_month_limit = Column(BigInteger, default=1_000_000)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)

    user = relationship("User", back_populates="subscription")


class Device(Base):
    __tablename__ = "devices"

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(255), default="")
    api_key_hash = Column(String(255), nullable=False)
    api_key_prefix = Column(String(8), nullable=False)  # first 8 chars for identification
    status = Column(String(50), default="offline")  # offline | online | error
    last_seen_at = Column(DateTime, nullable=True)
    version = Column(String(50), default="")
    public_ip = Column(String(45), default="")
    location = Column(String(255), default="")
    config_json = Column(JSON, default=dict)
    tags = Column(JSON, default=dict)
    created_at = Column(DateTime, default=_utcnow)

    user = relationship("User", back_populates="devices")

    __table_args__ = (
        Index("idx_devices_user", "user_id"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, default=_uuid)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    time = Column(DateTime, nullable=False, index=True)
    decision = Column(String(50), default="alert")
    severity = Column(String(20), default="medium")  # low | medium | high | critical
    confidence = Column(Float, default=0.0)
    source_ip = Column(String(45), default="")
    dest_ip = Column(String(45), default="")
    source_port = Column(Integer, default=0)
    dest_port = Column(Integer, default=0)
    protocol = Column(String(10), default="")
    attack_class = Column(String(100), default="")
    anomaly_score = Column(Float, default=0.0)
    ae_score = Column(Float, default=0.0)
    explanation = Column(Text, default="")
    raw_payload = Column(JSON, default=dict)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_utcnow)

    __table_args__ = (
        Index("idx_alerts_user_time", "user_id", "time"),
        Index("idx_alerts_device_time", "device_id", "time"),
        Index("idx_alerts_severity", "user_id", "severity", "time"),
    )


class Metric(Base):
    __tablename__ = "metrics"

    id = Column(String, primary_key=True, default=_uuid)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    time = Column(DateTime, nullable=False, index=True)
    events_per_sec = Column(Float, default=0.0)
    alerts_per_sec = Column(Float, default=0.0)
    blocks_per_sec = Column(Float, default=0.0)
    avg_latency_us = Column(Float, default=0.0)
    p99_latency_us = Column(Float, default=0.0)
    drift_score = Column(Float, default=0.0)
    memory_usage_pct = Column(Float, default=0.0)
    cpu_usage_pct = Column(Float, default=0.0)
    online_updates = Column(Integer, default=0)

    __table_args__ = (
        Index("idx_metrics_device_time", "device_id", "time"),
    )


class LogEntry(Base):
    __tablename__ = "logs"

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=True)
    time = Column(DateTime, nullable=False, index=True)
    type = Column(String(50), default="alert")
    protocol = Column(String(10), default="")
    src_ip = Column(String(45), default="")
    src_port = Column(Integer, default=0)
    dst_ip = Column(String(45), default="")
    dst_port = Column(Integer, default=0)
    severity = Column(String(20), default="info")
    message = Column(Text, default="")
    device_name = Column(String(255), default="")
    created_at = Column(DateTime, default=_utcnow)

    __table_args__ = (
        Index("idx_logs_user_time", "user_id", "time"),
        Index("idx_logs_type", "user_id", "type"),
    )


class TrafficEvent(Base):

    __tablename__ = "traffic_events"

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    device_id = Column(String, ForeignKey("devices.id"), nullable=False, index=True)
    time = Column(DateTime, nullable=False, index=True)
    src_ip = Column(String(45), default="")
    src_port = Column(Integer, default=0)
    dst_ip = Column(String(45), default="")
    dst_port = Column(Integer, default=0)
    protocol = Column(String(16), default="")
    bytes = Column(Integer, default=0)
    event_type = Column(String(32), default="network")
    raw_event = Column(JSON, default=dict)
    created_at = Column(DateTime, default=_utcnow)
    processed = Column(Boolean, default=False, index=True)

    __table_args__ = (
        Index("idx_traffic_events_user_time", "user_id", "time"),
        Index("idx_traffic_events_device_time", "device_id", "time"),
        Index("idx_traffic_events_user_src", "user_id", "src_ip", "time"),
        Index("idx_traffic_events_processed", "processed"),
    )


class Rule(Base):
    __tablename__ = "rules"

    id = Column(String, primary_key=True, default=_uuid)
    sid = Column(Integer, nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    category = Column(String(100), default="Web Attack")
    severity = Column(String(20), default="medium")
    protocol = Column(String(10), default="TCP")
    action = Column(String(50), default="Alert")
    enabled = Column(Boolean, default=True)
    triggers = Column(Integer, default=0)
    last_hit = Column(DateTime, nullable=True)
    condition = Column(Text, default="")
    created_at = Column(DateTime, default=_utcnow)

    __table_args__ = (
        Index("idx_rules_user_sid", "user_id", "sid"),
    )


class Report(Base):
    __tablename__ = "reports"

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    type = Column(String(50), default="daily")
    format = Column(String(10), default="PDF")
    template_id = Column(String(100), default="")
    file_path = Column(String(500), default="")
    generated_at = Column(DateTime, default=_utcnow)
    created_at = Column(DateTime, default=_utcnow)

    __table_args__ = (
        Index("idx_reports_user", "user_id"),
    )


class ReportSchedule(Base):
    __tablename__ = "report_schedules"

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    schedule = Column(String(100), default="0 0 * * *")
    recipients = Column(String(500), default="")
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=_utcnow)


class UsageMeter(Base):
    __tablename__ = "usage_meters"

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    month = Column(String(7), nullable=False)  # "2026-05"
    events_ingested = Column(BigInteger, default=0)
    alerts_stored = Column(BigInteger, default=0)
    created_at = Column(DateTime, default=_utcnow)

    __table_args__ = (
        UniqueConstraint("user_id", "month", name="uq_usage_user_month"),
    )
