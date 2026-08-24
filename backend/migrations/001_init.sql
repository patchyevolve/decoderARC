-- CoreIDS — initial schema
-- Run against Supabase SQL editor or psql

-- Extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Users
CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name          VARCHAR(255) DEFAULT '',
    company       VARCHAR(255) DEFAULT '',
    role          VARCHAR(50) DEFAULT 'customer',
    created_at    TIMESTAMPTZ DEFAULT now(),
    last_login    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Subscriptions
CREATE TABLE IF NOT EXISTS subscriptions (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id               UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    plan                  VARCHAR(50) DEFAULT 'free',
    status                VARCHAR(50) DEFAULT 'active',
    stripe_subscription_id VARCHAR(255) DEFAULT '',
    current_period_start  TIMESTAMPTZ,
    current_period_end    TIMESTAMPTZ,
    sensors_allowed       INT DEFAULT 1,
    retention_days        INT DEFAULT 7,
    events_per_month_limit BIGINT DEFAULT 1000000,
    created_at            TIMESTAMPTZ DEFAULT now(),
    updated_at            TIMESTAMPTZ DEFAULT now()
);

-- Devices
CREATE TABLE IF NOT EXISTS devices (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name           VARCHAR(255) DEFAULT '',
    api_key_hash   VARCHAR(255) NOT NULL,
    api_key_prefix VARCHAR(8) NOT NULL,
    status         VARCHAR(50) DEFAULT 'offline',
    last_seen_at   TIMESTAMPTZ,
    version        VARCHAR(50) DEFAULT '',
    public_ip      VARCHAR(45) DEFAULT '',
    location       VARCHAR(255) DEFAULT '',
    config_json    JSONB DEFAULT '{}',
    tags           JSONB DEFAULT '{}',
    created_at     TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);

-- Alerts
CREATE TABLE IF NOT EXISTS alerts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id       UUID REFERENCES devices(id) ON DELETE SET NULL,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    time            TIMESTAMPTZ NOT NULL,
    decision        VARCHAR(50) DEFAULT 'alert',
    severity        VARCHAR(20) DEFAULT 'medium',
    confidence      REAL DEFAULT 0,
    source_ip       VARCHAR(45) DEFAULT '',
    dest_ip         VARCHAR(45) DEFAULT '',
    source_port     INT DEFAULT 0,
    dest_port       INT DEFAULT 0,
    protocol        VARCHAR(10) DEFAULT '',
    attack_class    VARCHAR(100) DEFAULT '',
    anomaly_score   REAL DEFAULT 0,
    ae_score        REAL DEFAULT 0,
    explanation     TEXT DEFAULT '',
    raw_payload     JSONB DEFAULT '{}',
    acknowledged_at TIMESTAMPTZ,
    resolved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_alerts_user_time ON alerts(user_id, time DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_device_time ON alerts(device_id, time DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(user_id, severity, time DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(user_id, source_ip, time DESC);

-- Metrics (time-series)
CREATE TABLE IF NOT EXISTS metrics (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id        UUID REFERENCES devices(id) ON DELETE CASCADE,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    time             TIMESTAMPTZ NOT NULL DEFAULT now(),
    events_per_sec   REAL DEFAULT 0,
    alerts_per_sec   REAL DEFAULT 0,
    blocks_per_sec   REAL DEFAULT 0,
    avg_latency_us   REAL DEFAULT 0,
    p99_latency_us   REAL DEFAULT 0,
    drift_score      REAL DEFAULT 0,
    memory_usage_pct REAL DEFAULT 0,
    cpu_usage_pct    REAL DEFAULT 0,
    online_updates   INT DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_metrics_device_time ON metrics(device_id, time DESC);

-- Usage metering
CREATE TABLE IF NOT EXISTS usage_meters (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    month           VARCHAR(7) NOT NULL,
    events_ingested BIGINT DEFAULT 0,
    alerts_stored   BIGINT DEFAULT 0,
    created_at      TIMESTAMPTZ DEFAULT now(),
    UNIQUE(user_id, month)
);
