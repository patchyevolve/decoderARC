# decoderARC (CoreIDS) — Project Analysis

## What Is This?

A **production-grade real-time Intrusion Detection System (IDS)** deployed as SaaS. Edge sensors (daemons) capture network packets, detect threats locally or forward events to a central backend, which stores alerts and pushes them to a browser dashboard in real-time.

---

## Project Structure

```
decoderARC/
├── include/              # C++17 header-only IDS engine (24 headers)
│   ├── ids.hpp                    Main facade — 9-step detection pipeline
│   ├── ids_types.hpp              Shared structs, enums, config types
│   ├── ids_level0.hpp             L0 LocalAnalyzer — per-event 64-dim embedding
│   ├── ids_level1.hpp             L1 SegmentSSM — per-IP session SSM
│   ├── ids_ssm.hpp                L2 hierarchical SSM (L2s/L2m/L2l)
│   ├── ids_memory.hpp             Partitioned MemoryStore + Retriever
│   ├── ids_reasoning.hpp          Attention-based reasoning gate + score fusion
│   ├── ids_decision.hpp           Decision engine with 6-step override
│   ├── ids_correlation.hpp        Campaign tracking correlation engine
│   ├── ids_adaptive.hpp           Per-scope adaptive baselines
│   ├── ids_telemetry.hpp          Metrics, latency, drift series
│   ├── ids_sharded.hpp            ShardedIDS — N parallel pipeline instances
│   ├── ids_model.hpp              ModelHolder, parameter staging/apply
│   ├── ids_capture.hpp            libpcap packet capture bridge
│   ├── ids_cloud.hpp              CloudUploader — HTTP client for backend
│   ├── ids_ingest.hpp             CSV dataset ingester + calibration
│   ├── ids_parallel.hpp           Parallel processing utilities
│   ├── ids_thread_pool.hpp        Thread pool implementation
│   ├── ids_fused_engine.hpp       Fused engine combining multiple subsystems
│   ├── ids_specialist.hpp         Specialist detection modules
│   ├── ids_specialist_impl.hpp    Specialist implementations
│   ├── ids_specialist_ddos.hpp    DDoS specialist detector
│   ├── ids_nn.hpp                 Neural network (autoencoder) component
│   ├── ids_c_api.h                C API header for Python/FFI bridge
│   └── ids_cloud.hpp              Cloud uploader (libcurl-based)
│
├── tools/                # Daemon and deployment tools
│   ├── ids_production.cpp         Main production daemon (668 lines)
│   ├── ids_production.conf        Default daemon config
│   ├── ids.service                systemd service unit
│   ├── ids_collector.cpp          Real-time packet capture daemon
│   ├── ids_c_api.cpp              C API implementation (bridge to Python)
│   ├── ids_xdp.c                  eBPF/XDP kernel packet parser
│   └── ids_xdp.o                  Compiled BPF object
│
├── backend/              # Python/FastAPI SaaS backend
│   ├── Dockerfile                 Python 3.12-slim image
│   ├── requirements.txt           FastAPI, SQLAlchemy, etc.
│   ├── libids_central.so          Compiled C++ IDS shared library
│   ├── coreids.db                 SQLite dev database
│   ├── migrations/001_init.sql    PostgreSQL schema migration
│   ├── static/
│   │   ├── index.html             Full SPA frontend (1760 lines)
│   │   └── install.sh             Sensor one-liner installer
│   └── app/
│       ├── main.py                FastAPI entry point
│       ├── config.py              Settings from env vars
│       ├── database.py            SQLAlchemy engine + session
│       ├── models.py              ORM models (10 tables)
│       ├── schemas.py             Pydantic request/response schemas
│       ├── auth.py                JWT + API key auth
│       ├── broadcaster.py         In-memory pub/sub for WebSocket/SSE
│       ├── central_runtime.py     Event processing runtime (4 workers)
│       ├── ids_bridge.py          ctypes bridge to libids_central.so
│       ├── circuit_breaker.py     Circuit breaker for fault tolerance
│       ├── ratelimit.py           Sliding window rate limiter
│       ├── logging_config.py      Structured logging
│       └── routers/
│           ├── auth.py            /api/auth/* (register, login, profile)
│           ├── devices.py         /api/devices/* (CRUD, key mgmt)
│           ├── alerts.py          /api/alerts/* + /api/v1/ingest/*
│           ├── dashboard.py       /api/dashboard/* (overview, timeline, talkers)
│           ├── logs.py            /api/logs/* (query, export)
│           ├── rules.py           /api/rules/* (CRUD, import/export)
│           ├── reports.py         /api/reports/* (generate, schedule)
│           └── stream.py          /stream/alerts (SSE) + /ws/alerts (WebSocket)
│
├── real_datasets/        # 24 CSV datasets for training/testing
├── CMakeLists.txt        # CMake build system
├── Dockerfile            # Sensor multi-stage build (Alpine)
└── .github/workflows/ci.yml  # CI pipeline
```

---

## Total Components Count

| Category | Count |
|----------|-------|
| C++ header files | 24 |
| C++ source files (tools/) | 5 |
| Python modules (backend/app/) | 15 |
| Backend API routers | 8 |
| Database tables | 10 |
| Frontend pages | 10 |
| Environment variables | 9 |
| Daemon config keys | 14 |
| CI/CD jobs | 4 |

---

## How the Daemon Detects Threats

### Packet Capture

The daemon (`tools/ids_production.cpp`) uses **AF_PACKET raw sockets** to capture packets on a network interface (e.g., `eth0`). It parses:

- Ethernet frame header
- IPv4/IPv6 header (source/dest IPs)
- TCP/UDP header (source/dest ports, protocol)

### Event Construction

Raw packets are converted into `ids::Event` objects with fields:

- `source` / `destination` — IP addresses
- `payload.bytes_in` — packet size
- `payload.port_src` / `payload.port_dst` — ports
- `payload.protocol` — TCP/UDP/ICMP
- `payload.entropy` — payload randomness
- `payload.rate_hz` — traffic rate

### 9-Step Detection Pipeline

Each event flows through this pipeline (`include/ids.hpp`):

```
[1] L0 LocalAnalyzer     — sliding window, 64-dim embedding, anomaly score
[2] L1 SegmentSSM        — per-IP Mamba SSM accumulates events
[3-4] L2 Hierarchy       — L2s -> L2m -> L2l signal-driven promotion
[5] Memory Write          — score-gated, partitioned by IP/user/host/session
[6] Retrieval             — scoped narrow->broad, top-8 records, recency-weighted
[7] Reasoning Gate        — weighted 6-signal attention gate + score fusion
[7.5] Correlation Engine  — repeat/multi-stage/distributed attack detection
[8] Decision Engine       — 6-step override, hysteresis, cooldown
```

### What Gets Detected

- Port scans, brute-force login attempts
- DoS/DDoS floods
- Lateral movement within network
- APT / slow-burn attacks
- Ransomware activity
- Encrypted C2 channels
- Data exfiltration
- Privilege escalation
- Multi-stage attack chains

### Detection Thresholds

| Threshold | Score | Action |
|-----------|-------|--------|
| Alert | 0.70 | Log alert |
| Block | 0.92 | Block traffic |
| Escalate | 0.995 | Escalate to admin |

---

## How the Daemon Sends Data to Backend

### CloudUploader (`include/ids_cloud.hpp`)

A background thread batches data and sends it over HTTPS using libcurl:

| Endpoint | Frequency | Data |
|----------|-----------|------|
| `POST /api/v1/ingest/alerts` | Every 5s | Batched alerts (JSON) |
| `POST /api/v1/ingest/events` | Every 5s | Raw traffic events |
| `POST /api/v1/ingest/logs` | Every 5s | Log entries |
| `POST /api/v1/ingest/metrics` | Every 60s | Performance metrics (EPS, latency, drift) |
| `POST /api/v1/device/heartbeat` | Every 30s | Device liveness check |

### Authentication

API key sent in header: `Authorization: Bearer <api_key>`

### Forwarder-Only Mode

By default (`forwarder_only=true`), the daemon captures packets but does NOT run local inference. It forwards raw events to the backend, which runs the IDS engine centrally. This reduces resource usage on the sensor.

---

## Backend (FastAPI + Python)

### Stack

- **Framework**: FastAPI (Python 3.12)
- **ORM**: SQLAlchemy 2.0
- **Database**: PostgreSQL (SQLite fallback for dev)
- **Auth**: JWT (HttpOnly cookies) + API key hashing (SHA-256)
- **Password hashing**: PBKDF2-SHA256, 600K iterations

### Request Flow

```
Daemon POST /api/v1/ingest/events
  -> Backend verifies device_id + api_key hash
  -> Stores in traffic_events table (processed=false)
  -> UserRuntimeManager (4 worker threads) picks up unprocessed events
  -> Routes to per-user UserRuntime queues
  -> Calls ids_bridge.py -> libids_central.so (C shared library)
  -> C API creates per-user ShardedIDS (4 shards each)
  -> Full IDS pipeline runs
  -> If alert: stores Alert + LogEntry in DB
  -> Broadcasts to connected WebSocket/SSE clients
```

### API Endpoints

#### Daemon-Facing (authenticated via API key)

| Endpoint | Purpose |
|----------|---------|
| `POST /api/v1/ingest/alerts` | Receive batched alerts |
| `POST /api/v1/ingest/events` | Receive raw traffic events |
| `POST /api/v1/ingest/logs` | Receive log entries |
| `POST /api/v1/ingest/metrics` | Receive performance metrics |
| `POST /api/v1/device/heartbeat` | Device keepalive |
| `GET /api/v1/device/config` | Pull device configuration |

#### User-Facing (authenticated via JWT)

| Router | Prefix | Key Endpoints |
|--------|--------|---------------|
| auth | `/api/auth` | register, login, logout, me, plans, subscription |
| devices | `/api/devices` | CRUD, regenerate key, test connection |
| alerts | `/api/alerts` | list, filter, paginate, categories |
| dashboard | `/api/dashboard` | overview, top-talkers, alert-timeline, severity-breakdown |
| logs | `/api/logs` | list, stats, export CSV |
| rules | `/api/rules` | CRUD, toggle, import/export JSON |
| reports | `/api/reports` | templates, generate, schedule, download |
| stream | `/stream/*`, `/ws/*` | SSE and WebSocket real-time alerts |

### Database (10 Tables)

| Table | Purpose |
|-------|---------|
| `users` | User accounts (UUID PK, email, password_hash, role) |
| `subscriptions` | Plans (free/pro/enterprise), Stripe integration |
| `devices` | Sensor deployments (api_key_hash, status, config_json) |
| `alerts` | Security alerts (decision, severity, confidence, attack_class) |
| `metrics` | Time-series device health (EPS, latency, drift_score) |
| `logs` | Log entries (type, protocol, src/dst IP, severity) |
| `traffic_events` | Raw traffic events (processed flag for worker claiming) |
| `rules` | Detection rules (SID, category, severity, condition) |
| `reports` | Generated reports (template, format, file_path) |
| `report_schedules` | Scheduled report configs (cron, recipients) |
| `usage_meters` | Monthly usage tracking |

### Fault Tolerance

- **Circuit breaker**: CLOSED -> OPEN -> HALF_OPEN for external deps
- **Rate limiter**: 5 attempts per 300s sliding window
- **DB fallback**: PostgreSQL unreachable -> falls back to SQLite
- **Security headers**: CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy

---

## Frontend (Plain HTML/JS SPA)

**File**: `backend/static/index.html` (1760 lines, no build step)

### Pages

| Page | Description |
|------|-------------|
| Overview | 5 stat cards, alert timeline sparkline, categories chart, recent alerts, top talkers |
| Alerts | Paginated alert table with severity filter and IP search |
| Logs | Log viewer with type/protocol/severity filters, search, CSV export |
| Traffic | Traffic stats, inbound/outbound breakdown, sparkline |
| Analytics | Event stats, alert rate, benign %, avg latency, attack categories |
| Devices | Device grid with status dots, create, test, reinstall, uninstall, delete |
| Sources | Top source IPs table with alert count and threat score |
| Rules | Rule CRUD, toggle enable/disable, import/export JSON |
| Reports | Templates, recent reports, scheduled reports, generate/download |
| Settings | Profile, subscription plan comparison, API key management |

### Auth Flow

1. Login form POSTs to `/api/auth/login`
2. Server sets `HttpOnly` cookie + returns JWT in body
3. Frontend stores JWT in memory, sends in `Authorization` header
4. Server checks cookie first, then header
5. Logout clears cookie via `POST /api/auth/logout`

### Real-Time Updates

- Polls every 15 seconds (`setInterval(refreshAll, 15000)`)
- WebSocket (`/ws/alerts`) or SSE (`/stream/alerts`) for instant alert push
- "LIVE" indicator shows when devices are online

### Styling

Dark theme with CSS variables:
- Background: `#090d13` (deep navy)
- Panels: `#0e1421`
- Primary: `#3b82f6` (blue)
- Accent: `#06b6d4` (cyan)

---

## How All Three Components Connect

```
┌─────────────────────┐
│   Frontend (SPA)    │  Plain HTML/JS, 1760 lines
│   index.html        │  Dark theme, 10 pages
└─────────┬───────────┘
          │ HTTP(S) + JWT auth
          │ Polls every 15s + WebSocket/SSE for real-time
┌─────────v───────────┐
│   Backend (FastAPI) │  Python 3.12, 8 routers
│   4 runtime workers │  C bridge to libids_central.so
└─────────┬───────────┘
          │
    ┌─────┴─────┐
    │           │
┌───v───┐  ┌───v───────────┐
│PostgreSQL│ │  libids_central.so │  C++ IDS engine
│ 10 tables│ │  ShardedIDS/user   │  4 shards each
└───────┘  └───────▲───────────┘
                   │
          ┌────────┴────────┐
          │   Daemon        │  C++17, AF_PACKET capture
          │ ids_production  │  CloudUploader (libcurl)
          │ Deployed via    │  Docker or native binary
          │ Docker/systemd  │
          └─────────────────┘
          Customer sites (edge)
```

### Data Flow Summary

1. **Daemon** captures packets on customer network
2. **Daemon** either runs local IDS or forwards events to backend
3. **Backend** stores events, runs central IDS via C bridge
4. **Backend** stores alerts in PostgreSQL
5. **Backend** broadcasts alerts to connected frontends via WebSocket/SSE
6. **Frontend** displays real-time dashboard with stats, alerts, logs, devices

---

## Deployment Options

| Component | Method |
|-----------|--------|
| Daemon | Docker container or native binary via `install.sh` |
| Backend | Docker container (`docker compose up`) |
| Frontend | Served by FastAPI from `static/index.html` |

### Subscription Tiers

| Feature | Free | Pro ($49/mo) | Enterprise ($199/mo) |
|---------|------|-------------|---------------------|
| Sensors | 1 | 5 | Unlimited |
| Retention | 7 days | 30 days | 1 year |
| Events/month | 1M | 10M | Unlimited |
