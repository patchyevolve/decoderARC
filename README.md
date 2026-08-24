# CoreIDS — Intrusion Detection System

A production-grade, real-time IDS as a SaaS platform. Edge sensors (daemons) capture network packets, detect threats using a 9-step C++17 pipeline, and stream alerts to a web dashboard via a FastAPI backend.

**Detection latency**: under 300 µs per event on a single core.

---

## What Is This?

CoreIDS is a complete IDS platform with three components:

| Component | Technology | Location |
|-----------|-----------|----------|
| **Daemon** (sensor) | C++17, AF_PACKET capture | `tools/ids_production.cpp`, `include/` |
| **Backend** (API) | Python 3.12, FastAPI, SQLAlchemy | `backend/app/` |
| **Frontend** (dashboard) | Plain HTML/JS SPA | `backend/static/index.html` |

The daemon runs at customer sites, captures packets, and detects threats locally or forwards events to the backend for central inference. The backend stores alerts, runs the IDS engine via a C shared library, and pushes real-time updates to the browser dashboard via WebSocket.

---

## What Can It Detect?

- Port scans and reconnaissance
- Brute-force and credential stuffing
- DoS / DDoS bursts (single source and distributed)
- Lateral movement sequences
- APT / slow-burn attacks
- Ransomware and file system anomalies
- Encrypted C2 channels and data exfiltration
- Multi-stage attack chains (scan → brute force → lateral → exfil)
- Any custom pattern via rules or multi-stage sequence configs

---

## Architecture

```
┌─────────────────────┐
│   Frontend (SPA)    │  Plain HTML/JS, dark theme, 10 pages
│   index.html        │  WebSocket real-time alerts + 15s polling
└─────────┬───────────┘
          │ HTTP(S) + JWT auth
┌─────────v───────────┐
│   Backend (FastAPI) │  Python 3.12, 8 API routers
│   4 runtime workers │  C bridge to libids_central.so
└─────────┬───────────┘
          │
    ┌─────┴─────┐
    │           │
┌───v───┐  ┌───v───────────────┐
│PostgreSQL│ │  libids_central.so │  C++ IDS engine (4 shards/user)
│ 10 tables│ │  ShardedIDS        │
└───────┘  └───────▲───────────────┘
                   │
          ┌────────┴────────┐
          │   Daemon        │  C++17, AF_PACKET, CloudUploader
          │ ids_production  │  Docker or native binary
          └─────────────────┘
          Customer sites (edge)
```

### 9-Step Detection Pipeline

Defined in `include/ids.hpp`:

```
Event
  ├─ [1]   L0 LocalAnalyzer     — sliding window, 64-dim embedding, Z-score anomaly
  ├─ [2]   L1 SegmentSSM        — per-IP Mamba SSM, 5-condition flush
  ├─ [3-4] L2 Hierarchy         — L2s → L2m → L2l, signal-driven promotion
  ├─ [5]   Memory Write         — score-gated, partitioned by IP/user/host/session
  ├─ [6]   Retrieval            — cosine similarity, top-8, recency-weighted
  ├─ [7]   Reasoning Gate       — 6-signal weighted fusion, attention pooling
  ├─ [7.5] Correlation Engine   — repeat/multi-stage/distributed/slow detection
  └─ [8]   Decision Engine      — hysteresis, cooldown, escalation, overrides
```

### Detection Results (CICIDS2017 datasets)

| Attack Type | Recall | F1 |
|-------------|--------|-----|
| DoS Hulk | 100% | 100% |
| FTP Brute Force | 100% | 100% |
| DDoS Loit | 79.9% | 88.8% |
| SSH Brute Force | 59.8% | 74.9% |
| Port Scan | 46.2% | 63.2% |
| **Global** | **76.7%** | **86.8%** |

Precision: 100% (zero false positives among attack events).

---

## File Structure

```
decoderARC/
├── include/                          # C++17 header-only IDS engine (24 headers)
│   ├── ids.hpp                       # Main facade — 9-step pipeline
│   ├── ids_types.hpp                 # All shared structs, enums, config types
│   ├── ids_level0.hpp                # L0 LocalAnalyzer — 64-dim embedding
│   ├── ids_level1.hpp                # L1 SegmentSSM — per-IP session SSM
│   ├── ids_ssm.hpp                   # L2 hierarchical SSM (L2s/L2m/L2l)
│   ├── ids_memory.hpp                # Partitioned MemoryStore + Retriever
│   ├── ids_reasoning.hpp             # Attention-based reasoning gate
│   ├── ids_decision.hpp              # Decision engine with 6-step override
│   ├── ids_correlation.hpp           # Campaign tracking correlation engine
│   ├── ids_adaptive.hpp              # Per-scope adaptive baselines
│   ├── ids_telemetry.hpp             # Metrics, latency, drift series
│   ├── ids_sharded.hpp               # ShardedIDS — N parallel pipelines
│   ├── ids_model.hpp                 # ModelHolder, parameter staging
│   ├── ids_capture.hpp               # libpcap packet capture bridge
│   ├── ids_cloud.hpp                 # CloudUploader — HTTP client for backend
│   ├── ids_ingest.hpp                # CSV dataset ingester + calibration
│   ├── ids_nn.hpp                    # Neural network (autoencoder) component
│   ├── ids_parallel.hpp              # Parallel processing utilities
│   ├── ids_thread_pool.hpp           # Thread pool implementation
│   ├── ids_fused_engine.hpp          # Fused engine combining subsystems
│   ├── ids_specialist.hpp            # Specialist detection modules
│   ├── ids_specialist_impl.hpp       # Specialist implementations
│   ├── ids_specialist_ddos.hpp       # DDoS specialist detector
│   └── ids_c_api.h                   # C API header for Python FFI bridge
│
├── tools/                            # Daemon and deployment tools
│   ├── ids_production.cpp            # Main production daemon (668 lines)
│   ├── ids_production.conf           # Default daemon config
│   ├── ids.service                   # systemd service unit
│   ├── ids_collector.cpp             # Real-time packet capture daemon
│   ├── ids_c_api.cpp                 # C API implementation (Python bridge)
│   ├── ids_xdp.c                     # eBPF/XDP kernel packet parser
│   └── ids_xdp.o                     # Compiled BPF object
│
├── backend/                          # Python/FastAPI SaaS backend
│   ├── Dockerfile                    # Python 3.12-slim image
│   ├── requirements.txt              # FastAPI, SQLAlchemy, etc.
│   ├── libids_central.so             # Compiled C++ IDS shared library
│   ├── migrations/001_init.sql       # PostgreSQL schema migration
│   ├── static/
│   │   ├── index.html                # Full SPA frontend (1800+ lines)
│   │   └── install.sh                # Sensor one-liner installer script
│   └── app/
│       ├── main.py                   # FastAPI entry point
│       ├── config.py                 # Settings from env vars
│       ├── database.py               # SQLAlchemy engine + session
│       ├── models.py                 # ORM models (10 tables)
│       ├── schemas.py                # Pydantic request/response schemas
│       ├── auth.py                   # JWT + API key auth
│       ├── broadcaster.py            # In-memory pub/sub for WebSocket/SSE
│       ├── central_runtime.py        # Event processing runtime (4 workers)
│       ├── ids_bridge.py             # ctypes bridge to libids_central.so
│       ├── circuit_breaker.py        # Circuit breaker for fault tolerance
│       ├── ratelimit.py              # Sliding window rate limiter
│       ├── logging_config.py         # Structured logging setup
│       └── routers/
│           ├── auth.py               # /api/auth/* (register, login, profile)
│           ├── devices.py            # /api/devices/* (CRUD, key mgmt)
│           ├── alerts.py             # /api/alerts/* + /api/v1/ingest/*
│           ├── dashboard.py          # /api/dashboard/* (overview, timeline)
│           ├── logs.py               # /api/logs/* (query, export)
│           ├── rules.py              # /api/rules/* (CRUD, import/export)
│           ├── reports.py            # /api/reports/* (generate, schedule)
│           └── stream.py             # /stream/alerts (SSE) + /ws/alerts (WS)
│
├── tests/                            # Automated tests with assertions
│   ├── ids_unit_tests.cpp            # 21 unit tests (all pipeline stages)
│   └── ids_e2e_test.cpp              # End-to-end detection evaluation
│
├── real_datasets/                    # 21 CICIDS2017 CSV datasets (2.8 GB)
├── CMakeLists.txt                    # CMake build system
├── Dockerfile                        # Sensor multi-stage build (Alpine)
├── README.md                         # This file
├── ARCHITECTURE.md                   # SaaS architecture documentation
├── DETECTION_ANALYSIS.md             # Detection engine deep-dive
└── PROJECT_ANALYSIS.md               # Full project analysis
```

---

## Build

Requires: C++17, CMake >= 3.16, GCC 9+ or Clang 10+.

```bash
# Install optional dependencies
# Ubuntu/Debian
sudo apt install libpcap-dev libncurses-dev libcurl4-openssl-dev

# RHEL/Fedora
sudo dnf install libpcap-devel ncurses-devel libcurl-devel

# Build everything
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

This builds:

| Target | Description |
|--------|-------------|
| `ids_production` | Production daemon (requires libcurl for cloud upload) |
| `ids_central` | Shared library for Python FFI bridge |
| `ids_demo` | Integration demo (5-phase attack simulation) |
| `ids_dataset_demo` | Dataset calibration and evaluation |
| `ids_visualizer` | Live ncurses dashboard (requires libpcap + ncurses) |
| `ids_unit_tests` | 21 unit tests across all pipeline stages |
| `ids_e2e_test` | End-to-end detection evaluation on CICIDS2017 data |

---

## Run Tests

```bash
# Unit tests (L0, SSM, Memory, Reasoning, Decision, CSV parsing)
./build/ids_unit_tests

# End-to-end detection evaluation (trains on benign, tests on attacks)
./build/ids_e2e_test
```

---

## Quick Start

### As a library

```cpp
#include "ids.hpp"

ids::IDSConfig cfg;
cfg.gate.gate_threshold        = 0.35f;
cfg.thresholds.alert_threshold = 0.55f;
cfg.thresholds.block_threshold = 0.80f;

ids::IDS pipeline(cfg);

pipeline.on_alert([](const ids::Alert& a) {
    std::cout << "ALERT " << a.attack_class
              << " conf=" << a.confidence
              << " src=" << a.source << "\n";
});

ids::Event ev;
ev.source      = "192.168.1.100";
ev.destination = "10.0.0.1";
ev.type        = ids::EventType::NetworkPacket;
ev.payload.port_src = 12345;
ev.payload.port_dst = 80;
ev.payload.protocol = 6;
ev.payload.bytes_in = 1500;
ev.payload.rate_hz = 5000.f;
ev.payload.entropy = 0.9f;

pipeline.ingest(ev);
```

### As a daemon

```bash
# Live capture on eth0
sudo ./build/ids_production eth0

# Replay a CSV dataset
./build/ids_production --replay real_datasets/portscan.csv

# Train on benign traffic
./build/ids_production --train real_datasets/monday_benign.csv --train-only

# With cloud backend
./build/ids_production eth0 --config /etc/ids/config.conf
```

### Docker

```bash
# Build sensor image
docker build -t coreids-sensor .

# Run
docker run --rm --net=host --cap-add=NET_RAW coreids-sensor eth0

# Build backend image
docker build -t coreids-backend backend/
docker run -p 8000:8000 coreids-backend
```

### Backend

```bash
cd backend
pip install -r requirements.txt

# With PostgreSQL
DATABASE_URL=postgresql://user:pass@localhost:5432/coreids \
JWT_SECRET=your-secret-key \
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Or with SQLite (auto-fallback)
JWT_SECRET=your-secret-key uvicorn app.main:app --host 0.0.0.0 --port 8000
```

---

## Daemon Configuration

`tools/ids_production.conf`:

```ini
state_dir         = /var/lib/ids
alert_threshold   = 0.70
block_threshold   = 0.92
shards            = 0           # 0 = single pipeline
verbose           = true
prometheus        = true
prometheus_port   = 9102
cloud_url         = http://your-server.com:8000
device_id         = <paste-device-id-here>
api_key           = <paste-api-key-here>
forwarder_only    = true        # only forward events, no edge detection
```

---

## Backend API

### User-facing (JWT auth)

| Router | Prefix | Key Endpoints |
|--------|--------|---------------|
| auth | `/api/auth` | register, login, logout, me, plans, subscription |
| devices | `/api/devices` | CRUD, regenerate key, test connection |
| alerts | `/api/alerts` | list, filter, paginate, categories |
| dashboard | `/api/dashboard` | overview, top-talkers, alert-timeline |
| logs | `/api/logs` | list, stats, export CSV |
| rules | `/api/rules` | CRUD, toggle, import/export JSON |
| reports | `/api/reports` | templates, generate, schedule, download |
| stream | `/stream/*`, `/ws/*` | SSE and WebSocket real-time alerts |

### Daemon-facing (API key auth via Authorization header)

| Endpoint | Purpose |
|----------|---------|
| `POST /api/v1/ingest/alerts` | Batch alert push (every 5s) |
| `POST /api/v1/ingest/events` | Raw traffic event push |
| `POST /api/v1/ingest/logs` | Log entry push |
| `POST /api/v1/ingest/metrics` | Performance metrics push |
| `POST /api/v1/device/heartbeat` | Device keepalive (every 30s) |
| `GET /api/v1/device/config` | Pull device configuration |

---

## Frontend

Plain HTML/JS SPA (no build step, no framework). Dark theme with CSS variables.

### Pages

| Page | Features |
|------|----------|
| Overview | 5 stat cards, alert timeline sparkline, categories chart, recent alerts, top talkers |
| Alerts | Paginated table with severity filter and IP search |
| Logs | Log viewer with type/protocol/severity filters, CSV export |
| Traffic | Traffic volume, inbound/outbound breakdown |
| Analytics | Event stats, alert rate, benign %, avg latency |
| Devices | Device grid with status, create, test, reinstall, delete |
| Sources | Top source IPs with alert count and threat score |
| Rules | CRUD, toggle enable/disable, import/export JSON |
| Reports | Templates, recent reports, generate, download |
| Settings | Profile, subscription plan, API key management |

### Real-time

- **WebSocket** (`/ws/alerts`): Instant alert push from backend
- **Polling** (15s): Overview stats, devices, traffic, active page data
- **Live indicator**: Green pulsing dot when devices are online, red when offline

---

## Data Flow

```
1. Daemon captures packet via AF_PACKET raw socket
2. Parses Ethernet → IPv4/IPv6 → TCP/UDP headers
3. Constructs Event with IPs, ports, protocol, entropy, rate
4. IDS pipeline detects threat → generates Alert
5. CloudUploader batches alerts every 5s
6. POST /api/v1/ingest/alerts (Authorization: Bearer <api_key>)
7. Backend extracts API key from header, verifies device
8. Stores Alert + LogEntry in PostgreSQL
9. Broadcasts to WebSocket subscribers via in-memory pub/sub
10. Frontend receives via WebSocket, updates dashboard instantly
```

---

## Database (10 Tables)

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

---

## Subscription Tiers

| Feature | Free | Pro ($49/mo) | Enterprise ($199/mo) |
|---------|------|-------------|---------------------|
| Sensors | 1 | 5 | Unlimited |
| Retention | 7 days | 30 days | 1 year |
| Events/month | 1M | 10M | Unlimited |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql://...localhost:5432/coreids` | PostgreSQL connection |
| `JWT_SECRET` | `""` | Secret for JWT signing |
| `JWT_ALGORITHM` | `HS256` | JWT algorithm |
| `JWT_EXPIRE_MINUTES` | `1440` | Token expiry (24h) |
| `STRIPE_SECRET_KEY` | `""` | Stripe API key |
| `CORS_ORIGINS` | `""` | Comma-separated CORS origins |
| `COOKIE_SECURE` | `false` | Set true for HTTPS |

---

## Requirements

| Component | Minimum |
|-----------|---------|
| C++ standard | C++17 |
| CMake | 3.16 |
| Compiler | GCC 9+ or Clang 10+ |
| Threads | pthreads (Linux) |
| Cloud upload | libcurl |
| Visualizer | libpcap + libncurses |
| Backend | Python 3.12, FastAPI |
| Database | PostgreSQL (SQLite fallback) |

---

## CI/CD

`.github/workflows/ci.yml` runs 4 jobs:

1. **cpp-build**: CMake build + unit tests + e2e tests
2. **python-lint**: ruff check on backend code
3. **python-test**: pytest with PostgreSQL service container
4. **docker**: Build backend and sensor Docker images
