# CoreIDS SaaS — Architecture

## 1. Stack

| Component | Technology | Cost |
|-----------|-----------|------|
| Frontend | Plain HTML/JS SPA, served by FastAPI | $0 |
| Backend | Python 3.12, FastAPI, SQLAlchemy | $0 |
| Database | PostgreSQL (SQLite fallback) | $0 |
| IDS Engine | C++17 header-only library (24 headers) | $0 |
| Daemon | C++17, AF_PACKET, Docker | $0 (customer runs) |
| Real-time | In-memory pub/sub + WebSocket/SSE | $0 |
| CI/CD | GitHub Actions | $0 |

## 2. System Overview

```
                          ┌──────────────────────────────────────┐
   CUSTOMER               │         CLOUD BACKEND               │
   NETWORK                │                                      │
                          │  ┌────────────┐  ┌──────────────┐   │
   ┌────────────┐         │  │  FastAPI   │  │  SPA         │   │
   │ IDS Daemon │──HTTPS──│──│  4 workers │──│  index.html  │   │
   │ Docker     │  alerts │  │  + ctypes  │  └──────────────┘   │
   │            │──WS─────│──│  bridge    │                      │
   └────────────┘  stream │  └────┬───────┘                      │
                          │       │                              │
                          │  ┌────▼─────────────────────────┐   │
                          │  │  PostgreSQL                   │   │
                          │  │  10 tables (users, devices,   │   │
                          │  │  alerts, metrics, logs,       │   │
                          │  │  rules, reports, traffic)     │   │
                          │  └──────────────────────────────┘   │
                          │                                      │
                          │  ┌──────────────┐                    │
                          │  │  In-memory   │                    │
                          │  │  pub/sub     │                    │
                          │  │  (broadcast) │                    │
                          │  └──────────────┘                    │
                          └──────────────────────────────────────┘
```

No Redis. No Celery. No TimescaleDB. No Supabase. No external dependencies.

## 3. Backend Architecture

### Entry Point
`backend/app/main.py` — FastAPI app with CORS, static files, all routers mounted.

### Workers
4 background tasks started at startup:
- **Heartbeat checker** (30s): Marks devices offline if no heartbeat in 90s
- **Event processor** (1s): Claims unprocessed traffic events, runs through IDS bridge
- **Metrics collector** (60s): Stores device health metrics
- **Usage meter** (60s): Updates monthly event/alert counts

### Auth Flow
```
Register → password hashed (bcrypt) → user created → free subscription created → JWT returned
Login    → verify password → JWT returned
Daemon   → POST with Authorization: Bearer <api_key> header → verified against device.api_key_hash
Frontend → JWT in localStorage → Authorization: Bearer <jwt> → middleware verifies
```

### IDS Bridge
`backend/app/ids_bridge.py` uses ctypes to load `libids_central.so`. Each user gets an isolated `ShardedIDS` instance (4 parallel pipelines). Events flow through the full 9-step pipeline in-process — no network overhead.

### Real-time Push
`backend/app/broadcaster.py` — in-memory async pub/sub. Supports multiple subscribers. Routes:
- `/stream/alerts` — SSE (EventSource) with JWT query param
- `/ws/alerts` — WebSocket with JWT query param

When an alert is ingested, it's broadcast to all connected clients.

### Rate Limiting
Sliding window rate limiter per user (configurable limits). Circuit breaker protects downstream services.

## 4. Data Model

### Users & Auth
```
users
├── id (UUID, PK)
├── email (unique)
├── password_hash (bcrypt)
├── name
├── company
├── role (admin / customer)
├── created_at
└── last_login

subscriptions
├── id (UUID, PK)
├── user_id (FK → users)
├── plan (free / pro / enterprise)
├── status (active / past_due / cancelled)
├── stripe_subscription_id
├── current_period_start
├── current_period_end
├── sensors_allowed (int)
├── retention_days (int)
├── events_per_month_limit (bigint)
├── created_at
└── updated_at
```

### Devices
```
devices
├── id (UUID, PK)
├── user_id (FK → users)
├── name (customer-given label)
├── api_key (stored as plaintext for simplicity — hash in production)
├── api_key_hash
├── status (offline / online / error)
├── last_seen_at (timestamp)
├── version (daemon version string)
├── ip_address (public IP of the daemon)
├── location (optional, user-set)
├── config_json (JSON — daemon config overrides)
├── created_at
└── metadata (JSONB — tags, notes)
```

### Alerts
```
alerts
├── id (UUID, PK)
├── device_id (FK → devices)
├── user_id (UUID — same as device owner)
├── time (TIMESTAMPTZ, NOT NULL)
├── decision (alert / block / escalate / ignore)
├── severity (low / medium / high / critical)
├── confidence (float 0-1)
├── source_ip (inet)
├── dest_ip (inet)
├── source_port (int)
├── dest_port (int)
├── protocol (tcp / udp / icmp)
├── attack_class (varchar — sql_injection, brute_force, etc.)
├── anomaly_score (float)
├── ae_score (float)
├── explanation (text)
├── raw_event (JSONB — full event payload)
├── enriched (JSONB — geoip, whois, threat intel)
├── acknowledged_at (timestamptz, nullable)
└── resolved_at (timestamptz, nullable)

Indexes:
  - (device_id, time DESC)
  - (user_id, time DESC)
  - (user_id, severity, time DESC)
  - (user_id, source_ip, time DESC)
```

### Metrics (time-series)
```
metrics
├── device_id (UUID)
├── user_id (UUID)
├── time (TIMESTAMPTZ)
├── events_per_sec (float)
├── alerts_per_sec (float)
├── blocks_per_sec (float)
├── avg_latency_us (float)
├── p99_latency_us (float)
├── drift_score (float)
├── anomaly_history (float)
├── memory_usage_pct (float)
├── cpu_usage_pct (float)
├── active_devices_count (int)
└── online_updates_count (int)
```

### Logs
```
logs
├── id (UUID, PK)
├── device_id (UUID)
├── user_id (UUID)
├── time (TIMESTAMPTZ)
├── type (string)
├── protocol (string)
├── src_ip (inet)
├── dst_ip (inet)
├── src_port (int)
├── dst_port (int)
├── severity (string)
└── message (text)
```

### Other Tables
- `traffic_events` — raw traffic events with processed flag for worker claiming
- `rules` — detection rules (SID, category, severity, condition JSONB)
- `reports` — generated reports (template, format, file_path, status)
- `report_schedules` — scheduled report configs (cron expression, recipients)
- `usage_meters` — monthly usage tracking (events_ingested, alerts_stored)

## 5. API Routes

### Public
| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/auth/register` | Create account + free subscription |
| POST | `/api/auth/login` | Get JWT |
| GET | `/api/plans` | List subscription tiers |

### User-facing (JWT auth)
| Router | Prefix | Key Endpoints |
|--------|--------|---------------|
| auth | `/api/auth` | register, login, logout, me, plans, subscription |
| devices | `/api/devices` | CRUD, regenerate key, test connection |
| alerts | `/api/alerts` | list, filter, paginate, categories, timeseries |
| dashboard | `/api/dashboard` | overview (5 stat cards), top-talkers, alert-timeline |
| logs | `/api/logs` | list, stats, export CSV |
| rules | `/api/rules` | CRUD, toggle enable/disable, import/export JSON |
| reports | `/api/reports` | templates, generate, schedule, download |
| stream | `/stream/alerts`, `/ws/alerts` | SSE and WebSocket real-time push |

### Daemon-facing (API key in Authorization header)
| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/ingest/alerts` | Batch alert push (every 5s) |
| POST | `/api/v1/ingest/events` | Raw traffic event push |
| POST | `/api/v1/ingest/logs` | Log entry push |
| POST | `/api/v1/ingest/metrics` | Performance metrics push |
| POST | `/api/v1/device/heartbeat` | Keepalive (every 30s) |
| GET | `/api/v1/device/config` | Pull device configuration |

### Auth for daemon endpoints
Daemon sends `Authorization: Bearer <api_key>` header. Backend extracts API key from header (falls back to JSON body for backward compatibility). Verifies against `devices.api_key_hash`.

## 6. Frontend

Plain HTML/JS SPA (no build step, no framework). Dark theme with CSS variables. 10 pages:

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

### Real-time updates
- **WebSocket** (`/ws/alerts`): Instant alert push from backend via in-memory pub/sub
- **Polling** (15s): Overview stats, devices, traffic, active page data
- **Live indicator**: Green pulsing dot when devices are online, red when offline

### Auth flow
- Login/register modals → JWT stored in `localStorage`
- All API calls include `Authorization: Bearer <jwt>` header
- Logout clears localStorage and redirects

## 7. IDS Daemon

### Compilation
- Daemon (`ids_production.cpp`) compiled with `-O3 -std=c++17 -D_GNU_SOURCE`
- Links libpcap for packet capture
- Links libcurl for cloud upload
- Outputs `ids_production` binary

### Runtime
- AF_PACKET raw socket captures Ethernet frames
- Parses Ethernet → IPv4/IPv6 → TCP/UDP headers
- Constructs Event with IPs, ports, protocol, entropy, rate
- 9-step pipeline detects threat → generates Alert
- CloudUploader batches alerts every 5s, POSTs to backend
- Heartbeat every 30s marks device as online
- Replay mode processes CSV datasets through the full pipeline

### Docker
```bash
docker build -t coreids-sensor .
docker run --rm --net=host --cap-add=NET_RAW coreids-sensor eth0
```

## 8. Data Flow

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

## 9. Subscription Tiers

| Feature | Free | Pro ($49/mo) | Enterprise ($199/mo) |
|---------|------|-------------|---------------------|
| Sensors | 1 | 5 | Unlimited |
| Retention | 7 days | 30 days | 1 year |
| Events/month | 1M | 10M | Unlimited |
| API access | read-only | read + write | full |
| Alert webhooks | No | Yes | Yes |
| Custom rules | No | No | Yes |
| Support | community | email | SLA + Slack |

Billing flow: Stripe Checkout → Webhook updates subscription → API enforces limits.

## 10. Build System

`CMakeLists.txt` builds these targets:

| Target | Description |
|--------|-------------|
| `ids_production` | Production daemon (requires libcurl) |
| `ids_central` | Shared library (`libids_central.so`) for Python FFI bridge |
| `ids_demo` | Integration demo (5-phase attack simulation) |
| `ids_dataset_demo` | Dataset calibration and evaluation |
| `ids_visualizer` | Live ncurses dashboard (requires libpcap + ncurses) |
| `ids_unit_tests` | 21 unit tests across all pipeline stages |
| `ids_e2e_test` | End-to-end detection evaluation on CICIDS2017 data |

## 11. CI/CD

`.github/workflows/ci.yml` runs 4 jobs:

1. **cpp-build**: CMake build + unit tests + e2e tests
2. **python-lint**: ruff check on backend code
3. **python-test**: pytest with PostgreSQL service container
4. **docker**: Build backend and sensor Docker images

## 12. Detection Metrics

End-to-end evaluation on CICIDS2017 datasets (train: Monday+Tuesday benign, test: 5 attack types):

| Attack Type | Recall | F1 |
|-------------|--------|-----|
| DoS Hulk | 100% | 100% |
| FTP Brute Force | 100% | 100% |
| DDoS Loit | 79.9% | 88.8% |
| SSH Brute Force | 59.8% | 74.9% |
| Port Scan | 46.2% | 63.2% |
| **Global** | **76.7%** | **86.8%** |

Precision: 100% (zero false positives among attack events).
