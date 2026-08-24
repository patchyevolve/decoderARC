# CoreIDS — Technical Reference Document

## A Complete Analysis of the CoreIDS Intrusion Detection System

**Version**: 1.0  
**Date**: August 2026

---

## Table of Contents

1. [What Is CoreIDS](#1-what-is-coreids)
2. [System Architecture](#2-system-architecture)
3. [The Detection Engine — How It Works](#3-the-detection-engine)
4. [The 9-Step Pipeline — Step by Step](#4-the-9-step-pipeline)
5. [Scoring and Decision Making](#5-scoring-and-decision-making)
6. [The Daemon — Edge Sensor](#6-the-daemon)
7. [The Backend — Central Intelligence](#7-the-backend)
8. [The Frontend — Dashboard](#8-the-frontend)
9. [Data Flow — From Packet to Alert](#9-data-flow)
10. [Execution States and Lifecycle](#10-execution-states)
11. [Why Each Component Exists](#11-why-each-component-exists)
12. [What Is Better to Have](#12-what-is-better-to-have)

---

## 1. What Is CoreIDS

### 1.1 The Problem

Every organization connected to the internet faces threats: hackers scanning for open ports, brute-force attacks on login systems, distributed denial-of-service (DDoS) floods, malware spreading laterally across networks, and advanced persistent threats (APTs) that operate slowly over weeks or months. Traditional intrusion detection systems (IDS) rely on static rules — they can only detect attacks they have been explicitly told about. Novel attacks, zero-day exploits, and slow-burn campaigns pass through undetected.

### 1.2 The Solution

CoreIDS is a real-time, machine-learning-powered intrusion detection system delivered as a SaaS (Software as a Service) platform. Unlike rule-based systems, CoreIDS builds a statistical model of what "normal" looks like for each network, each user, and each device — then flags anything that deviates from that norm.

### 1.3 What Makes It Different

| Traditional IDS | CoreIDS |
|----------------|---------|
| Rule-based (only known attacks) | Anomaly-based (detects unknown attacks) |
| Static thresholds | Adaptive thresholds that learn per-device |
| Single-pass analysis | Multi-level hierarchical analysis |
| No memory of past events | Partitioned memory with cosine-similarity retrieval |
| Central processing only | Edge detection + central correlation |
| Manual tuning | Self-calibrating with online learning |

### 1.4 What It Can Detect

- **Port scans and reconnaissance** — sequential connection attempts across many ports
- **Brute-force attacks** — repeated authentication failures
- **DoS / DDoS floods** — abnormally high packet rates or symmetric traffic patterns
- **Lateral movement** — internal hosts contacting unusual internal targets
- **Encrypted C2 channels** — high-entropy, low-rate persistent connections
- **Slow APT campaigns** — subtle deviations accumulating over hours
- **Multi-stage attacks** — scan → compromise → lateral → exfil sequences
- **Any custom pattern** via user-defined rules or multi-stage sequence configs

### 1.5 Proven Performance

End-to-end evaluation on CICIDS2017 datasets (real captured network traffic from the Canadian Institute for Cybersecurity):

| Attack Type | Recall | F1 Score |
|-------------|--------|----------|
| DoS Hulk | 100% | 100% |
| FTP Brute Force | 100% | 100% |
| DDoS (Loit) | 79.9% | 88.8% |
| SSH Brute Force | 59.8% | 74.9% |
| Port Scan | 46.2% | 63.2% |
| **Global** | **76.7%** | **86.8%** |

Precision across all categories: 100% — zero false positive alerts among actual attack traffic.

---

## 2. System Architecture

### 2.1 The Three Components

CoreIDS consists of three independent components that communicate over HTTP(S):

```
┌──────────────────────────────────────────────────────────────┐
│                    COREIDS PLATFORM                          │
│                                                              │
│  ┌─────────────────┐    ┌──────────────────────────────────┐ │
│  │   FRONTEND       │    │   BACKEND                        │ │
│  │   (Browser)      │    │   (Python/FastAPI)               │ │
│  │                  │    │                                  │ │
│  │  HTML/JS SPA     │◄──►│  ┌─────────┐  ┌──────────────┐ │ │
│  │  10 pages        │WS/ │  │REST API │  │C IDS Bridge  │ │ │
│  │  Real-time       │HTTP│  │8 routers│  │ctypes→       │ │ │
│  │  WebSocket       │    │  │         │  │libids_central│ │ │
│  └─────────────────┘    │  └────┬────┘  └──────┬───────┘ │ │
│                         │       │               │          │ │
│                         │  ┌────▼───────────────▼───────┐  │ │
│                         │  │  PostgreSQL Database        │  │ │
│                         │  │  (10 tables)                │  │ │
│                         │  └────────────────────────────┘  │ │
│                         └──────────────────────────────────┘ │
│                                    ▲                         │
│                                    │ HTTPS (every 5s)        │
│                                    │                         │
│  ┌─────────────────────────────────┴──────────────────────┐  │
│  │              DAEMON (C++17 Binary)                     │  │
│  │                                                        │  │
│  │  ┌──────────┐  ┌────────────┐  ┌───────────────────┐  │  │
│  │  │AF_PACKET │→ │9-Step IDS  │→ │CloudUploader      │  │  │
│  │  │Capture   │  │Pipeline    │  │POST /api/v1/ingest│  │  │
│  │  └──────────┘  └────────────┘  └───────────────────┘  │  │
│  │                                                        │  │
│  │  Runs at customer site (edge)                          │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### 2.2 Why Three Components

**The Daemon** runs at the customer's network edge — directly on the machine connected to their network traffic. This is where raw packets are captured and analyzed. Keeping the heavy computation at the edge means:
- Low latency (analysis happens in microseconds, not milliseconds over a network)
- Privacy (raw traffic never leaves the customer's network)
- Resilience (detection continues even if the backend is unreachable)

**The Backend** provides the management layer — user accounts, device registration, alert storage, subscription billing, and a bridge to the C++ IDS engine for centralized analysis. It stores alerts in PostgreSQL and pushes real-time updates to the browser via WebSocket.

**The Frontend** is a plain HTML/JavaScript single-page application served by the backend. No build step, no framework, no dependencies. It displays the dashboard, allows filtering and searching alerts, and receives real-time push notifications.

### 2.3 The C++ Engine — Core Intelligence

The detection engine is a header-only C++17 library consisting of 24 header files in the `include/` directory. It is compiled into two forms:

1. **Static binary** (`ids_production`) — the daemon that runs at customer sites
2. **Shared library** (`libids_central.so`) — loaded by the Python backend via ctypes for centralized inference

The engine processes events through a 9-step pipeline. Each step has a specific purpose, and the steps are ordered so that cheaper computations run first and more expensive ones only execute when needed.

---

## 3. The Detection Engine

### 3.1 Core Philosophy — What Anomaly Detection Means

Traditional IDS works like a blacklist: "If you see IP address X doing Y, raise an alert." This requires knowing every possible attack in advance.

CoreIDS works like a doctor's checkup: it builds a profile of what healthy looks like (normal traffic patterns), then flags anything that looks sick (statistically unusual). The key insight is that attacks, by their nature, must be different from normal traffic. A port scan looks different from a web server's normal traffic. A brute-force attack generates different authentication patterns than legitimate logins.

### 3.2 The 64-Dimensional Embedding

Every network event is converted into a 64-dimensional numerical vector (called an embedding). Think of this as translating a network packet into a "medical report" with 64 different measurements:

| Dimensions | What They Measure | Why It Matters |
|-----------|-------------------|----------------|
| [0-3] | Bytes in/out, source/dest port | Basic flow characteristics |
| [4-5] | Protocol type, TCP flags | Connection behavior |
| [6-7] | Entropy, packet rate | Data randomness and speed |
| [8] | Event type | What kind of event this is |
| [9] | Burst metric | How "bursty" the traffic is |
| [10] | Protocol diversity | How many different protocols |
| [11-16] | Flow statistics | Packet counts, sizes, timing |
| [17-26] | Source/dest IP hash | Which IPs are communicating |
| [27] | Inter-arrival time gap | Time since last event |
| [28-39] | Rolling statistics | Mean and variance of 6 features |

This embedding captures enough information for the engine to understand the character of each event without needing to inspect the full packet payload (which would be a privacy concern).

### 3.3 The Hierarchical Analysis — Why Multiple Levels

A single analysis pass misses patterns that emerge over time. Consider:

- **L0 (instant)**: A single SYN packet looks normal. But 1000 SYN packets in 1 second is suspicious.
- **L1 (seconds)**: A 10-second segment of traffic might show a trend — increasing rate, changing pattern.
- **L2s (tens of seconds)**: Multiple segments together reveal whether this is a sustained attack or a brief spike.
- **L2m (minutes)**: Over minutes, slow attacks become visible that individual seconds miss.
- **L2l (tens of minutes)**: APT campaigns operating over hours become detectable.

Each level uses a different time scale and a different State Space Model (SSM) to track the evolving state of network behavior.

### 3.4 State Space Models — What They Are

A State Space Model (SSM) is a mathematical framework for tracking how a system evolves over time. Think of it as a "memory" that:
1. Takes in a new observation (the current event's embedding)
2. Updates its internal state based on what it has seen before
3. Produces an output that summarizes the current situation

The SSM used in CoreIDS is inspired by the Mamba architecture — a modern approach to sequence modeling that uses selective state spaces. The key equation is:

```
state_new = A_bar * state_old + delta * B * input
output = C * state_new + D * input
```

Where:
- `A_bar` = how much of the old state to keep (input-dependent, computed via softplus)
- `delta` = step size (how fast to update)
- `B` = how to project input into state space
- `C` = how to read state space into output
- `D` = skip connection (direct input-to-output)

The critical innovation is that `delta` depends on the input itself — the model decides how fast to update based on what it sees. Normal traffic causes slow updates; anomalous traffic causes fast updates.

### 3.5 Why 32-Dimensional State

The SSM uses 32-dimensional internal state (kSSMStateDim = 32). This is chosen because:
- 32 dimensions provide enough capacity to model complex traffic patterns
- The state is small enough for fast computation (O(32) per step)
- It is large enough to avoid information bottlenecks

---

## 4. The 9-Step Pipeline

Each event entering the IDS pipeline passes through 9 sequential steps. The pipeline is implemented in `include/ids.hpp` in the `IDS::ingest()` method.

### Step 1: Level 0 — Local Analysis

**File**: `include/ids_level0.hpp`  
**Class**: `LocalAnalyzer`  
**Purpose**: Analyze each event individually and produce a local anomaly score

**What happens**:
1. The event is added to a sliding window buffer (default: 64 events)
2. A 64-dimensional embedding is computed from the event's features
3. Rolling mean and variance are updated using Welford's online algorithm (numerically stable)
4. A Z-score is computed for 6 key features: total bytes, rate, packet count, packet size, inter-arrival time, SYN count
5. The Z-score components are combined: L2-norm catches weak-but-consistent anomalies, max-Z preserves single-spike detection
6. Known attack indicators add boosts: SYN flood (+0.4), many small packets (+0.3), burst (+0.3), asymmetric traffic (+0.3), irregular timing (+0.25), FIN scan (+0.3), high entropy (+0.5), high burst (+0.3)
7. The final score is clamped to [0, 1]

**Why this exists**: Most events are normal. L0 catches the obvious attacks quickly without involving the more expensive higher levels. It is the first filter.

**Latency**: ~1-5 microseconds per event

### Step 1.5: Autoencoder Anomaly Score

**File**: `include/ids_nn.hpp`  
**Class**: `Autoencoder`  
**Purpose**: Neural network-based anomaly detection

**What happens**:
1. The L0 embedding is fed through a 3-layer autoencoder (40 → 16 → 8 → 16 → 40)
2. The autoencoder tries to reconstruct the original input
3. Reconstruction error (MSE) becomes the anomaly score
4. The AE score is fused with the L0 score: `anomaly = 0.85 * L0 + 0.15 * AE`

**Why this exists**: The autoencoder learns nonlinear relationships that Z-scores miss. If traffic patterns deviate from the training distribution, reconstruction error increases. The 15% weight keeps it as a secondary signal — it provides diversity without dominating.

**The autoencoder architecture**:
- Encoder Layer 1: 40 inputs → 16 hidden (ReLU activation)
- Encoder Layer 2: 16 hidden → 8 bottleneck (ReLU activation)
- Decoder Layer 1: 8 bottleneck → 16 hidden (ReLU activation)
- Decoder Layer 2: 16 hidden → 40 output (identity activation)
- Training: SGD with lr=0.01, Xavier initialization
- Online learning: Single SGD step on confirmed-benign events (lr=0.001)

### Step 2-4: Level 1 → Level 2 Hierarchical Routing

**File**: `include/ids_level1.hpp`, `include/ids_ssm.hpp`  
**Classes**: `SegmentSSM`, `HierarchicalSSM`  
**Purpose**: Build temporal context across increasing time scales

**What happens**:

**Level 1 (per-IP segment tracking)**:
- Each IP address gets its own `SegmentSSM` instance
- Events accumulate until a flush condition triggers
- Flush conditions (any one triggers):
  - Count ≥ 100 events (`flush_n`)
  - Average anomaly > 0.70 (`flush_anomaly`)
  - Time elapsed > 10 seconds (`flush_t`)
  - Session ended
  - Event type changed
- On flush, the accumulated segment state (mean anomaly trend, error frequency, dominant event type) is emitted

**Level 2 (hierarchical SSM)**:
- `L2s` (short): Processes each flushed segment from L1
- `L2m` (mid): Processes L2s states every 10 ticks or when anomaly/drift exceeds thresholds
- `L2l-short`: Processes L2m states every 60 ticks or on high drift
- `L2l-global`: Processes L2l states every 600 ticks or on very high drift
- Each level uses a separate 32×32 SSM with its own parameters
- Signal-driven promotion: levels only update when there is something worth promoting (SkipRules suppress noise)

**Why this exists**: A single SYN flood is suspicious at L1. But a sustained port scan over 5 minutes is only visible at L2m. An APT operating over days is only visible at L2l. The hierarchy provides multi-scale temporal analysis.

### Step 5: Memory Write

**File**: `include/ids_memory.hpp`  
**Class**: `Retriever` (write method)  
**Purpose**: Store embeddings in partitioned memory for future retrieval

**What happens**:
1. A `MemoryRecord` is created containing the embedding, anomaly score, and metadata
2. Write decision is governed by `WritePolicy`:
   - `memory_write_gate` (0.50): Events with anomaly ≥ 0.50 are written
   - `memory_force_gate` (0.85): Events with anomaly ≥ 0.85 are force-written to global store
   - `write_on_rule_match`: Rule matches trigger writes
   - `write_on_block` / `write_on_escalate`: Post-decision writes
3. Records are written to partitioned stores: IP, user, host, session, process, global

**Why this exists**: Without memory, the engine has no context beyond the current event. Memory allows the engine to say "this IP did something similar 10 minutes ago and it was an attack." Partitioned stores enable per-IP, per-user, and global lookups.

### Step 6: Retrieval

**File**: `include/ids_memory.hpp`  
**Class**: `Retriever` (retrieve method)  
**Purpose**: Find similar past events to provide context

**What happens**:
1. Only triggers when anomaly ≥ 50% of gate threshold AND per-IP cooldown (1 Hz max)
2. Searches across all partitioned stores (IP, user, session, host, global)
3. Uses cosine similarity between the current embedding and stored embeddings
4. Search is scored by: `final = w_sim * similarity + w_anomaly * stored_score + w_time * recency + scope_weight`
5. Top 8 results are kept (kTopKRetrieval = 8)
6. Rule table is checked for pattern matches

**Why this exists**: A single event might look borderline. But if the top 8 most similar past events were all attacks, the current event is very likely an attack too. Retrieval provides "memory-based reasoning" — the engine learns from its own history.

### Step 7: Gate + Reasoning

**File**: `include/ids_reasoning.hpp`  
**Classes**: `compute_gate_score`, `ReasoningModel`  
**Purpose**: Decide whether to invoke the expensive reasoning model, then produce a decision

**What happens**:

**Gate score computation** (determines if reasoning is needed):
```
gate = 0.35 * local_anomaly
     + 0.25 * segment_trend
     + 0.15 * anomaly_history
     + 0.10 * drift_score (normalized)
     + 0.10 * retrieval_similarity
     + 0.05 * rule_match (0 or 1)
```

**Force conditions** (bypass gate):
- Rule match found
- Local anomaly > 0.90
- Drift score > 6.0
- Anomaly history > 0.70

**Skip conditions** (avoid unnecessary reasoning):
- Local anomaly < 0.10
- Source is in allow list

**When reasoning runs**:
1. Build token sequence: [current embedding, segment state, L2s state, L2l state, + top-8 retrieval embeddings]
2. Single-head attention pool: compute attention weights over all tokens, produce weighted sum
3. Score fusion: `combined = w_local * local + w_segment * trend + w_history * history + w_drift * drift + retrieval_boost + rule_boost + 0.05 * attention_similarity`
4. Rule override: if rules matched, combined ≥ alert_threshold
5. False positive suppression: if combined < 0.2, set decision to Ignore
6. Attack classification: map combined score + features to attack class label
7. Build human-readable explanation string

**Why this exists**: Reasoning is the most expensive step. The gate ensures it only runs when there is enough signal to justify the cost. Most events (normal traffic) skip reasoning entirely.

### Step 7.3: Specialist Fusion

**File**: `include/ids_specialist.hpp`  
**Class**: `Specialist` (interface)  
**Purpose**: Domain-specific detection modules

**What happens**:
1. Each registered specialist analyzes the event
2. If any specialist reports a validated result with confidence > 0.30:
   - Boost the main confidence: `confidence = confidence + specialist_confidence * 0.5`
   - Override attack class with specialist's class
   - Re-evaluate decision
   - Append specialist info to explanation

**Why this exists**: General-purpose anomaly detection cannot match the precision of a purpose-built detector for a specific attack type. Specialists provide this precision without bloating the main pipeline.

### Step 7.4: Near-Miss & Aggregate Detection

**File**: `include/ids_types.hpp`  
**Classes**: `NearMissDetector`, `PerIPAggregator`  
**Purpose**: Catch borderline events that accumulate suspicious patterns

**Near-miss detection**:
- Tracks events with scores in [0.25, 0.60) per IP
- If 5+ near-miss events accumulate within 60 seconds, boost confidence by 0.40

**Per-IP aggregation**:
- Tracks last 20 events per IP
- Computes: SYN ratio, RST ratio, protocol entropy, average bytes
- SYN flood pattern (SYN > 80%, RST < 10%): boost 0.50
- RST flood (RST > 30%): boost 0.40
- Many small packets (< 50 bytes avg, 10+ events): boost 0.30
- Protocol diversity > 0.5: boost 0.20

**Why this exists**: Some attacks look normal event-by-event but reveal their pattern in aggregate. A single SYN packet is normal. 20 SYN packets in 30 seconds with no completions is a scan.

### Step 7.5: Correlation Engine

**File**: `include/ids_correlation.hpp`  
**Class**: `CorrelationEngine`  
**Purpose**: Detect multi-event attack patterns across time

**Four detection modes**:

1. **Repeat Detection**: Same IP triggers ≥ 3 alerts within 60 seconds → correlation score += 0.20
2. **Multi-stage Detection**: Attack class sequence matches a known pattern (e.g., PortScan → BruteForce → LateralMovement within 600s) → score += 0.30
3. **Distributed Detection**: ≥ 5 unique source IPs targeting the same host within 60 seconds → score += 0.25
4. **Slow Attack Detection**: ≥ 10 events from same IP within 1 hour, each scoring ≥ 0.30 → score += 0.15

**Campaign tracking**:
- Active campaigns group related alerts by source IP and attack class
- Campaigns expire after 30 minutes of inactivity
- Maximum 200 active campaigns

**Decision upgrade**: If correlation score > 0.40 and current decision is Alert, upgrade to Escalate.

**Why this exists**: Individual events might not be alarming, but their pattern reveals intent. A port scan followed by brute force followed by lateral movement is a clear attack chain — even if each individual step was borderline.

### Step 8: Decision Engine

**File**: `include/ids_decision.hpp`  
**Class**: `DecisionEngine`  
**Purpose**: Apply final overrides, hysteresis, cooldowns, and dispatch

**What happens**:

1. **Override application** (fixed priority order):
   - Allow list: if source is in allow list → hard Ignore
   - Block list: if source is in block list → hard Block
   - Escalation checks: high anomaly history + repeat alerts → Escalate

2. **Hysteresis**: If a Block decision was made recently (within `decision_hold_time_s` = 10s), a borderline score still counts as Block. This prevents rapid alert/block oscillation.

3. **Cooldown**: After an alert, suppress duplicate alerts for 5 seconds. After a block, suppress for 30 seconds. Stronger decisions (Block, Escalate) always override cooldowns.

4. **Learning mode**: When enabled, Block and Escalate decisions are downgraded to Alert (to avoid blocking during training/calibration).

5. **Dispatch**: Based on final decision:
   - `Alert`: fires `on_alert` callback
   - `Block`: fires `on_block` callback + `on_alert` callback
   - `Escalate`: fires `on_escalate` callback + `on_alert` callback
   - `Ignore`: no callback

**Decision thresholds** (configurable):
```
Ignore:    score < 0.20
Log:       score < 0.40
Alert:     score < 0.60
Block:     score < 0.85
Escalate:  score ≥ 0.95
```

**Why this exists**: The reasoning model produces a raw confidence score. But raw scores are not decisions — they need context (was this IP already blocked? is it in the allow list? should we escalate because of repeated alerts?). The decision engine provides this contextual logic.

### Step 8b: Post-Decision Memory Write

After the decision is made, if the decision was Block or Escalate, a second memory write fires. This ensures that blocked/escalated events are always stored in memory, regardless of the write gate threshold.

### Step 8c: Online Autoencoder Learning

For events with confidence < 0.10 (confirmed benign), a single SGD step is applied to the autoencoder with learning rate 0.001. Only 1 in 100 qualifying events triggers this update (stochastic sampling). This allows the autoencoder to adapt to gradual traffic drift without offline retraining.

---

## 5. Scoring and Decision Making

### 5.1 The Scoring Pipeline

```
Event
  │
  ▼
L0 Local Anomaly Score (Z-score + AE) ──────────── local_anomaly
  │
  ▼
Segment SSM Output ──────────────────────────────── segment_trend
  │
  ▼
Hierarchical SSM + Baseline ─────────────────────── drift_score, anomaly_history
  │
  ▼
Memory Retrieval ─────────────────────────────────── similarity_max
  │
  ▼
Gate Score ────────────────────────────────────────── should_reason?
  │
  ▼
Score Fusion ──────────────────────────────────────── combined_score
  │
  ▼
Attention Boost ───────────────────────────────────── +0.05 * attn_similarity
  │
  ▼
Specialist Boost ──────────────────────────────────── +0.5 * specialist_confidence
  │
  ▼
Near-miss / Aggregate Boost ──────────────────────── +0.3 to +0.5
  │
  ▼
Correlation Upgrade ───────────────────────────────── Alert → Escalate
  │
  ▼
Override / Hysteresis / Cooldown ──────────────────── final_decision
```

### 5.2 The 6-Signal Gate Score

The gate score determines whether the expensive reasoning model should run. It is a weighted combination of 6 signals:

```
gate = 0.35 * ls.anomaly_score          ← What does L0 think?
     + 0.25 * ss.anomaly_trend          ← What does the segment look like?
     + 0.15 * gs.anomaly_history        ← Has there been a pattern?
     + 0.10 * (gs.drift_score / 10)     ← How far from baseline?
     + 0.10 * ctx.similarity_max        ← Does memory recall similar attacks?
     + 0.05 * rule_match                ← Did any rule fire?
```

**Default threshold**: 0.35. If gate score ≥ 0.35, reasoning runs.

### 5.3 The Score Fusion

When reasoning runs, it produces a fused score using the same 6 signals with slightly different weights:

```
combined = 0.35 * ls.anomaly_score
         + 0.25 * ss.anomaly_trend
         + 0.20 * gs.anomaly_history
         + 0.10 * (gs.drift_score / 10)
         + retrieval_boost              ← 0.05 if any retrieval score > 0.80
         + rule_boost                   ← 0.05 if rules matched
```

The fusion weights are configurable per-attack-class. For example, DoS attacks might weight burst_metric higher, while brute-force attacks might weight auth-related features higher.

### 5.4 Adaptive Thresholds

The system automatically adjusts thresholds based on observed traffic patterns:

**Per-scope baselines** are maintained at 4 levels:
- **Global**: EMA with α=0.001 (very slow, ~1000 events to shift)
- **Per-IP**: EMA with α=0.05 (fast, adapts to individual device behavior)
- **Per-user**: EMA with α=0.02 (medium)
- **Per-host**: EMA with α=0.005 (slow)

**Threshold adaptation**:
```
adapted_alert_threshold = clamp(global_mean + 3.0 * global_std, 0.30, 0.90)
adapted_block_threshold = clamp(alert + 5.0 * global_std, alert + 0.05, 0.95)
```

**Baseline freeze**: If anomaly history ≥ 0.70, the baseline is frozen to prevent the system from normalizing an active attack.

### 5.5 The Decision Override Chain

The decision engine applies overrides in a fixed priority order:

1. **Allow list** → always Ignore (for known-safe IPs like monitoring systems)
2. **Block list** → always Block (for known-bad IPs)
3. **Escalation checks** → if anomaly history high + repeat alerts → Escalate
4. **Hysteresis** → if recently blocked and score is borderline → stay Block
5. **Cooldown** → suppress duplicate alerts (5s) or blocks (30s)
6. **Learning mode** → suppress blocks during calibration

---

## 6. The Daemon

### 6.1 What It Is

The daemon (`tools/ids_production.cpp`) is a C++17 binary that runs at the customer's network edge. It captures raw packets, runs the detection pipeline, and optionally forwards alerts to the backend.

### 6.2 Lifecycle

```
1. Load config from JSON file (or use defaults)
2. Load saved state (memory, autoencoder, L0 stats) from disk
3. If no saved state, train on benign CSV data
4. Start capture loop (AF_PACKET) or CSV replay
5. For each packet:
   a. Parse Ethernet → IPv4/IPv6 → TCP/UDP headers
   b. Construct Event with IPs, ports, protocol, entropy, rate
   c. Run through 9-step pipeline
   d. If alert generated, add to CloudUploader batch
6. CloudUploader batches alerts every 5 seconds → POST /api/v1/ingest/alerts
7. Heartbeat every 30 seconds → POST /api/v1/device/heartbeat
8. Graceful shutdown on SIGINT/SIGTERM with state save
```

### 6.3 Configuration

`tools/ids_production.conf`:
```ini
state_dir         = /var/lib/ids
alert_threshold   = 0.70
block_threshold   = 0.92
shards            = 0           # 0 = single pipeline
verbose           = true
prometheus        = true
prometheus_port   = 9102
cloud_url         = http://backend:8000
device_id         = <uuid>
api_key           = <key>
forwarder_only    = true
```

### 6.4 Modes of Operation

| Mode | Command | Description |
|------|---------|-------------|
| Live capture | `sudo ./ids_production eth0` | Captures real packets on network interface |
| CSV replay | `./ids_production --replay attack.csv` | Replays a CSV dataset through the pipeline |
| Train only | `./ids_production --train benign.csv` | Trains the autoencoder on benign traffic |
| Daemon | `./ids_production eth0 --config config.conf` | Production mode with cloud forwarding |

### 6.5 State Persistence

The daemon saves its state to disk on shutdown:
- `ids_state.bin` — Global state, L1 accumulators, L2 hierarchy (binary, CRC32 checksum)
- `ids_memory.json` — Memory records (JSON)
- `ids_config.json` — Current configuration (key=value)
- `ids_l0.bin` — L0 rolling statistics (binary)
- `ids_ae.bin` — Autoencoder weights (binary)

State is loaded on startup, allowing the daemon to resume where it left off.

### 6.6 Fault Tolerance

- **Panic mode**: If fault count exceeds 100, the engine enters panic mode — disables reasoning and memory writes, uses only rule-based detection. Auto-exits when fault rate drops.
- **SSM energy overflow**: If SSM state energy exceeds 100, state is clamped. If still overflowing after clamp, state is reset to zero.
- **NaN/Inf protection**: Every SSM step checks for NaN/Inf values. If detected, state is reset and an exception is thrown, caught by the pipeline.
- **Watchdog**: In sharded mode, a watchdog thread monitors each shard's heartbeat. If a shard stops responding for 3+ beats, it is automatically restarted.

---

## 7. The Backend

### 7.1 Technology Stack

| Component | Technology |
|-----------|-----------|
| Framework | Python 3.12 + FastAPI |
| ORM | SQLAlchemy |
| Database | PostgreSQL (SQLite fallback) |
| Auth | JWT tokens + bcrypt password hashing |
| Real-time | In-memory async pub/sub + WebSocket |
| IDS Bridge | ctypes → libids_central.so |

### 7.2 Database Schema (10 Tables)

| Table | Purpose | Key Fields |
|-------|---------|-----------|
| `users` | User accounts | id, email, password_hash, role |
| `subscriptions` | Plan management | plan, status, sensors_allowed, retention_days |
| `devices` | Sensor deployments | api_key_hash, status, last_seen_at, config_json |
| `alerts` | Security alerts | decision, severity, confidence, attack_class, source_ip |
| `metrics` | Time-series health | events_per_sec, latency_us, drift_score |
| `logs` | Log entries | type, protocol, src_ip, dst_ip, severity |
| `traffic_events` | Raw events for processing | processed flag for worker claiming |
| `rules` | Detection rules | sid, category, condition JSONB |
| `reports` | Generated reports | template_id, format, file_path |
| `usage_meters` | Monthly usage | events_ingested, alerts_stored |

### 7.3 API Structure

**User-facing (JWT auth)**:
- `/api/auth/*` — Register, login, profile, plans
- `/api/devices/*` — CRUD, regenerate key, test connection
- `/api/alerts/*` — List, filter, paginate, categories
- `/api/dashboard/*` — Overview stats, top-talkers, timeline
- `/api/logs/*` — List, stats, CSV export
- `/api/rules/*` — CRUD, import/export
- `/api/reports/*` — Templates, generate, schedule

**Daemon-facing (API key in Authorization header)**:
- `POST /api/v1/ingest/alerts` — Batch alert push
- `POST /api/v1/ingest/events` — Raw traffic events
- `POST /api/v1/ingest/logs` — Log entries
- `POST /api/v1/ingest/metrics` — Performance metrics
- `POST /api/v1/device/heartbeat` — Keepalive (30s)
- `GET /api/v1/device/config` — Pull config

### 7.4 The Event Processing Runtime

The backend has a built-in IDS engine (via the C bridge) for centralized analysis:

```
TrafficEvent (DB)
    │
    ▼
Worker Thread (4 workers, partitioned by user_id hash)
    │
    ▼
UserRuntime.ingest() → per-user queue (max 10,000 events)
    │
    ▼
UserRuntime.process_batch()
    │
    ▼
CentralRuntime.ingest_batch() → ctypes → libids_central.so
    │
    ▼
ShardedIDS (4 shards per user)
    │
    ▼
Alert JSON returned → stored in PostgreSQL + broadcast via WebSocket
```

### 7.5 Real-time Push

`backend/app/broadcaster.py` implements an in-memory pub/sub system:

1. When an alert is ingested, `broadcaster.broadcast_alert(user_id, alert_data)` is called
2. All WebSocket/SSE connections subscribed to that user_id receive the alert instantly
3. The frontend's WebSocket client receives the JSON and updates the dashboard

No Redis. No external message broker. The pub/sub is entirely in-memory within the Python process.

### 7.6 Authentication Flow

**User registration**:
```
POST /api/auth/register {email, password}
  → bcrypt(password) → store in users table
  → create free subscription
  → return JWT token
```

**User login**:
```
POST /api/auth/login {email, password}
  → bcrypt.verify(password, stored_hash)
  → return JWT token
```

**Daemon authentication**:
```
POST /api/v1/ingest/alerts
  Header: Authorization: Bearer <api_key>
  Body: {device_id, alerts: [...]}
  → extract API key from header
  → SHA-256(api_key) → compare with devices.api_key_hash
  → if match, store alerts + update device.last_seen_at
```

---

## 8. The Frontend

### 8.1 Architecture

Plain HTML/JavaScript single-page application. No build step, no framework, no npm. Served by FastAPI as a static file.

**Key file**: `backend/static/index.html` (~1800 lines)

### 8.2 Pages

| Page | Data Sources | Update Pattern |
|------|-------------|---------------|
| Overview | `/api/dashboard/overview`, `/api/alerts?limit=5`, `/api/dashboard/top-talkers` | Poll 15s + WebSocket push |
| Alerts | `/api/alerts?page=N&severity=X` | On demand + WebSocket push |
| Logs | `/api/logs?page=N&type=X` | On demand |
| Traffic | `/api/v1/ingest/events` data | Poll 15s |
| Analytics | `/api/dashboard/*` | Poll 30s |
| Devices | `/api/devices` | Poll 15s |
| Sources | Aggregated from alerts | On demand |
| Rules | `/api/rules` | On demand |
| Reports | `/api/reports` | On demand |
| Settings | `/api/auth/me`, `/api/auth/plans` | On demand |

### 8.3 Real-time Updates

**WebSocket** (`/ws/alerts?token=JWT`):
- Connects on login
- Receives JSON: `{type: "alert", data: {id, time, decision, severity, source_ip, dest_ip, attack_class}}`
- Updates overview stat cards, alerts page, and notification badge
- Auto-reconnects on disconnect (5-second backoff)

**Polling** (15-second interval):
- Overview stats, device status, traffic data
- Active page data (alerts, logs, etc.)

---

## 9. Data Flow

### 9.1 Complete Path: Packet to Dashboard

```
1. Customer's network traffic arrives at the daemon's network interface

2. AF_PACKET raw socket captures Ethernet frames
   tools/ids_production.cpp (lines ~350-420)

3. Parse Ethernet → IPv4 → TCP/UDP headers
   Extract: src_ip, dst_ip, src_port, dst_port, protocol, bytes, flags

4. Construct Event struct with all features
   include/ids_types.hpp:58-66

5. IDS pipeline.ingest(event)
   include/ids.hpp:283-593

6. Step 1: LocalAnalyzer.process(event)
   include/ids_level0.hpp:16-26
   → 64-dim embedding, anomaly score

7. Step 1.5: Autoencoder.anomaly_score(embedding)
   include/ids_nn.hpp:260-265
   → AE anomaly score, fused with L0

8. Steps 2-4: SegmentSSM.update() → HierarchicalSSM.update()
   include/ids_level1.hpp:23-56, ids_ssm.hpp:127-244
   → Segment flush, L2 promotion, drift calculation

9. Step 5: Retriever.write()
   include/ids_memory.hpp:286-298
   → Memory record stored

10. Step 6: Retriever.retrieve()
    include/ids_memory.hpp:231-283
    → Top-8 similar past events

11. Step 7: compute_gate_score() → ReasoningModel.reason()
    include/ids_reasoning.hpp:36-166
    → Combined confidence score, attack class, explanation

12. Step 7.3: Specialist.analyze()
    include/ids_specialist.hpp:44
    → Specialist boost if applicable

13. Step 7.4: NearMissDetector.check() + PerIPAggregator.score()
    include/ids_types.hpp:692-788
    → Aggregate boost

14. Step 7.5: CorrelationEngine.process()
    include/ids_correlation.hpp:118-193
    → Repeat/multi-stage/distributed/slow detection

15. Step 8: DecisionEngine.execute()
    include/ids_decision.hpp:106-169
    → Final decision (Alert/Block/Escalate), callback fired

16. CloudUploader batches alerts (every 5s)
    include/ids_cloud.hpp
    → POST /api/v1/ingest/alerts

17. Backend receives batch
    backend/app/routers/alerts.py:65-132
    → Verify API key, store in PostgreSQL

18. Backend broadcasts via in-memory pub/sub
    backend/app/broadcaster.py:43-44
    → All WebSocket subscribers notified

19. Frontend WebSocket client receives alert
    backend/static/index.html (WebSocket handler)
    → Updates dashboard tables, stat cards, badge count

20. User sees the alert in their browser
```

### 9.2 Latency Budget

| Stage | Typical Latency |
|-------|----------------|
| Packet capture (AF_PACKET) | ~1 μs |
| Header parsing | ~0.5 μs |
| L0 Local analysis | ~3 μs |
| Autoencoder | ~2 μs |
| L1 Segment SSM | ~1 μs |
| L2 Hierarchical SSM | ~5 μs |
| Memory write | ~1 μs |
| Memory retrieval | ~5 μs |
| Gate + Reasoning | ~10 μs |
| Decision | ~1 μs |
| **Total per event** | **~30 μs** |
| CloudUploader batch | Every 5s |
| Backend processing | ~50 ms |
| WebSocket push | ~5 ms |
| **End-to-end (edge to dashboard)** | **~5 seconds** |

---

## 10. Execution States

### 10.1 Event Lifecycle States

```
Event Created
    │
    ▼
[Captured] ──────── Raw packet captured by AF_PACKET
    │
    ▼
[Parsed] ─────────── Ethernet/IP/TCP/UDP headers extracted
    │
    ▼
[Embedded] ───────── 64-dim vector computed
    │
    ▼
[Scored] ─────────── L0 anomaly score computed
    │
    ▼
[Segmented] ──────── Added to L1 segment accumulator
    │
    ▼
[Flushed] ────────── Segment flushed → L2 promotion considered
    │
    ├─── [Skipped] ── Low anomaly, no promotion
    │
    ▼
[Promoted] ───────── State promoted through L2s → L2m → L2l
    │
    ▼
[Stored] ─────────── Written to memory (if above gate)
    │
    ▼
[Retrieved] ──────── Similar past events found
    │
    ▼
[Reasoned] ───────── Confidence score computed
    │
    ├─── [Ignored] ── Score below threshold
    │
    ├─── [Logged] ─── Score in log range
    │
    ├─── [Alerted] ── Score in alert range
    │
    ├─── [Blocked] ── Score in block range
    │
    └─── [Escalated] Score in escalate range or correlation upgrade
```

### 10.2 Daemon States

| State | Description |
|-------|------------|
| **Starting** | Loading config, loading saved state, training if needed |
| **Training** | Processing benign CSV data to calibrate autoencoder |
| **Running** | Normal operation — capturing packets, running pipeline |
| **Forwarder-only** | Only forwarding events to backend, no edge detection |
| **Panic** | Fault threshold exceeded — rule-based detection only |
| **Saving** | Writing state to disk on shutdown |
| **Stopped** | Clean shutdown complete |

### 10.3 Device States

| State | Description |
|-------|------------|
| **offline** | No heartbeat received in 90+ seconds |
| **online** | Heartbeat received within last 90 seconds |
| **error** | Device reported an error condition |

### 10.4 Pipeline States

| State | Description |
|-------|------------|
| **Active** | L1 instance is receiving events normally |
| **Idle** | No events received for 300+ seconds (idle timeout) |
| **Expired** | No events received for 3600+ seconds (expire timeout) |

---

## 11. Why Each Component Exists

### 11.1 Why Header-Only C++ Library

The IDS engine is implemented as header-only C++ (24 `.hpp` files). This means:
- No separate compilation of the engine — it compiles with whatever includes it
- Template-heavy code can be inlined for maximum performance
- The same code compiles into both the daemon binary and the shared library
- Single source of truth — no version drift between daemon and backend

### 11.2 Why Multiple Hierarchy Levels

A single analysis level cannot detect attacks at all time scales simultaneously. A SYN flood is visible in 1 second. A slow APT is only visible over hours. The hierarchy provides:
- L2s (short): Detects burst attacks (SYN floods, port scans)
- L2m (mid): Detects sustained attacks (brute force, DDoS campaigns)
- L2l (global): Detects slow attacks (APTs, lateral movement)

### 11.3 Why Partitioned Memory

Global memory is too noisy — 100,000 records from all IPs dilute the signal. Partitioned memory enables:
- IP-specific retrieval: "What did this IP do recently?"
- User-specific retrieval: "What has this user's traffic looked like?"
- Host-specific retrieval: "What attacks targeted this server?"
- Session-specific retrieval: "What happened in this connection?"
- Global retrieval: "What attacks have we seen across the entire network?"

### 11.4 Why the Gate Exists

The reasoning model (attention pooling + score fusion) is the most expensive step. Without a gate, every event would trigger reasoning. With a gate:
- Normal traffic (gate score < 0.35) skips reasoning entirely
- Only suspicious traffic (gate score ≥ 0.35) pays the reasoning cost
- This provides ~80% cost reduction while maintaining detection accuracy

### 11.5 Why Cooldown and Hysteresis

Without cooldown: a single IP generating 100 events/second would produce 100 alerts/second — flooding the dashboard.
Without hysteresis: a borderline score oscillating around the alert threshold would cause rapid alert/clear/alert/clear — confusing operators.

### 11.6 Why Online Learning

Network traffic evolves. The autoencoder trained on Monday's traffic may not accurately model Friday's traffic. Online learning:
- Updates the autoencoder with a single SGD step on confirmed-benign events
- Uses low learning rate (0.001) and stochastic sampling (1 in 100 events)
- Adapts to gradual drift without catastrophic forgetting
- Avoids expensive offline retraining

### 11.7 Why Panic Mode

If the engine encounters 100+ faults (NaN in state, storage failures, etc.), it may be producing incorrect results. Rather than generating false alerts or missing real attacks:
- Panic mode disables reasoning and memory writes
- Falls back to rule-based detection only
- Auto-exits when fault rate drops below threshold
- Provides graceful degradation under hardware/software issues

---

## 12. What Is Better to Have

### 12.1 Already Implemented (What We Have)

| Feature | Status | Value |
|---------|--------|-------|
| 9-step detection pipeline | Complete | Core detection capability |
| Hierarchical SSM (4 levels) | Complete | Multi-scale temporal analysis |
| Partitioned memory | Complete | Context-aware retrieval |
| Autoencoder | Complete | Nonlinear anomaly detection |
| Online learning | Complete | Adaptation to traffic drift |
| Correlation engine | Complete | Multi-event pattern detection |
| Specialist modules | Complete | Domain-specific detection |
| Sharded pipeline | Complete | Parallel processing |
| State persistence | Complete | Crash recovery |
| C API bridge | Complete | Python ↔ C++ integration |
| CloudUploader | Complete | Edge-to-cloud forwarding |
| Real-time WebSocket | Complete | Instant alert delivery |
| Adaptive thresholds | Complete | Self-calibrating |
| Panic mode | Complete | Graceful degradation |
| Watchdog | Complete | Auto-restart hung shards |
| Hot-reload config | Complete | Runtime tuning |
| 21 unit tests | Complete | Core algorithm verification |
| 13 e2e tests | Complete | End-to-end detection evaluation |

### 12.2 What Would Improve Detection

| Enhancement | Current Gap | Impact |
|------------|-------------|--------|
| Deep packet inspection | Only header-level features | Could detect payload-based attacks |
| TLS fingerprinting | No JA3/JA3S analysis | Could detect encrypted C2 channels |
| DNS analytics | Not implemented | Could detect DNS tunneling |
| Geographic analysis | Not implemented | Could detect unusual geo-locations |
| Threat intel feeds | Not integrated | Could correlate with known IOIs |
| Anomaly explanation | Basic text only | Could provide visual explanations |
| Multi-tenant isolation | Shared backend | Need per-tenant SSM state |
| Horizontal scaling | Single backend | Need distributed processing |

### 12.3 What Would Improve Operations

| Enhancement | Current Gap | Impact |
|------------|-------------|--------|
| Prometheus/Grafana | Basic TCP metrics server | Production monitoring |
| Structured logging | Basic Python logging | Debugging, audit trail |
| Backup/restore | Manual state files | Disaster recovery |
| Alert fatigue mgmt | Basic cooldown | Smart deduplication, grouping |
| Incident response | Not implemented | Automated containment |
| Compliance reports | Basic report templates | SOC2, HIPAA, PCI-DSS |

### 12.4 What Would Improve Security

| Enhancement | Current Gap | Impact |
|------------|-------------|--------|
| API key rotation | Manual regeneration | Automatic rotation |
| Rate limiting | Basic sliding window | Per-endpoint limits |
| Audit logging | Not implemented | Track all API operations |
| Encryption at rest | Database stores plaintext | Encrypt sensitive fields |
| Network segmentation | Single Docker network | Micro-segmentation |

---

## Appendix A: File Reference

### C++ Engine (include/)

| File | Lines | Purpose |
|------|-------|---------|
| `ids.hpp` | 1130+ | Main facade — 9-step pipeline, config, state persistence |
| `ids_types.hpp` | 790 | All shared types, enums, structs, near-miss/aggregator |
| `ids_level0.hpp` | 199 | L0 LocalAnalyzer — 64-dim embedding, Z-score |
| `ids_level1.hpp` | 150 | L1 SegmentSSM — per-IP flush rules |
| `ids_ssm.hpp` | 276 | SSM (Mamba-style) + HierarchicalSSM (4 levels) |
| `ids_memory.hpp` | 349 | VectorStore, RuleTable, MemoryStore, Retriever |
| `ids_reasoning.hpp` | 216 | Gate score, score fusion, attention, reasoning model |
| `ids_decision.hpp` | 221 | Decision engine — overrides, hysteresis, cooldown |
| `ids_correlation.hpp` | 342 | Correlation engine — repeat/multi-stage/distributed/slow |
| `ids_adaptive.hpp` | 221 | Adaptive baselines — per-scope EWMA |
| `ids_nn.hpp` | 327 | Autoencoder — 3-layer NN with backprop |
| `ids_sharded.hpp` | 416 | ShardedIDS — N parallel pipelines + watchdog |
| `ids_specialist.hpp` | 70 | Specialist interface |
| `ids_cloud.hpp` | — | CloudUploader — HTTP client for backend |
| `ids_ingest.hpp` | — | CSV dataset ingester + calibration |
| `ids_telemetry.hpp` | — | Metrics, latency, drift series |
| `ids_model.hpp` | — | ModelHolder, parameter staging |
| `ids_parallel.hpp` | — | Parallel processing utilities |
| `ids_thread_pool.hpp` | — | Thread pool implementation |
| `ids_fused_engine.hpp` | — | Fused engine combining subsystems |
| `ids_specialist_impl.hpp` | — | Specialist implementations |
| `ids_specialist_ddos.hpp` | — | DDoS specialist detector |
| `ids_capture.hpp` | — | libpcap packet capture bridge |
| `ids_c_api.h` | — | C API header for Python FFI |

### Tools

| File | Lines | Purpose |
|------|-------|---------|
| `ids_production.cpp` | 698 | Production daemon — capture, pipeline, cloud forwarding |
| `ids_production.conf` | — | Default daemon configuration |
| `ids.service` | — | systemd service unit |
| `ids_c_api.cpp` | 303 | C API implementation — Python bridge |
| `ids_collector.cpp` | — | Real-time packet capture daemon |
| `ids_xdp.c` | — | eBPF/XDP kernel packet parser |

### Backend (backend/app/)

| File | Lines | Purpose |
|------|-------|---------|
| `main.py` | 178 | FastAPI entry point, CORS, routers |
| `config.py` | — | Settings from env vars |
| `database.py` | — | SQLAlchemy engine + session |
| `models.py` | 250 | ORM models (10 tables) |
| `schemas.py` | 328 | Pydantic request/response schemas |
| `auth.py` | — | JWT + bcrypt authentication |
| `broadcaster.py` | 53 | In-memory pub/sub for WebSocket |
| `central_runtime.py` | 333 | Event processing runtime (4 workers) |
| `ids_bridge.py` | 198 | ctypes bridge to libids_central.so |
| `routers/alerts.py` | 415 | Alert ingestion + queries |
| `routers/stream.py` | 104 | SSE + WebSocket endpoints |

### Tests

| File | Tests | Coverage |
|------|-------|----------|
| `ids_unit_tests.cpp` | 21 | L0, SSM, Memory, Reasoning, Decision, CSV parsing |
| `ids_e2e_test.cpp` | 13 | End-to-end detection on CICIDS2017 data |

---

## Appendix B: Configuration Reference

### IDSConfig (include/ids.hpp)

```cpp
struct IDSConfig {
    size_t               local_window     = 64;        // L0 sliding window
    SegmentSSM::Config   segment          = {};        // L1 flush rules
    ReasoningConfig      reason           = {};        // Reasoning thresholds
    DecisionPolicy       policy           = {};        // Allow/block lists
    RoutingConfig        routing          = {};        // Flush/promote/skip rules
    WritePolicy          write_policy     = {};        // Memory write gates
    EvictionConfig       eviction         = {};        // Memory limits per scope
    RetrievalTimeConfig  retrieval_time   = {};        // Max age, recency tau
    RetrievalWeights     retrieval_weights= {};        // Similarity weights
    ForceRetrievalConfig force_retrieval  = {};        // Force retrieval conditions
    MemoryCleanupConfig  cleanup          = {};        // TTL, cleanup triggers
    ReasoningGateConfig  gate             = {};        // Gate threshold + weights
    ForcedReasoningConfig force_gate      = {};        // Force reasoning conditions
    SkipReasoningConfig  skip_gate        = {};        // Skip reasoning conditions
    ScoreFusionWeights   fusion           = {};        // Score fusion weights
    DecisionThresholds   thresholds       = {};        // Ignore/Log/Alert/Block/Escalate
    EscalationConfig     escalation       = {};        // Escalation rules
    HysteresisConfig     hysteresis       = {};        // Decision stability
    CooldownConfig       cooldown         = {};        // Alert/block cooldown
    PanicConfig          panic            = {};        // Panic mode triggers
    StateConfig          state            = {};        // Decay rates, timeouts
    LearningModeConfig   learning         = {};        // Training mode
    OnlineLearningConfig online_learning  = {};        // Online AE updates
    CorrelationConfig    correlation      = {};        // Correlation weights
    CorrelationLimits    corr_limits      = {};        // Store size limits
    MultiStageConfig     multi_stage      = {};        // Attack patterns
    DistributedAttackConfig distributed   = {};        // DDoS detection
    SlowAttackConfig     slow_attack      = {};        // APT detection
    AdaptiveThresholdConfig adaptive_threshold = {};   // Threshold adaptation
    AdaptiveDecayConfig  adaptive_decay    = {};       // Decay adaptation
    AdaptiveRoutingConfig adaptive_routing = {};       // Routing adaptation
    AdaptationLimits     adapt_limits      = {};       // Adaptation bounds
    ShardingConfig       sharding          = {};       // Shard count + hash key
    QueueConfig          queue             = {};       // Queue depth
    BackpressureConfig   backpressure      = {};       // Backpressure policy
    WatchdogConfig       watchdog          = {};       // Watchdog settings
    TelemetryConfig      telemetry         = {};       // Logging + metrics
};
```

### Default Thresholds

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `ignore_threshold` | 0.20 | Below this: ignore event |
| `log_threshold` | 0.40 | Below this: log only |
| `alert_threshold` | 0.60 | Below this: raise alert |
| `block_threshold` | 0.85 | Below this: block |
| `escalate_threshold` | 0.95 | Above this: escalate |
| `gate_threshold` | 0.35 | Gate score to trigger reasoning |
| `memory_write_gate` | 0.50 | Anomaly score to write to memory |
| `memory_force_gate` | 0.85 | Anomaly score to force global write |
