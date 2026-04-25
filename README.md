# IDS — Intrusion Detection System v2

A production-grade, header-only C++17 intrusion detection engine built around a hierarchical Mamba-style Selective State Space Model (SSM) pipeline. It processes network and system events in real time, detects anomalies, correlates multi-stage attack campaigns, and makes block/alert/escalate decisions — all in under 300 µs per event on a single core.

---

## What Is This?

IDS is a self-contained detection engine you embed directly into your application, network appliance, or monitoring stack. It is not a standalone daemon or a signature-only scanner. It combines:

- statistical anomaly detection (per-event, per-IP, per-host, per-user)
- a Mamba-style SSM hierarchy that learns and tracks behavioral drift over time
- a partitioned vector memory store for scoped retrieval of past attack context
- an attention-based reasoning layer that fuses all signals into a final decision
- a correlation engine that links individual events into tracked campaigns
- a per-scope adaptive baseline that self-tunes thresholds to observed traffic

The result is a system that catches both known attacks (via rules and signatures) and unknown/novel attacks (via behavioral drift and anomaly scoring) while suppressing noise from benign traffic.

---

## What Can It Detect?

- Port scans and reconnaissance
- Brute-force and credential stuffing attacks
- DoS / DDoS bursts (single source and distributed, N sources → same host)
- Lateral movement sequences
- APT / slow-burn attacks (low-and-slow accumulation over hours)
- Ransomware and file system anomalies
- Encrypted C2 channels and data exfiltration
- Auth anomalies and privilege escalation
- Multi-stage attack chains (port scan → brute force → lateral movement → exfil)
- Any custom attack pattern defined via rules or multi-stage sequence configs

---

## Architecture

Events flow through a fixed 9-step pipeline defined in `ids.hpp`:

```
Event
  │
  ├─ [1]   L0 — LocalAnalyzer (ids_level0.hpp)
  │              sliding window, 64-dim embedding, per-event anomaly score
  │
  ├─ [2]   L1 — SegmentSSM per source IP (ids_level1.hpp)
  │              Mamba SSM accumulates events, flushes on:
  │              count / wall-time / anomaly spike / session-end / type change
  │
  ├─ [3-4] L2 Hierarchy — HierarchicalSSM (ids_ssm.hpp)
  │              L2s (short, per-IP) → L2m (mid, per-host) → L2l (global)
  │              signal-driven conditional promotion; skip rules suppress noise
  │              NaN/Inf + energy clamp after every SSM step
  │
  ├─ [5]   Memory Write — Retriever (ids_memory.hpp)
  │              score-gated; partitioned by IP / user / host / session / process
  │
  ├─ [6]   Retrieval — scoped narrow→broad (IP → user → session → host → global)
  │              top-8 records, recency-weighted, deduped
  │
  ├─ [7]   Reasoning Gate + Score Fusion (ids_reasoning.hpp)
  │              weighted 6-signal gate; single-head attention over token set;
  │              configurable ScoreFusionWeights; force/skip rules
  │
  ├─ [7.5] Correlation Engine (ids_correlation.hpp)
  │              repeat / multi-stage / distributed / slow-attack detection
  │              campaign lifecycle tracking
  │
  └─ [8]   Decision Engine (ids_decision.hpp)
               6-step override order, hysteresis, cooldown, escalation
               post-decision memory write for Block/Escalate
```

### SSM Hierarchy Levels

| Level | Scope | Key | Promotion trigger |
|-------|-------|-----|-------------------|
| L0 | per-event | — | every event |
| L1 | per-IP session | source IP | flush rules (count / time / anomaly / session-end / type change) |
| L2s | short-term per-IP | source IP | on L1 flush; skip if anomaly_trend < 0.20 and segment_count < 3 |
| L2m | mid-term per-host | destination host | every 10 L2s updates OR anomaly_history > 0.55 OR drift > 3.0 |
| L2l | global | singleton | every 60 L2m updates OR drift > 8.0 OR anomaly_history > 0.70 |

Force promotion bypasses all skip/tick rules when `anomaly_score > 0.90` or decision is Block/Escalate.

---

## Decision Outputs

| Decision | Score range | Meaning |
|----------|-------------|---------|
| Ignore | < 0.20 | Benign, no action |
| Log | 0.20–0.40 | Low-confidence anomaly, record only |
| Alert | 0.40–0.60 | Suspicious, notify SOC |
| Block | 0.60–0.85 | High-confidence threat, block so
**Partitioned memory** — each IP, user, host, session, and process has its own memory partition. IP A's attack history never contaminates IP B's retrieval context.

**Configurable score fusion** — all weights (gate, fusion, retrieval, escalation) are exposed as structs. No hardcoded magic numbers in the hot path.

**Correlation engine** — links events across time into campaigns. Detects repeat offenders, multi-stage attack sequences (port scan → brute force → lateral movement), distributed attacks (N sources → same host), and slow-burn APT patterns.

**Adaptive baseline** — per-scope EMA baselines (global / host / user / IP) freeze during attacks and adapt during normal traffic. Thresholds self-tune to the observed traffic profile.

**Fault tolerance** — every pipeline stage is wrapped in try/catch. NaN/Inf in SSM state triggers a reset, not a crash. Panic mode degrades gracefully to rule-only detection when fault rate spikes.

**Sharded pipeline** — `ShardedIDS` runs N independent pipeline instances with consistent hash routing (same IP always hits the same shard). Supports Priority backpressure that drops low-anomaly events first under load.

**Full observability** — per-stage latency (avg + p99), drift time series, routing log, fault log, campaign state, shard stats, and a live ncurses dashboard.

---

## File Structure

```
include/
  ids_types.hpp       — all shared structs, enums, config types
  ids_level0.hpp      — LocalAnalyzer (L0), event validation
  ids_level1.hpp      — SegmentSSM (L1), flush rules
  ids_ssm.hpp         — L1SSM, HierarchicalSSM (L2s/L2m/L2l)
  ids_memory.hpp      — partitioned MemoryStore, Retriever
  ids_reasoning.hpp   — gate scoring, score fusion, ReasoningModel
  ids_decision.hpp    — DecisionEngine, RepeatTracker, overrides
  ids_correlation.hpp — CorrelationEngine, campaign tracking
  ids_adaptive.hpp    — AdaptiveLayer, per-scope baselines
  ids_telemetry.hpp   — metrics, latency, drift series, MetricsSink
  ids_sharded.hpp     — ShardedIDS, BoundedQueue, watchdog
  ids_model.hpp       — ModelHolder, parameter staging/apply
  ids.hpp             — IDS facade (main entry point)

ids_example.cpp       — integration demo (5-phase attack simulation)
ids_visualizer.cpp    — live ncurses dashboard with pcap capture
CMakeLists.txt        — build system
```

---

## Build

Requires: C++17, CMake ≥ 3.16, GCC ≥ 9 or Clang ≥ 10.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

This builds `ids_demo` (the example). The live visualizer also builds if `libpcap` and `libncurses` are present:

```bash
# Ubuntu/Debian
sudo apt install libpcap-dev libncurses-dev

# RHEL/Fedora
sudo dnf install libpcap-devel ncurses-devel
```

---

## Quick Start

```cpp
#include "ids.hpp"

ids::IDSConfig cfg;
cfg.gate.gate_threshold        = 0.35f;
cfg.thresholds.alert_threshold = 0.55f;
cfg.thresholds.block_threshold = 0.80f;
cfg.write_policy.memory_write_gate = 0.50f;
cfg.policy.block_list = {"10.0.0.99"};

ids::IDS pipeline(cfg);

pipeline.on_alert([](const ids::Alert& a) {
    std::cout << "ALERT " << a.attack_class
              << " conf=" << a.confidence
              << " src=" << a.source << "\n";
});

pipeline.on_block([](const std::string& src) {
    std::cout << "BLOCK " << src << "\n";
});

pipeline.on_escalate([](const ids::Alert& a) {
    std::cout << "ESCALATE campaign=" << a.trace.campaign_id << "\n";
});

// Add a rule
pipeline.add_rule({1, "PortScan", "", 0.60f, ids::Decision::Alert});

// Ingest events
ids::Event ev;
ev.source      = "192.168.1.100";
ev.destination = "10.0.0.1";
ev.type        = ids::EventType::NetworkPacket;
ev.payload.rate_hz = 5000.f;
ev.payload.entropy = 0.9f;

pipeline.ingest(ev);
```

---

## Sharded (Production) Setup

```cpp
#include "ids_sharded.hpp"

ids::IDSConfig cfg;
cfg.sharding.hash_key             = "ip";
cfg.queue.queue_depth             = 4096;
cfg.backpressure.policy           = ids::BackpressurePolicy::Priority;
cfg.watchdog.heartbeat_interval_s = 1.0f;
cfg.watchdog.auto_restart         = true;

ids::ShardedIDS ids_sys(cfg, 8);   // 8 independent pipeline shards
ids_sys.on_alert([](const ids::Alert& a){ /* ... */ });
ids_sys.start();

ids_sys.ingest(event);   // lock-free hash-route + enqueue
ids_sys.shutdown();
```

---

## Live Dashboard

```bash
# capture all IP traffic on eth0
sudo ./build/ids_visualizer eth0

# TCP only
sudo ./build/ids_visualizer eth0 "tcp port 80 or tcp port 443"
```

Press `q` to quit. See `VISUALIZER_SETUP.md` for full setup and BPF filter examples.

---

## Configuration Reference

All config lives in `IDSConfig`. Key sub-structs:

| Struct | Controls |
|--------|----------|
| `gate` (`ReasoningGateConfig`) | Multi-signal gate threshold and weights |
| `thresholds` (`DecisionThresholds`) | Ignore / Log / Alert / Block score boundaries |
| `write_policy` (`WritePolicy`) | When to write events to memory |
| `routing` (`RoutingConfig`) | Flush, promotion, skip, force, split rules |
| `escalation` (`EscalationConfig`) | Escalation conditions and repeat window |
| `correlation` (`CorrelationConfig`) | Correlation weights and campaign timeouts |
| `panic` (`PanicConfig`) | Fault threshold and degraded-mode behavior |
| `telemetry` (`TelemetryConfig`) | Log level, drift series, routing debug |
| `sharding` (`ShardingConfig`) | Number of shards and hash key |

Hot-reload thresholds and weights at runtime without restarting:

```cpp
auto new_cfg = std::make_shared<ids::IDSConfig>(cfg);
new_cfg->thresholds.alert_threshold = 0.60f;
pipeline.hot_reload_config(new_cfg);

// Roll back if needed
pipeline.rollback_config(1);
```

---

## Latency Budget (single shard, p99)

| Stage | Target |
|-------|--------|
| L0 local analyzer | < 5 µs |
| L1 segment SSM | < 10 µs |
| L2 hierarchy | < 10 µs |
| Memory write | < 5 µs |
| Retrieval | < 50 µs |
| Reasoning (~20% of events) | < 200 µs |
| Decision | < 5 µs |
| Total (no reasoning) | < 85 µs |
| Total (with reasoning) | < 285 µs |

---

## What You Can Do With This

- Embed it in a network appliance or host agent to detect intrusions in real time
- Use it as the detection core of a SIEM or XDR platform
- Run it in learning mode for an hour to auto-calibrate thresholds to your traffic
- Feed it custom rules and attack signatures for your environment
- Use the correlation engine to track multi-stage campaigns across your network
- Export `DecisionTrace` from every alert into your SIEM for full audit trails
- Scale horizontally with `ShardedIDS` across multiple CPU cores
- Hot-reload thresholds and rules without downtime

---

## v1 → v2 Migration

See `IDS_v2_Upgrade_Documentation.md` for the full migration guide. The short version:

```cpp
// v1
cfg.reasoning_gate    = 0.35f;
cfg.memory_write_gate = 0.50f;

// v2
cfg.gate.gate_threshold            = 0.35f;
cfg.write_policy.memory_write_gate = 0.50f;
```

All callbacks (`on_alert`, `on_block`, `on_escalate`) and the `ingest()` API are unchanged.


---

## Live Packet Capture (ids_capture.hpp)

`ids_capture.hpp` provides a `PacketCapture` class that bridges raw libpcap packets directly into the IDS pipeline. It handles Ethernet → IPv4 → TCP/UDP parsing, Shannon entropy calculation from payload bytes, and runs the capture loop on a background thread.

```cpp
#include "ids_capture.hpp"

ids::IDS pipeline(cfg);

ids::PacketCapture cap("eth0", "ip");   // interface + BPF filter
cap.on_event([&](const ids::Event& ev) {
    pipeline.ingest(ev);
});

if (!cap.start()) {
    std::cerr << "Capture failed\n";
    return 1;
}

// ... run until done ...
cap.stop();

auto snap = cap.stats().snapshot();
std::cout << "captured=" << snap.packets_captured
          << " dropped=" << snap.packets_dropped << "\n";
```

List available interfaces:

```cpp
auto ifaces = ids::PacketCapture::list_interfaces();
for (const auto& i : ifaces) std::cout << i << "\n";
```

The `packet_to_event()` function is also available standalone if you already have a pcap handle and want to convert packets yourself.

---

## Telemetry & Observability

Every pipeline instance exposes a full telemetry surface.

**Metrics snapshot:**

```cpp
const auto& m = pipeline.metrics();
m.events_total.load()
m.alerts_total.load()
m.blocks_total.load()
m.escalations_total.load()
m.reasoning_calls.load()
m.forced_reasoning.load()
m.memory_writes.load()
m.faults_total.load()
```

**Per-stage latency (avg + p99):**

```cpp
auto lat = pipeline.latency_stats();
lat.l0_avg_us           // LocalAnalyzer
lat.l1_avg_us           // SegmentSSM
lat.retrieval_avg_us    // memory retrieval
lat.reasoning_avg_us    // attention + fusion
lat.total_avg_us        // end-to-end
lat.total_p99_us        // p99 end-to-end
```

**Health and fault log:**

```cpp
const auto& h = pipeline.health();
h.numeric_faults.load()   // NaN/Inf in SSM state
h.reasoning_fails.load()  // reasoning exceptions
h.panic_mode              // currently degraded?

auto faults = pipeline.fault_log_entries(10);  // last 10 faults
```

**Drift time series** (records drift_score + anomaly_history over time):

```cpp
// enabled via cfg.telemetry.drift_series = true
// access via TelemetryExporter::export_drift_series()
```

**Push metrics to an external sink** (e.g. Prometheus, StatsD):

```cpp
// Access the exporter via the pipeline internals or wire your own sink
// using TelemetryExporter::set_sink():
exporter.set_sink([](const ids::Metrics& m) {
    push_to_prometheus(m.events_total.load(), m.alerts_total.load());
}, 1.0f);  // push every 1 second
```

**Routing debug log** (traces every flush/promote/skip decision):

```cpp
cfg.telemetry.routing_debug = true;
// ...
auto log = pipeline.routing_log(50);  // last 50 routing events
for (const auto& e : log)
    std::cout << e.reason << " from=" << e.from_level
              << " to=" << e.to_level << "\n";
```

---

## DecisionTrace — Full Audit Trail

Every `Alert` carries a `DecisionTrace` with the complete signal breakdown for SOC review or SIEM ingestion:

```cpp
pipeline.on_alert([](const ids::Alert& a) {
    const auto& t = a.trace;
    // Raw signals
    t.local_score              // L0 anomaly score
    t.segment_trend            // L1 segment trend
    t.anomaly_history          // L2 EMA
    t.drift_score              // baseline drift
    t.retrieval_similarity_max // top retrieved record similarity
    t.rule_matched             // any rule fired?
    // Gate
    t.gate_score               // weighted multi-signal gate result
    t.forced                   // was reasoning forced?
    t.skipped                  // was reasoning skipped?
    // Scores
    t.fused_score              // score fusion output
    t.corr_score               // correlation engine contribution
    t.final_score              // combined final
    // Decisions
    t.base_decision            // before overrides
    t.final_decision           // after all overrides
    // Classification
    t.attack_class
    t.correlation_type         // "repeat" | "multi_stage" | "distributed" | "slow_attack"
    t.campaign_id              // links all alerts from the same campaign
});
```

---

## Threshold Calibration

Use `BaselineCalibrator` to observe normal traffic and get suggested thresholds before going live:

```cpp
ids::BaselineCalibrator cal;

// Learning phase — feed normal traffic
for (const auto& ev : normal_traffic) {
    auto state = pipeline.ingest(ev);
    cal.observe(state.local, state.segment);
}

// Get suggestions targeting 1% false-positive rate
auto s = cal.compute(0.01f);
cfg.gate.gate_threshold        = s.gate_threshold;
cfg.thresholds.alert_threshold = s.alert_threshold;
cfg.thresholds.block_threshold = s.block_threshold;
```

Or use learning mode to do this automatically during initial deployment:

```cpp
cfg.learning.enabled          = true;
cfg.learning.disable_blocking = true;   // no Block/Escalate during learning
cfg.learning.duration_s       = 3600.f; // observe for 1 hour
```

---

## State Persistence

Save and restore pipeline state across restarts:

```cpp
// Save
pipeline.save_all("/var/ids/state");
// Writes: ids_state.bin, ids_memory.json, ids_config.json

// Restore (missing files start clean — non-fatal)
pipeline.load_state("/var/ids/state/ids_state.bin");
```

For `ShardedIDS`:

```cpp
ids_sys.flush_pending();              // flush in-flight L1 segments first
ids_sys.save_all("/var/ids/state");   // shard_0_state.bin, shard_1_state.bin, ...
ids_sys.load_all("/var/ids/state");   // on next startup
```

---

## Model Updates

Stage and apply new SSM parameters without downtime:

```cpp
// Stage (validates, does not affect running pipeline)
pipeline.stage_model("/models/ids_v3.bin");

// Apply atomically (resets all SSM state, installs new params)
pipeline.apply_model();

// Roll back if the new model behaves badly
pipeline.rollback_model(1);
```

---

## Attack Classification Labels

The reasoning model produces these attack class strings in `Alert.attack_class` and `DecisionTrace.attack_class`:

| Label | Trigger |
|-------|---------|
| `DoS/DDoS` | High burst metric + high rate |
| `EncryptedC2/Exfiltration` | High entropy + high error frequency |
| `BruteForce/CredentialStuffing` | Auth-dominant segment + high anomaly trend |
| `FileSystemAnomaly/Ransomware` | File-dominant segment + high local score |
| `LateralMovement/Persistence` | Process-dominant segment + high drift |
| `RuleMatch:<name>` | Matched a named rule |
| `UnknownHighSeverity` | Score above block threshold, no class match |
| `UnknownLowSeverity` | Score above alert threshold, no class match |
| `none` | Score below classification floor |

Multi-stage correlation adds campaign-level labels like `LateralMovement` and `APT-Exfiltration` via the `CorrelationEngine`.

---

## Requirements

| Requirement | Minimum |
|-------------|---------|
| C++ standard | C++17 |
| CMake | 3.16 |
| Compiler | GCC 9+ or Clang 10+ |
| Threads | pthreads (Linux) |
| Visualizer | libpcap + libncurses |
| Capture bridge | libpcap |

Header-only — no separate compilation step for the core library. Just `#include "ids.hpp"` and link with `-lpthread`.
