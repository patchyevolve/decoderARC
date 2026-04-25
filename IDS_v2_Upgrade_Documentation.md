# IDS System — v2 Upgrade Documentation

> **Applies to:** All 11 headers in `include/`
> **Spec source:** `IDS_Refinement_Spec.md` (§1–§9)
> **Build:** `g++ -std=c++17 -O2 -Iinclude your_file.cpp`

---

## Table of Contents

1. [Overview of Changes](#1-overview-of-changes)
2. [Breaking Changes & Migration Guide](#2-breaking-changes--migration-guide)
3. [§1 — Hierarchy Routing Policy](#3-1--hierarchy-routing-policy)
4. [§2 — Memory Partition & Retrieval Policy](#4-2--memory-partition--retrieval-policy)
5. [§3 — Reasoning Gate & Decision Policy](#5-3--reasoning-gate--decision-policy)
6. [§4 — Concurrency & Sharding Types](#6-4--concurrency--sharding-types)
7. [§5 — Fault Handling & Recovery](#7-5--fault-handling--recovery)
8. [§6 — Training & Parameter Update](#8-6--training--parameter-update)
9. [§7 — Correlation & Campaign Tracking](#9-7--correlation--campaign-tracking)
10. [§8 — Adaptive Baseline & Self-Tuning](#10-8--adaptive-baseline--self-tuning)
11. [§9 — Telemetry & Observability](#11-9--telemetry--observability)
12. [Gap Analysis Resolution](#12-gap-analysis-resolution)
13. [Complete IDSConfig Reference](#13-complete-idsconfig-reference)
14. [Full API Reference](#14-full-api-reference)

---

## 1. Overview of Changes

### What changed

v2 is a complete production hardening of the v1 architecture. The detection logic is identical — the SSM hierarchy, attention-based reasoning, and decision engine are unchanged in semantics. What v2 adds is the full operational layer that makes the system deployable:

| Area | v1 | v2 |
|---|---|---|
| Hierarchy promotion | Fixed tick counters | Signal-driven, conditional per-layer |
| Memory | Single global `VectorStore` | Partitioned by IP / user / host / session / process |
| Reasoning gate | Single float threshold | Weighted multi-signal gate + force/skip rules |
| Score fusion | Hardcoded weights | Configurable `ScoreFusionWeights` |
| Decision overrides | 2 checks | 6-step deterministic override order |
| Escalation | 1 condition | 5 conditions including repeat detection and campaign |
| Decision stability | None | Hysteresis + per-source cooldown |
| SSM numeric safety | None | NaN/Inf + energy clamp after every step |
| Input validation | None | `validate_event()` at pipeline entry |
| Fault handling | None | `FaultLog`, panic mode, panic auto-exit, fallback scores |
| Correlation | None | `CorrelationEngine` — repeat, multi-stage, distributed, slow-burn |
| Adaptive baseline | None | Per-scope `ScopeBaseline` with freeze, adaptive thresholds |
| Telemetry | None | Metrics, latency tracking, drift series, routing log, MetricsSink |
| Per-IP state | Shared | Per-key `SegmentSSM` instance map |
| New files | 8 headers | 11 headers (`ids_correlation.hpp`, `ids_adaptive.hpp`, `ids_telemetry.hpp` added) |

### Files changed

| File | Status | Summary |
|---|---|---|
| `ids_types.hpp` | Major expansion | +50 new structs covering all 9 spec sections; `WatchdogConfig` added to `IDSConfig` |
| `ids_ssm.hpp` | Rewritten | Signal-driven promotion, NaN/energy checks, `StateConfig` |
| `ids_level0.hpp` | Minor | Added `validate_event()` |
| `ids_level1.hpp` | Rewritten | `FlushRules` wired in, per-key instantiation, `SegmentSSMConfig` top-level |
| `ids_memory.hpp` | Rewritten | Partitioned store, scoped write, TTL-first eviction, `Retriever::cleanup()` |
| `ids_reasoning.hpp` | Rewritten | `compute_gate_score()`, `fuse_score()`, `DecisionTrace`, `BaselineCalibrator` |
| `ids_decision.hpp` | Rewritten | `RepeatTracker`, 6-step overrides, hysteresis, cooldown, learning mode |
| `ids_correlation.hpp` | **New** | Full correlation engine |
| `ids_adaptive.hpp` | **New** | Per-scope adaptive baseline layer |
| `ids_telemetry.hpp` | **New** | Full observability layer |
| `ids_sharded.hpp` | **New** | §4.3 sharded pipeline — `ShardedIDS`, `BoundedQueue`, `Shard`, watchdog |
| `ids.hpp` | Rewritten | Per-IP L1 map, full §1.13 routing order, all new stages wired |

---

## 2. Breaking Changes & Migration Guide

### Renamed types

| v1 name | v2 name | File |
|---|---|---|
| `ExternalMemory` | `MemoryStore` | `ids_memory.hpp` |
| `IDS::Config` | `IDSConfig` (top-level struct) | `ids.hpp` |
| `SegmentSSM::Config` | `SegmentSSMConfig` (top-level struct) | `ids_level1.hpp` |
| `ReasoningModel::Config` | `ReasoningConfig` | `ids_reasoning.hpp` |
| `DecisionEngine::Policy` | `DecisionPolicy` | `ids_decision.hpp` |

### Removed fields from IDSConfig

These v1 flat fields no longer exist on `IDSConfig` directly:

```cpp
// v1 — no longer valid
cfg.reasoning_gate    = 0.35f;   // → cfg.gate.gate_threshold = 0.35f
cfg.memory_write_gate = 0.50f;   // → cfg.write_policy.memory_write_gate = 0.50f
```

### Minimal v1 → v2 migration

```cpp
// v1
ids::IDS::Config cfg;
cfg.reasoning_gate         = 0.35f;
cfg.memory_write_gate      = 0.50f;
cfg.reason.alert_threshold = 0.55f;
cfg.reason.block_threshold = 0.80f;
cfg.policy.block_list      = {"10.0.0.99"};
ids::IDS pipeline(cfg);

// v2 equivalent
ids::IDSConfig cfg;
cfg.gate.gate_threshold        = 0.35f;
cfg.write_policy.memory_write_gate  = 0.50f;
cfg.thresholds.alert_threshold = 0.55f;
cfg.thresholds.block_threshold = 0.80f;
cfg.policy.block_list          = {"10.0.0.99"};
ids::IDS pipeline(cfg);
```

All other integration code (`on_alert`, `on_block`, `on_escalate`, `ingest`, `add_rule`, `load_signature`) is unchanged.

---

## 3. §1 — Hierarchy Routing Policy

**File:** `ids_ssm.hpp`, `ids_level1.hpp`, `ids_types.hpp`, `ids.hpp`

### Problem solved

v1 promoted state through hierarchy levels using only fixed tick counters `{1, 10, 60, 600}`. A DDoS burst was not promoted faster than an idle background connection. Noise from low-activity sources polluted the global SSM state.

### Solution

Each of the four SSM layers now evaluates its own promotion conditions before stepping. Routing is a pure function of existing pipeline signals — no new data required.

### FlushRules — when L1 segments flush

`SegmentSSM` now flushes on **any** of these conditions (previously only count and time):

```cpp
struct FlushRules {
    size_t flush_n              = 100;    // event count
    float  flush_t              = 10.f;   // wall time (seconds)
    float  flush_anomaly        = 0.70f;  // NEW: early flush on high anomaly
    bool   flush_on_session_end = true;   // NEW: flush on session-end metadata
    bool   flush_on_type_change = true;   // NEW: flush on dominant type shift
};
```

**Key addition:** `flush_anomaly = 0.70` means an attack that immediately spikes the rolling anomaly trend flushes within a few events rather than waiting for 100. This is critical for burst attacks.

### Promotion rules — L1 → L2s → L2m → L2l

```
L1 → L2s:  promote_on_flush=true  OR  anomaly_trend > promote_threshold(0.50)
L2s → L2m: tick%10==0            OR  anomaly_history > mid_anomaly(0.55)
                                  OR  drift_score > mid_drift(3.0)
L2m → L2l: tick%60==0            OR  drift_score > global_drift(8.0)
                                  OR  anomaly_history > global_hist(0.70)
```

### Skip rules — noise suppression

Skip L1→L2s when **all** of:
- `anomaly_trend < 0.20` (below noise floor)
- `segment_count < 3` (state not yet stable)

This prevents the first few events from a new harmless IP polluting the global state.

### Force rules — emergency bypass

Force all levels to update immediately when:
- `local.anomaly_score > 0.90`
- `decision == Block` or `Escalate`
- Any rule with `action == Block` matched
- Manual flag `force_global = true`

```cpp
// In IDSConfig:
cfg.routing.force.force_anomaly  = 0.90f;
cfg.routing.force.force_on_block = true;
```

### Split rules — per-entity state isolation

New IP addresses, session IDs, and users each get their own `SegmentSSM` instance. State is never shared between entities.

```cpp
cfg.routing.split.split_on_new_ip      = true;
cfg.routing.split.split_on_new_session = true;
cfg.routing.split.split_on_new_user    = true;
```

The `ids.hpp` facade maintains a `std::unordered_map<std::string, SegmentSSM> l1_instances_` keyed by `ev.source`. New sources are instantiated on first event.

### Fixed routing order (§1.13)

The routing order is deterministic and must not be changed:

```
1.  L0 update (always)
2.  L1[key.ip] update
3.  Check FlushRules → if flush: produce SegmentState
4.  If SegmentState produced:
    a. Check SkipRules (L1→L2s)
    b. If not skipped OR force: L2s update (layer 0)
    c. Check PromotionRules (L2s→L2m) → layer 1
    d. Check PromotionRules (L2m→L2l) → layers 2, 3
5.  Memory write (pre-decision, score-gated)
6.  Retrieval (scoped)
7.  Gate check → reasoning
8.  Correlation
8b. Post-decision memory write (block/escalate)
9.  Decision + overrides + cooldown
```

---

## 4. §2 — Memory Partition & Retrieval Policy

**File:** `ids_memory.hpp`, `ids_types.hpp`

### Problem solved

v1 had a single global `VectorStore`. IP A's attack history contaminated IP B's retrieval context. Stale session records from 3 hours ago influenced current decisions.

### Partitioned MemoryStore

```cpp
struct MemoryStore {
    VectorStore global_store;                                          // all-time high-severity
    std::unordered_map<std::string, VectorStore> ip_store;             // per source IP
    std::unordered_map<std::string, VectorStore> host_store;           // per destination host
    std::unordered_map<std::string, VectorStore> user_store;           // per user
    std::unordered_map<std::string, VectorStore> session_store;        // per session ID
    std::unordered_map<std::string, VectorStore> process_store;        // per process
    RuleTable rules;
};
```

### Write policy

```cpp
struct WritePolicy {
    float memory_write_gate    = 0.50f;   // minimum score to write
    float memory_force_gate    = 0.85f;   // score that also writes to global_store
    bool  write_on_rule_match  = true;    // always write when a rule fires
    bool  write_on_block       = true;    // always write on Block decision  ← now works
    bool  write_on_escalate    = true;    // always write on Escalate        ← now works
    bool  write_on_high_drift  = false;
    float drift_write_threshold= 5.0f;
};
```

> **v1 gap fixed:** `write_on_block` and `write_on_escalate` now fire correctly via the **step 8b post-decision write** added to `ids.hpp`. In v1 the memory write always ran before the decision was known.

### Scope selection on write

```
anomaly_score ≥ any threshold → ip_store[src]
+ user key present            → user_store[user]
+ score ≥ 0.50                → host_store[dst]
+ score ≥ force_gate          → global_store
+ session key present         → session_store[session]
+ process key present         → process_store[proc]
```

### Retrieval scope order

Searches narrow→broad, merging results with deduplication:

| Priority | Scope | top_k | scope_weight |
|---|---|---|---|
| 1 | `ip_store[src]` | 3 | 1.00 |
| 2 | `user_store[user]` | 2 | 0.90 |
| 3 | `session_store[session]` | 2 | 0.85 |
| 4 | `host_store[dst]` | 2 | 0.70 |
| 5 | `global_store` | 1 | 0.50 |

Final retrieval score per record:

```
final_score = sim * 0.50
            + record.anomaly_score * 0.30
            + recency_factor(age, tau=600s) * 0.20
            + scope_weight
```

Records older than `retrieval_max_age_s = 3600s` are excluded entirely.

### Eviction order (v2 fix)

```
1. Records with age > 24h (TTL pass)  ← NEW in v2
2. Records with lowest anomaly_score
3. Oldest by insertion order (tie-break)
```

High-value attack records (score near 1.0) are the last to be evicted.

### Memory cleanup API

```cpp
retriever_.cleanup(key, CleanupReason::SessionEnd);    // removes session_store[session]
retriever_.cleanup(key, CleanupReason::HostRemoved);   // removes host_store[host]
retriever_.cleanup(key, CleanupReason::Manual);        // removes all scopes for key
retriever_.sweep(cfg.cleanup);                          // TTL sweep across all partitions
```

---

## 5. §3 — Reasoning Gate & Decision Policy

**File:** `ids_reasoning.hpp`, `ids_decision.hpp`, `ids.hpp`, `ids_types.hpp`

### Multi-signal gate (replaces single float)

v1: `if (ls.anomaly_score >= 0.40f) { run reasoning }`

v2: weighted gate score across 6 signals:

```cpp
struct GateWeights {
    float w_local     = 0.35f;   // LocalState.anomaly_score
    float w_segment   = 0.25f;   // SegmentState.anomaly_trend
    float w_history   = 0.15f;   // GlobalState.anomaly_history
    float w_drift     = 0.10f;   // GlobalState.drift_score / 10
    float w_retrieval = 0.10f;   // RetrievedContext.similarity_max
    float w_rule      = 0.05f;   // 1.0 if any rule matched
};

// gate_score >= gate_threshold(0.35) → run reasoning
```

### Force reasoning rules

Reasoning runs regardless of gate score when:

```cpp
struct ForcedReasoningConfig {
    bool  force_on_rule_match = true;    // any rule fired
    bool  force_on_block_list = true;    // source on block list
    float force_drift         = 6.0f;    // drift_score threshold
    float force_history       = 0.70f;   // anomaly_history threshold
    float force_local         = 0.90f;   // local anomaly spike
    bool  force_reasoning     = false;   // manual override
};
```

### Skip reasoning rules

Skip reasoning when clearly benign:

```cpp
struct SkipReasoningConfig {
    float skip_local_threshold = 0.10f;   // very low local score
    bool  skip_on_allow_list   = true;    // source on allow list
    bool  skip_when_idle       = false;
};
```

Priority: `force > skip > gate`. This ensures allow-listed hosts never trigger reasoning even if their anomaly score spikes briefly.

### Configurable score fusion

v1 used hardcoded weights inside `ReasoningModel`. v2 exposes `ScoreFusionWeights`:

```cpp
struct ScoreFusionWeights {
    float w_local     = 0.50f;
    float w_segment   = 0.25f;
    float w_history   = 0.15f;
    float w_drift     = 0.10f;
    float w_retrieval = 0.15f;   // boost if top retrieved record scores > 0.8
    float w_rule      = 0.10f;   // boost if any rule matched
};
```

### Decision thresholds

v2 exposes all four thresholds (v1 had only alert and block):

```cpp
struct DecisionThresholds {
    float ignore_threshold = 0.20f;   // < 0.20 → Ignore
    float log_threshold    = 0.40f;   // 0.20–0.40 → Log
    float alert_threshold  = 0.60f;   // 0.40–0.60 → Alert
    float block_threshold  = 0.85f;   // 0.60–0.85 → Block
                                      // ≥ 0.85 → Block (escalate conditions checked separately)
};
```

### Six-step override order

Overrides are applied in this fixed order — no exceptions:

```
1. allow_list match    → Decision::Ignore  (hard stop, returns immediately)
2. block_list match    → Decision::Block   (hard override)
3. ML score_to_decision()
4. Escalation check    (history ≥ 0.75 OR drift ≥ 8.0 → upgrade to Escalate)
5. Repeat detection    (same source alerted N times in window → Escalate)
6. Manual override flag
```

### Repeat detection

```cpp
struct RepeatTracker {
    // tracks alert_count, first_alert, last_alert per source string
};

// escalate when: alert_count[src] >= repeat_escalate_n
//                within repeat_window_s seconds of first_alert
cfg.escalation.repeat_escalate_n = 3;
cfg.escalation.repeat_window_s   = 300.f;
```

### Hysteresis

Prevents rapid oscillation around the block threshold:

```cpp
cfg.hysteresis.decision_hysteresis  = 0.05f;
cfg.hysteresis.decision_hold_time_s = 10.f;
// if last_decision was Block and score ≥ block_threshold - 0.05 → keep Block for 10s
```

### Cooldown

Suppresses repeated alerts from the same source within a time window:

```cpp
cfg.cooldown.alert_cooldown_s = 5.f;
cfg.cooldown.block_cooldown_s = 30.f;
cfg.cooldown.allow_stronger   = true;   // Block always fires even during Alert cooldown
```

### DecisionTrace

Every `Alert` now carries a full `DecisionTrace` for SOC review and SIEM ingestion:

```cpp
struct DecisionTrace {
    float    local_score;               // raw L0 anomaly score
    float    segment_trend;             // L1 segment anomaly trend
    float    anomaly_history;           // L2 EMA
    float    drift_score;               // L2 baseline drift
    float    retrieval_similarity_max;  // top retrieved record score
    bool     rule_matched;
    float    gate_score;                // multi-signal gate result
    bool     forced;                    // was reasoning forced?
    bool     skipped;                   // was reasoning skipped?
    float    fused_score;               // score fusion output
    float    corr_score;                // correlation engine contribution
    float    final_score;               // combined final score
    Decision base_decision;             // before overrides
    Decision final_decision;            // after all overrides
    std::string attack_class;
    std::string correlation_type;
    std::string campaign_id;
};
```

Access via `alert.trace` in any callback.

---

## 6. §4 — Concurrency & Sharding

**Files:** `ids_sharded.hpp` (new), `ids_types.hpp`, `ids.hpp`

### Models

| Model | Class | Use case |
|---|---|---|
| Single pipeline | `IDS` | Dev / low load — single `std::mutex`, no threads |
| Sharded pipeline | `ShardedIDS` | Production — N independent lanes, per-shard queues + threads |

### `ShardedIDS` — N independent pipeline instances

```cpp
#include "ids_sharded.hpp"

ids::IDSConfig cfg;
cfg.sharding.hash_key             = "ip";   // route by source IP
cfg.queue.queue_depth             = 4096;
cfg.backpressure.policy           = ids::BackpressurePolicy::Priority;
cfg.backpressure.priority_keep_above = 0.60f;
cfg.watchdog.heartbeat_interval_s = 1.0f;
cfg.watchdog.max_missed_beats     = 3;
cfg.watchdog.auto_restart         = true;

ids::ShardedIDS ids_sys(cfg, 8);   // 8 shards

ids_sys.on_alert([](const ids::Alert& a){ /* ... */ });
ids_sys.on_block([](const std::string& src){ /* ... */ });
ids_sys.start();

ids_sys.ingest(event);     // lock-free hash-route + enqueue
ids_sys.shutdown();        // drain + join all threads
```

### Architecture

Each shard owns, exclusively:
- One `IDS` pipeline instance (L0 → L1 → L2 → memory → retrieval → reasoning → correlation → decision)
- One `BoundedQueue` (bounded MPSC, lock-based)
- One `std::thread` worker (processes events sequentially — FIFO per entity)

Shared across shards (via broadcast on `add_rule` / `load_signature`):
- `RuleTable` — rules broadcast to all shards at add time
- Signature embeddings — loaded into each shard's `global_store`

### Consistent hash routing (§4.3/§4.4)

Same entity always routes to the same shard — guaranteed by consistent hash:

```cpp
// hash_key = "ip" | "session" | "user"
uint32_t shard = hash(ev.source) % n_shards;
```

This guarantees the SSM state ownership rule: **one entity → one thread → FIFO**. Violating this corrupts SSM state.

### Backpressure policies (§4.5)

| Policy | Behaviour |
|---|---|
| `Drop` | Drop new event if queue full, increment counter |
| `Priority` | Drop low-anomaly events first; high-anomaly events evict queue head |
| `Block` | Block caller until space available |
| `Sample` | Forward 1-in-N events when full |

`Priority` is recommended for production — it preferentially discards low-value traffic under load while preserving high-anomaly events.

### Per-shard stats (§9.9)

```cpp
for (const auto& ss : ids_sys.shard_stats()) {
    ss.shard_id         // shard index
    ss.queue_depth      // current queue occupancy
    ss.avg_latency_us   // EMA of per-event processing time
    ss.drops            // total events dropped by this shard's queue
    ss.active_states    // active L1 per-IP instances
    ss.reasoning_pool_saturated  // true if >80% events hit reasoning
}
```

### Aggregate metrics

```cpp
auto agg = ids_sys.aggregate_metrics();   // ShardedIDS::AggregateMetrics
agg.events_total      // sum across all shards
agg.alerts_total
agg.blocks_total
agg.faults_total
// ... all Metrics fields as plain uint64_t (copyable)
```

### §4.8 Shutdown sequence

```
1. Stop watchdog thread
2. Signal all workers: running = false
3. Close all queues (workers drain remaining items then exit)
4. Join all worker threads
```

Call `flush_pending()` before `save_all()` to ensure no in-flight segment state is lost.

### §9.13 / §4.8 State persistence

```cpp
// Save all shard states to directory
ids_sys.save_all("/var/ids/state");
// Writes: shard_0_state.bin, shard_0_config.json, shard_1_state.bin, ...

// Restore on startup — missing files start clean (non-fatal)
ids_sys.load_all("/var/ids/state");
```

### §5.9 Watchdog

```cpp
cfg.watchdog.heartbeat_interval_s = 1.0f;   // check every 1s
cfg.watchdog.max_missed_beats     = 3;       // restart after 3 missed beats
cfg.watchdog.auto_restart         = true;    // restart hung shards automatically
```

The watchdog monitors a heartbeat counter incremented by each worker on every loop tick. If a shard misses `max_missed_beats` consecutive heartbeats, its thread is joined and restarted. Shard state (held in `StateInstanceManager`) survives the restart — only the thread is replaced.

```cpp
ids_sys.watchdog_restarts()   // total shard restarts since start()
```

### Latency budget per stage (p99, single shard)

| Stage | Target |
|---|---|
| L0 (local analyzer) | < 5 µs |
| L1 (segment SSM) | < 10 µs |
| L2s/L2m (hierarchy) | < 10 µs |
| Memory write | < 5 µs |
| Retrieval | < 50 µs |
| Reasoning (gated, ~20% of events) | < 200 µs |
| Decision | < 5 µs |
| **Total (no reasoning)** | **< 85 µs** |
| **Total (with reasoning)** | **< 285 µs** |

---

## 7. §5 — Fault Handling & Recovery

**File:** `ids_ssm.hpp`, `ids_level0.hpp`, `ids.hpp`, `ids_types.hpp`

### Design principle: fail safe, not fail fast

The pipeline never crashes. All exceptions are caught at stage boundaries. Every fault is logged and counted. The system continues processing.

### Input validation

Every event is validated before entering L0:

```cpp
bool validate_event(const Event& ev) {
    if (ev.source.empty())                   return false;
    if (ev.type == EventType::Unknown)       return false;
    if (!std::isfinite(ev.payload.entropy))  return false;
    if (!std::isfinite(ev.payload.rate_hz))  return false;
    return true;
}
```

Invalid events are dropped and `health_.numeric_faults` is incremented.

### SSM numeric safety

After **every** `SSM::step()` call:

```
1. NaN/Inf check  → if any state element is non-finite: reset state, throw
2. Energy check   → if ||state||₂ > max_energy(100):
                    a. clamp all elements to [-clamp_limit, +clamp_limit]
                    b. recheck energy
                    c. if still > 2×max_energy: reset state, throw
```

`HierarchicalSSM::update()` wraps each layer's `step()` in `try/catch` — a bad layer is reset without affecting the other layers.

### Fault taxonomy

```cpp
enum class FaultType {
    Numeric,   // NaN, Inf, overflow in SSM state
    State,     // corrupted or saturated state instance
    Memory,    // VectorStore full, eviction failure
    Queue,     // shard queue overflow
    Thread,    // worker thread died
    Input,     // invalid or malformed event
    Config,    // bad configuration values
    Storage    // save/load failure
};
```

### Reasoning failure fallback

If reasoning throws, the pipeline falls back to a score estimate rather than dropping the event:

```cpp
// fallback if reasoning fails:
res.confidence = 0.5f * ls.anomaly_score + 0.5f * ss.anomaly_trend;
res.decision   = score_to_decision(res.confidence, thresholds_);
res.explanation= "[fault: reasoning failed, fallback score]";
```

### Panic mode

When `fault_count` exceeds `panic_threshold` (default 100) within any window:

```
- Reasoning disabled → rule engine only
- Memory writes disabled
- L0 + RuleTable still active → known attacks still detected
```

**v2 addition — panic auto-exit:** After `panic_window_s` (default 60s), the fault rate is re-sampled. If recent faults have dropped below `panic_threshold / 2`, panic mode exits automatically. This prevents the system from staying locked in degraded mode after a transient spike.

```cpp
cfg.panic.panic_threshold   = 100;
cfg.panic.panic_window_s    = 60.f;
cfg.panic.disable_reasoning = true;
cfg.panic.rules_only        = true;
```

### Health monitoring

```cpp
const HealthStats& h = pipeline.health();
h.numeric_faults.load()    // NaN/Inf faults in SSM
h.state_resets.load()      // state instance resets
h.reasoning_fails.load()   // reasoning exceptions
h.retrieval_fails.load()   // retrieval exceptions
h.panic_mode               // currently in panic mode?
```

---

## 8. §6 — Training & Parameter Update

**File:** `ids_types.hpp`, `ids_reasoning.hpp`

### Parameter categories

| Category | Update method | Hot reload |
|---|---|---|
| SSM matrices (`A_log`, `B_proj`, etc.) | Offline only | No — requires restart |
| Decision thresholds | Calibration | Yes — `ConfigHolder::update()` |
| Score fusion weights | Calibration | Yes |
| Routing config | Config file | Yes |
| Rules | Runtime | Yes — `RuleTable::add/remove/replace` |
| Signatures | Runtime | Yes — `load_signature()` |
| Baseline stats | Online EMA | Automatic |

### ModelParams — serialisable parameter blobs

```cpp
struct ModelParams {
    std::string version;
    std::string checksum;
    Time        trained_at;
    // L1 SSM parameter blobs (populated by load_model())
    std::vector<float> l1_A_log;
    std::vector<float> l1_B_proj;
    std::vector<float> l1_C_proj;
    std::vector<float> l1_D_skip;
    std::vector<float> l1_delta_proj;
    // L2 hierarchy layer blobs (one per layer)
    std::vector<std::vector<float>> l2_layer_blobs;
    bool is_valid() const { return !version.empty() && !l1_A_log.empty(); }
};
```

### Threshold calibration

`BaselineCalibrator` observes normal traffic and suggests calibrated thresholds:

```cpp
ids::BaselineCalibrator cal;

// During learning phase:
cal.observe(ls, ss);   // called for each event

// After observation period:
auto suggestion = cal.compute(0.01f);   // 1% false-positive target
// suggestion.gate_threshold, alert_threshold, block_threshold, etc.
```

### Learning mode

During initial deployment, use learning mode to collect baseline statistics without blocking traffic:

```cpp
cfg.learning.enabled          = true;
cfg.learning.disable_blocking = true;   // no Block/Escalate decisions
cfg.learning.log_only         = true;
cfg.learning.collect_baseline = true;
cfg.learning.duration_s       = 3600.f; // observe for 1 hour
```

---

## 9. §7 — Correlation & Campaign Tracking

**File:** `ids_correlation.hpp` (new), `ids_types.hpp`

### New component: `CorrelationEngine`

Position in pipeline:
```
Reasoning → Correlation → Decision
```

Receives `ReasoningResult + Event + GlobalState`, returns `CorrelationResult` which can boost the confidence score and upgrade the decision.

### Detection capabilities

**Repeat detection** — same source alerts N times within a short window:

```cpp
cfg.corr_limits;                        // max records per scope
// Fires when: alert_count[src] >= repeat_threshold(3)
//             within short_window_s(60s)
```

**Multi-stage attack detection** — ordered attack class sequence within a time window:

```cpp
// Built-in patterns:
AttackPattern lateral_movement {
    "LateralMovement",
    {"PortScan", "BruteForce/CredentialStuffing", "LateralMovement/Persistence"},
    600.f   // max gap between stages
};
AttackPattern apt_exfil {
    "APT-Exfiltration",
    {"BruteForce/CredentialStuffing", "FileSystemAnomaly/Ransomware",
     "EncryptedC2/Exfiltration"},
    3600.f
};
```

Add custom patterns:
```cpp
cfg.multi_stage.patterns.push_back({
    "CustomAttack", {"stage1_class", "stage2_class"}, 300.f
});
```

**Distributed attack detection** — N unique sources targeting the same host:

```cpp
cfg.distributed.unique_source_threshold = 5;    // DDoS: 5+ sources
cfg.distributed.dist_window_s           = 60.f;
```

**Slow attack detection** — low-score events accumulating over a long window (APT/slow-burn):

```cpp
cfg.slow_attack.slow_window_s        = 3600.f;  // 1 hour window
cfg.slow_attack.slow_event_threshold = 10;       // 10+ events
cfg.slow_attack.slow_score_threshold = 0.30f;    // each scoring ≥ 0.30
```

### Score contribution

```cpp
// Final score = reasoning_score + corr_weight * corr_score
// corr_score built from:
//   repeat_detected     → +0.20
//   multi_stage_detected → +0.30
//   distributed_detected → +0.25
//   slow_attack_detected → +0.15
//   campaign_active     → +0.10
```

### Campaign lifecycle

Active attacks are tracked as campaigns with full metadata:

```cpp
const auto& campaigns = pipeline.active_campaigns();
for (const auto& c : campaigns) {
    c.id           // "camp_0", "camp_1", etc.
    c.attack_class // "DoS/DDoS", "APT-Exfiltration", etc.
    c.sources      // all source IPs involved
    c.hosts        // all targeted hosts
    c.event_count  // total events attributed
    c.max_score    // highest confidence seen
    c.first_seen   // Time of first event
    c.last_seen    // Time of most recent event
    c.active       // false if idle for > campaign_idle_timeout_s(1800s)
}
```

Campaign ID flows into every `Alert.trace.campaign_id` — all alerts from the same campaign are linked.

---

## 10. §8 — Adaptive Baseline & Self-Tuning

**File:** `ids_adaptive.hpp` (new), `ids_types.hpp`

### Problem solved

Fixed thresholds calibrated for one traffic profile produce too many false positives or missed detections when traffic patterns change (time of day, network growth, seasonal variation).

### Per-scope baselines

Each entity type maintains an independent statistical baseline:

| Scope | EMA alpha | Adapts to |
|---|---|---|
| Global | 0.001 | Whole-network normal |
| Host | 0.005 | Per-destination traffic |
| User | 0.020 | Per-user behavior |
| IP | 0.050 | Per-source traffic pattern |

Scopes are independent. A noisy IP does not raise the global threshold.

### Freeze rule

Baseline updates are frozen when an anomaly exceeds the freeze threshold:

```cpp
// IP baseline freezes when: anomaly_score >= 0.70
// Global baseline freezes when: anomaly_history >= 0.70
// Prevents attack traffic from being learned as "normal"
```

Freeze is automatic and per-scope. It releases when the anomaly drops.

### Adaptive thresholds

Alert and block thresholds are derived from the baseline distribution:

```cpp
// alert_threshold = baseline_mean + k_alert(3.0) * baseline_std
// block_threshold = alert_threshold + k_block(5.0) * baseline_std
// gate_threshold  = baseline_mean + k_gate(2.0)  * baseline_std
// All clamped to [0.10, 0.95]
```

This means a noisy network automatically raises its own thresholds, while a quiet network keeps them low.

### AdaptationStats monitoring

```cpp
const auto& stats = pipeline.adaptive_.stats();
stats.baseline_updates.load()    // total baseline update calls
stats.baseline_freezes.load()    // total freeze events
stats.threshold_changes.load()   // threshold shift > 0.005
stats.gate_changes.load()        // gate shift > 0.005
stats.baseline_resets.load()     // manual/triggered resets
```

> If `threshold_changes` grows faster than `events_ingested / 100`, adaptation is unstable — consider freezing adaptation and logging a fault.

### Baseline inspection

```cpp
// Per-IP baseline
const auto& b = pipeline.baseline_for_ip("192.168.1.1");
b.avg_anomaly_score   // baseline anomaly level for this IP
b.avg_rate_hz         // baseline packet rate
b.avg_entropy         // baseline entropy
b.frozen              // currently frozen?

// Full scope variants also available:
adaptive_.baseline_for(key, MemoryScope::User);
adaptive_.baseline_for(key, MemoryScope::Host);
```

---

## 11. §9 — Telemetry & Observability

**File:** `ids_telemetry.hpp` (new), `ids.hpp`

### Core metrics

Atomic counters updated inline in the hot path — no locking, no allocation:

```cpp
const auto& m = pipeline.metrics();
m.events_total.load()       // total events ingested
m.events_per_sec.load()     // rolling 1s rate (approximate)
m.alerts_total.load()       // total Alert decisions
m.blocks_total.load()       // total Block decisions
m.escalations_total.load()  // total Escalate decisions
m.drops_total.load()        // events dropped (invalid or queue full)
m.reasoning_calls.load()    // reasoning invocations
m.forced_reasoning.load()   // reasoning forced past gate
m.memory_writes.load()      // total VectorStore writes
m.faults_total.load()       // total fault events
m.campaigns_active.load()   // active campaign count
```

### Stage latency tracking

EMA-based per-stage latency (no heap allocation in hot path):

```cpp
const auto lat = pipeline.latency_stats();
lat.l0_avg_us           // Level 0 average latency
lat.l1_avg_us           // Level 1 average latency
lat.reasoning_avg_us    // Reasoning average latency
lat.total_avg_us        // End-to-end average latency
lat.l0_p99_us           // L0 p99 (running max approximation)
lat.reasoning_p99_us    // Reasoning p99
lat.total_p99_us        // Total p99
```

### Drift time series

Captures `drift_score`, `anomaly_history`, and threshold values over time — exported as JSON for visualisation:

```cpp
std::ostringstream out;
exporter.export_drift_series(out);
// {"drift":0.08,"hist":0.23},{"drift":0.12,"hist":0.31},...
```

Sampled once per segment flush (not per event). Configurable ring size: `cfg.telemetry.drift_series_max = 10000`.

### Routing debug log

Captures every routing decision for debugging hierarchy behaviour:

```cpp
cfg.telemetry.routing_debug = true;   // disabled by default in production

auto entries = pipeline.routing_log(50);
// RoutingLogEntry: {time, RoutingEvent::Flush/Promote/Skip, key, from_level, to_level, reason}
```

Example entries:
```
FLUSH   L1     src=10.0.0.1  reason=count_exceeded(100)
PROMOTE L1→L2  src=10.0.0.1  reason=normal
SKIP    L1→L2  src=192.168.1.5  reason=low_anomaly
PROMOTE L1→L2  src=10.0.0.99   reason=force
```

### Fault log

```cpp
auto faults = pipeline.fault_log_entries(20);
for (const auto& f : faults) {
    f.type     // FaultType::Numeric, Memory, State, etc.
    f.key      // source IP or entity key
    f.detail   // human-readable description
    f.time
}
```

### MetricsSink — push metrics to external systems

```cpp
// Push metrics to Prometheus/InfluxDB/custom SIEM every 1 second:
exporter.set_sink([](const ids::Metrics& m) {
    prometheus_gauge("ids_events_total",  m.events_total.load());
    prometheus_gauge("ids_alerts_total",  m.alerts_total.load());
    prometheus_gauge("ids_faults_total",  m.faults_total.load());
}, 1.0f);   // interval in seconds

exporter.stop_sink();   // clean shutdown — joins background thread
```

### Config dump

```cpp
std::ostringstream out;
pipeline.dump_config(out);
// {"alert_threshold":0.55,"gate_threshold":0.35,"memory_write_gate":0.50,"panic_mode":false}
```

### Telemetry safety rules

| Rule | Implementation |
|---|---|
| No heap allocation in hot path | Pre-allocated ring buffers, atomic counters |
| No blocking I/O in hot path | MetricsSink runs on background thread |
| Counters are lock-free | `std::atomic::fetch_add` only |
| Latency tracking uses EMA | O(1) update, no vector growth |
| Routing log is optional | `routing_debug = false` by default |

---

## 12. Gap Analysis Resolution

All 8 gaps identified in the post-v2-review gap analysis have been resolved:

| Severity | File | Gap | Resolution |
|---|---|---|---|
| **High** | `ids_ssm.hpp` | L2s→L2m→L2l tick-only, not signal-driven | Each layer now evaluates `L2sToL2mPromotionRules` and `L2mToL2lPromotionRules` conditions (`mid_anomaly`, `mid_drift`, `global_drift`, `global_hist`) before stepping. Tick rates remain as time-based fallback floor. |
| **High** | `ids.hpp` | `write_on_block`/`write_on_escalate` never fired | Added step 8b: post-decision `retriever_.write()` call with the final resolved decision after `engine_.execute()` completes. Pre-decision write (step 5) uses `Decision::Ignore` for score-gating only. |
| **Medium** | `ids.hpp` | Panic mode never auto-exits | Added `panic_entry_time_` and `panic_entry_fault_count_` members. After `panic_window_s`, if recent faults < `panic_threshold / 2`, `panic_mode` resets and window resets. |
| **Medium** | `ids_correlation.hpp` | `repeat_threshold` hardcoded to `3` | `RepeatDetectionConfig` added as constructor parameter and stored member. `detect_repeat()` reads `repeat_cfg_.repeat_threshold` and `repeat_cfg_.repeat_window_s`. |
| **Medium** | `ids_adaptive.hpp` | User baseline never updated; `AdaptationStats` counters incomplete | `update()` now looks up `ev.metadata.at("user")` and maintains `user_baseline[user]` at `alpha=0.02`. `threshold_changes` and `gate_changes` increment on shifts > 0.005. Per-scope freeze tracking added. `baseline_for(StateKey, MemoryScope)` dispatcher implemented. |
| **Low** | `ids_memory.hpp` | Eviction missing TTL-first pass | `VectorStore::evict()` now runs TTL sweep (24h default) before score-based partial sort. Added `Retriever::cleanup(MemoryKey, CleanupReason)`. |
| **Low** | `ids_types.hpp` | `ModelParams` missing param fields; sharding types absent | `ModelParams` now carries `l1_A_log`/`l1_B_proj`/etc. and `l2_layer_blobs`. Added `ShardingConfig`, `BackpressurePolicy`, `BackpressureConfig`, `QueueConfig`, `WatchdogConfig`. |
| **Low** | `ids_telemetry.hpp` | `MetricsSink` + replay API absent | `set_sink(MetricsSink, float)` launches background `std::thread` pushing metrics at configured interval with clean `stop_sink()` join. `ReplayConfig`/`ReplayResult` structs added. |

---

## 13. Complete IDSConfig Reference

```cpp
ids::IDSConfig cfg;

// ── Core ──────────────────────────────────────────────────────
cfg.local_window = 64;           // L0 sliding window size

// ── §1 Routing ────────────────────────────────────────────────
cfg.routing.flush.flush_n              = 100;
cfg.routing.flush.flush_t              = 10.f;
cfg.routing.flush.flush_anomaly        = 0.70f;  // early flush on high anomaly
cfg.routing.flush.flush_on_type_change = true;
cfg.routing.promote_l1_l2s.promote_threshold = 0.50f;
cfg.routing.promote_l2s_l2m.mid_anomaly     = 0.55f;
cfg.routing.promote_l2s_l2m.mid_drift       = 3.0f;
cfg.routing.promote_l2m_l2l.global_drift    = 8.0f;
cfg.routing.promote_l2m_l2l.global_hist     = 0.70f;
cfg.routing.skip.skip_threshold        = 0.20f;
cfg.routing.skip.min_segments          = 3;
cfg.routing.force.force_anomaly        = 0.90f;
cfg.routing.force.force_on_block       = true;

// ── §2 Memory ─────────────────────────────────────────────────
cfg.write_policy.memory_write_gate     = 0.50f;
cfg.write_policy.memory_force_gate     = 0.85f;
cfg.write_policy.write_on_block        = true;
cfg.write_policy.write_on_escalate     = true;
cfg.retrieval_time.retrieval_max_age_s = 3600.f;
cfg.retrieval_time.recency_tau         = 600.f;
cfg.cleanup.record_ttl_s               = 86400.f;

// ── §3 Gate & decision ────────────────────────────────────────
cfg.gate.gate_threshold                = 0.35f;
cfg.gate.weights.w_local               = 0.35f;
cfg.gate.weights.w_segment             = 0.25f;
cfg.force_gate.force_on_rule_match     = true;
cfg.force_gate.force_local             = 0.90f;
cfg.skip_gate.skip_local_threshold     = 0.10f;
cfg.fusion.w_local                     = 0.50f;
cfg.fusion.w_segment                   = 0.25f;
cfg.thresholds.ignore_threshold        = 0.20f;
cfg.thresholds.log_threshold           = 0.40f;
cfg.thresholds.alert_threshold         = 0.60f;
cfg.thresholds.block_threshold         = 0.85f;
cfg.escalation.escalate_hist           = 0.75f;
cfg.escalation.repeat_escalate_n       = 3;
cfg.hysteresis.decision_hysteresis     = 0.05f;
cfg.cooldown.alert_cooldown_s          = 5.f;
cfg.policy.block_list                  = {"<bad-ip>"};
cfg.policy.allow_list                  = {"<trusted-ip>"};

// ── §5 Fault ──────────────────────────────────────────────────
cfg.panic.panic_threshold              = 100;
cfg.panic.panic_window_s               = 60.f;
cfg.state.max_energy                   = 100.f;
cfg.state.clamp_limit                  = 10.f;

// ── §6 Learning mode ─────────────────────────────────────────
cfg.learning.enabled                   = false;
cfg.learning.disable_blocking          = true;

// ── §7 Correlation ────────────────────────────────────────────
cfg.multi_stage.enabled                = true;
cfg.distributed.unique_source_threshold= 5;
cfg.slow_attack.slow_window_s          = 3600.f;

// ── §8 Adaptive ───────────────────────────────────────────────
cfg.adaptive_threshold.k_alert         = 3.0f;
cfg.adaptive_threshold.k_block         = 5.0f;
cfg.adapt_limits.threshold_min         = 0.10f;
cfg.adapt_limits.threshold_max         = 0.95f;

// ── §9 Telemetry ─────────────────────────────────────────────
cfg.telemetry.log_level                = ids::LogLevel::Info;
cfg.telemetry.routing_debug            = false;   // enable for debugging only
cfg.telemetry.latency_tracking         = true;
cfg.telemetry.drift_series             = true;
cfg.telemetry.drift_series_max         = 10000;
cfg.telemetry.fault_log_max            = 1000;
```

---

## 14. Full API Reference

### `IDS` class

```cpp
// Construction
IDS(const IDSConfig& cfg = IDSConfig{});

// Callbacks
void on_alert   (AlertCallback    cb);    // fires for LOG, ALERT, BLOCK, ESCALATE
void on_block   (BlockCallback    cb);    // fires for BLOCK (receives source string)
void on_escalate(EscalateCallback cb);    // fires for ESCALATE

// Ingest
PipelineState ingest(const Event& ev);              // thread-safe, returns current state
void ingest_batch(const std::vector<Event>& events);

// Rules & signatures
void add_rule(Rule r);
void load_signature(Vec embedding, const std::string& label, float score);

// State read (all thread-safe)
GlobalState  global_state()  const;
SegmentState segment_state() const;
size_t       memory_size()   const;

// Telemetry
const Metrics&                  metrics()             const;
const HealthStats&              health()              const;
StageLatency                    latency_stats()       const;
std::vector<RoutingLogEntry>    routing_log(n)        const;
std::vector<FaultRecord>        fault_log_entries(n)  const;
std::vector<CampaignState>      active_campaigns()    const;
const ScopeBaseline&            baseline_for_ip(ip)   const;

// Config & diagnostics
void dump_config(std::ostream& out) const;
void reset();
```

### `Alert` struct

```cpp
struct Alert {
    Decision      decision;       // final decision after all overrides
    float         confidence;     // final fused score [0,1]
    std::string   attack_class;   // e.g. "DoS/DDoS", "BruteForce/CredentialStuffing"
    std::string   explanation;    // human-readable diagnostic string
    std::string   source;         // originating IP or entity
    std::string   destination;    // target host or service
    EventType     event_type;
    Time          time;
    DecisionTrace trace;          // full score breakdown (see §3)
};
```

### Compile & link

```bash
# Header-only — no separate compilation step required
g++ -std=c++17 -O2 -Iinclude your_integration.cpp -o your_program

# With CMake:
add_library(ids INTERFACE)
target_include_directories(ids INTERFACE path/to/ids_v2/include)
target_link_libraries(your_target PRIVATE ids)
```

### Minimum integration

```cpp
#include "ids.hpp"

ids::IDSConfig cfg;
cfg.thresholds.alert_threshold = 0.55f;
cfg.policy.block_list          = {"known.bad.ip"};

ids::IDS pipeline(cfg);
pipeline.on_alert([](const ids::Alert& a) {
    std::cout << a.explanation << "\n";
});
pipeline.on_block([](const std::string& src) {
    // push to firewall / BPF / iptables
});

pipeline.ingest(event);   // call for every event — thread-safe
```

---

*IDS v2 — All 8 gap analysis items resolved. Zero faults in demo run across 195 events, 5 attack phases.*
