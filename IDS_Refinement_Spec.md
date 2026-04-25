# IDS Refinement Specification
## Control Rules, Stability, and Production Readiness

> Applies to: `ids_ssm.hpp`, `ids_memory.hpp`, `ids_level0.hpp`, `ids_level1.hpp`,
> `ids_reasoning.hpp`, `ids_decision.hpp`, `ids.hpp`, `ids_types.hpp`

---

## Table of Contents

1. [Hierarchy Routing Policy](#1-hierarchy-routing-policy)
2. [Memory Partition & Retrieval Policy](#2-memory-partition--retrieval-policy)
3. [Reasoning Gate & Decision Policy](#3-reasoning-gate--decision-policy)
4. [Concurrency & Pipeline Execution Model](#4-concurrency--pipeline-execution-model)
5. [Fault Handling & Recovery Policy](#5-fault-handling--recovery-policy)
6. [Training / Parameter Update / Adaptation Policy](#6-training--parameter-update--adaptation-policy)
7. [Attack Correlation & Campaign Tracking Layer](#7-attack-correlation--campaign-tracking-layer)
8. [Adaptive Baseline & Self-Tuning Layer](#8-adaptive-baseline--self-tuning-layer)
9. [Telemetry / Visualization / Debug Layer](#9-telemetry--visualization--debug-layer)
10. [Summary — Required Changes per File](#10-summary--required-changes-per-file)

---

## 1. Hierarchy Routing Policy

### 1.1 Problem

Current `HierarchicalSSM` promotes state on fixed tick counters only:
`tick_rates = {1, 10, 60, 600}`. This is insufficient for IDS because
events are not uniform — a burst attack needs fast promotion while idle
traffic should not pollute higher levels at all.

Routing must be conditional on signals, not just time.

This section defines: `RoutingConfig`, `FlushRules`, `PromotionRules`,
`SkipRules`, `SplitRules`, `MergeRules`, `ForceRules`, and the fixed
routing order.

### 1.2 Routing Inputs

All routing decisions consume signals already available in the pipeline:

| Signal                      | Source                  |
|-----------------------------|-------------------------|
| `local.anomaly_score`       | `LocalState`            |
| `segment.anomaly_trend`     | `SegmentState`          |
| `segment.rate_mean`         | `SegmentState`          |
| `segment.error_freq`        | `SegmentState`          |
| `global.drift_score`        | `GlobalState`           |
| `global.anomaly_history`    | `GlobalState`           |
| `event.type`                | `Event`                 |
| `event.source`              | `Event`                 |
| `event.metadata["session"]` | `Event`                 |
| `time_since_last_update`    | `StateMeta`             |

No new signals are required. Routing is a pure function of existing state.

### 1.3 Level Definitions

```
L0 (Local)   → stateless sliding window, per-event
L1 (Segment) → keyed by ip / session
L2s (Short)  → keyed by ip
L2m (Mid)    → keyed by host
L2l (Long)   → global singleton

Flow: L0 → L1 → L2s → L2m → L2l
      (but not always — routing decides)
```

### 1.4 FlushRules — L1 segment flush

`SegmentSSM` flushes its accumulated window into a `SegmentState` when
**any** of these conditions is true:

| Condition                               | Config key             | Default |
|-----------------------------------------|------------------------|---------|
| event count >= N                        | `flush_n`              | 100     |
| wall time since last flush >= T seconds | `flush_t`              | 10.0 s  |
| `anomaly_trend > flush_anomaly`         | `flush_anomaly`        | 0.70    |
| session-end event received              | always                 | —       |
| dominant event type changed             | `flush_on_type_change` | true    |

```cpp
struct FlushRules {
    size_t flush_n              = 100;
    float  flush_t              = 10.f;
    float  flush_anomaly        = 0.70f;
    bool   flush_on_session_end = true;
    bool   flush_on_type_change = true;
};
```

Early flush on high anomaly ensures attacks are not buffered for 100 events
before the segment reaches L2s.

### 1.5 PromotionRules — L1 → L2s

Promote a flushed `SegmentState` into `L2s[key.ip]` when **any** of:

| Condition                               | Config key          | Default |
|-----------------------------------------|---------------------|---------|
| segment was flushed (always promote)    | `promote_on_flush`  | true    |
| `anomaly_trend > promote_threshold`     | `promote_threshold` | 0.50    |
| wall time since last L2s update >= T    | `promote_time`      | 30.0 s  |

```cpp
struct L1ToL2sPromotionRules {
    bool  promote_on_flush   = true;
    float promote_threshold  = 0.50f;
    float promote_time       = 30.f;
};
```

When `promote_on_flush = true` every flush promotes. Set to `false` to
gate promotion on anomaly or time only (lower-noise environments).

### 1.6 PromotionRules — L2s → L2m

Mid-level updates slower. Promote `L2s` state into `L2m[key.host]` when
**any** of:

| Condition                               | Config key      | Default |
|-----------------------------------------|-----------------|---------|
| segment count since last L2m update >= K| `mid_tick`      | 10      |
| `anomaly_history > mid_anomaly`         | `mid_anomaly`   | 0.55    |
| `drift_score > mid_drift`               | `mid_drift`     | 3.0     |
| session-end event received              | always          | —       |

```cpp
struct L2sToL2mPromotionRules {
    uint32_t mid_tick    = 10;
    float    mid_anomaly = 0.55f;
    float    mid_drift   = 3.0f;
    bool     promote_on_session_end = true;
};
```

### 1.7 PromotionRules — L2m → L2l

Global state should only reflect sustained, long-term anomalies.
Promote `L2m` into `L2l[global]` when **any** of:

| Condition                               | Config key     | Default |
|-----------------------------------------|----------------|---------|
| segment count since last L2l update >= K| `global_tick`  | 60      |
| `drift_score > global_drift`            | `global_drift` | 8.0     |
| `anomaly_history > global_hist`         | `global_hist`  | 0.70    |
| force-promotion flag set (see §1.11)    | `force_global` | false   |

```cpp
struct L2mToL2lPromotionRules {
    uint32_t global_tick  = 60;
    float    global_drift = 8.0f;
    float    global_hist  = 0.70f;
};
```

### 1.8 SkipRules

Promotion must be **skipped** to prevent noise from reaching higher levels.

Skip L1 → L2s when **all** of:
- `anomaly_trend < skip_threshold`
- `segment_count < min_segments` (state not yet stable)

Skip L2s → L2m when **all** of:
- `anomaly_history < skip_threshold`
- `drift_score < skip_drift`

Skip L2m → L2l when **all** of:
- `anomaly_history < global_hist` (see §1.7)
- `drift_score < global_drift`
- no force flag

```cpp
struct SkipRules {
    float    skip_threshold  = 0.20f;
    float    skip_drift      = 1.0f;
    uint32_t min_segments    = 3;
};
```

### 1.9 SplitRules

A new state instance must be created (not reused) when the entity context
changes. This prevents state mixing between entities.

Split (create new instance) when:

| Trigger                        | New key created for          |
|--------------------------------|------------------------------|
| new IP seen for first time     | `L1[ip]`, `L2s[ip]`          |
| new session ID in event        | `L1[session]`                |
| new user in event metadata     | `L1[user]`                   |
| new process ID                 | `L1[process]`                |
| protocol change on same IP     | optional — config flag        |

New instances always start from zero state. No state is copied from
another entity on creation.

```cpp
struct SplitRules {
    bool split_on_new_ip       = true;
    bool split_on_new_session  = true;
    bool split_on_new_user     = true;
    bool split_on_proto_change = false;
};
```

### 1.10 MergeRules

Merging is optional and must be explicit. No automatic merge.

```cpp
struct MergeRules {
    bool  enable_merge             = false;
    float merge_similarity         = 0.90f;
    bool  merge_same_host_ips      = false;
    bool  merge_same_user_sessions = false;
};
```

When `enable_merge = false` (default), this block is a no-op.
Merging is reserved for future campaign correlation (see §7).

### 1.11 ForceRules — emergency global promotion

Critical events must bypass tick counters and promote to all levels
immediately.

Force full promotion when **any** of:

| Condition                              | Config key            | Default |
|----------------------------------------|-----------------------|---------|
| `local.anomaly_score > force_anomaly`  | `force_anomaly`       | 0.90    |
| decision == Block or Escalate          | `force_on_block`      | true    |
| rule matched with `action == Block`    | `force_on_rule_block` | true    |
| manual policy flag set                 | `force_global`        | false   |

```cpp
struct ForceRules {
    float force_anomaly       = 0.90f;
    bool  force_on_block      = true;
    bool  force_on_rule_block = true;
    bool  force_global        = false;
};

bool should_force_promote(const LocalState& ls,
                          const ReasoningResult& res,
                          const RetrievedContext& ctx,
                          const ForceRules& cfg) {
    if (ls.anomaly_score > cfg.force_anomaly)                         return true;
    if (cfg.force_on_block && res.decision == Decision::Block)        return true;
    if (cfg.force_on_block && res.decision == Decision::Escalate)     return true;
    if (cfg.force_on_rule_block && !ctx.matched_rules.empty())        return true;
    if (cfg.force_global)                                             return true;
    return false;
}
```

When force promotion fires, all levels are updated in the same tick
regardless of their tick counters.

### 1.12 RoutingConfig — unified struct

```cpp
struct RoutingConfig {
    FlushRules              flush;
    L1ToL2sPromotionRules   promote_l1_l2s;
    L2sToL2mPromotionRules  promote_l2s_l2m;
    L2mToL2lPromotionRules  promote_l2m_l2l;
    SkipRules               skip;
    SplitRules              split;
    MergeRules              merge;
    ForceRules              force;
};
```

Add to `IDSConfig`:
```cpp
struct IDSConfig {
    // ... existing fields ...
    RoutingConfig routing = {};
};
```

### 1.13 Fixed Routing Order

The routing order is fixed and must not be changed:

```
1.  L0 update (always)
2.  L1[key.ip] update
3.  Check FlushRules → if flush: produce SegmentState
4.  If SegmentState produced:
    a. Check SkipRules (L1→L2s)
    b. If not skipped OR force: L2s[key.ip] update
    c. Check PromotionRules (L2s→L2m)
    d. If promote OR force: L2m[key.host] update
    e. Check PromotionRules (L2m→L2l)
    f. If promote OR force: L2l[global] update
5.  Memory write (gated by WritePolicy — see §2.4)
6.  Scoped retrieval (see §2.7)
7.  MultiSignalGate check → reasoning (see §3.3)
8.  Decision + escalation (see §3.8–3.9)
```

Steps 4b–4f are skipped entirely if no `SegmentState` was produced in
step 3. Force promotion (§1.11) overrides skip at every level.

### 1.14 Why Routing Policy Is Critical

| Without routing policy           | With routing policy                    |
|----------------------------------|----------------------------------------|
| hierarchy = fixed timers only    | hierarchy = conditional, signal-driven |
| global state polluted by noise   | global state reflects real threats     |
| burst attack detected slowly     | burst attack promotes immediately      |
| idle traffic fills global state  | idle traffic skipped at L2m/L2l        |
| unrelated IPs share state        | each IP has isolated state             |
| drift score meaningless          | drift score reflects true baseline shift|

---

## 2. Memory Partition & Retrieval Policy

> This section defines the full operational rules for write policy,
> scope selection, eviction, retrieval priority, time decay, and cleanup.

### 2.1 Problem

Current `Retriever` in `ids_memory.hpp` searches one global `vector_db`
and one global `log_db`. All events share the same memory regardless of
source IP, user, or session.

Consequences:
- IP A's anomaly history contaminates IP B's retrieval context
- Old attack records from expired sessions affect new session decisions
- High-volume noise sources crowd out low-volume attack signals
- Retrieval accuracy degrades as memory grows

### 2.2 MemoryScope and MemoryKey

```cpp
enum class MemoryScope {
    Global,
    Host,
    User,
    IP,
    Session,
    Process
};
```

Every stored record must carry a key identifying its origin:

```cpp
struct MemoryKey {
    std::string  host;
    std::string  user;
    std::string  ip;
    std::string  session;
    std::string  process;
    MemoryScope  scope;
};
```

Key is derived from the event at write time:

```cpp
MemoryKey key_from_event(const Event& ev, MemoryScope scope) {
    return {
        .host    = ev.destination,
        .user    = ev.metadata.count("user")    ? ev.metadata.at("user")    : "",
        .ip      = ev.source,
        .session = ev.metadata.count("session") ? ev.metadata.at("session") : "",
        .process = ev.metadata.count("proc")    ? ev.metadata.at("proc")    : "",
        .scope   = scope
    };
}
```

### 2.3 Partitioned MemoryStore

Full structure (replaces `ExternalMemory`):

```cpp
struct MemoryStore {
    VectorStore global_store;

    std::unordered_map<std::string, VectorStore> host_store;
    std::unordered_map<std::string, VectorStore> user_store;
    std::unordered_map<std::string, VectorStore> ip_store;
    std::unordered_map<std::string, VectorStore> session_store;
    std::unordered_map<std::string, VectorStore> process_store;

    RuleTable rules;
};
```

Each `VectorStore` instance is independent with its own size limit and
eviction state.

### 2.4 WritePolicy

Not every event should be stored. Write is gated.

```cpp
struct WritePolicy {
    float  memory_write_gate      = 0.50f;
    float  memory_force_gate      = 0.85f;
    bool   write_on_rule_match    = true;
    bool   write_on_block         = true;
    bool   write_on_escalate      = true;
    bool   write_on_high_drift    = false;
    float  drift_write_threshold  = 5.0f;
};

bool should_write(float anomaly_score, float drift,
                  const RetrievedContext& ctx,
                  Decision decision,
                  const WritePolicy& pol) {
    if (anomaly_score >= pol.memory_force_gate)                        return true;
    if (anomaly_score >= pol.memory_write_gate)                        return true;
    if (pol.write_on_rule_match && !ctx.matched_rules.empty())         return true;
    if (pol.write_on_block     && decision == Decision::Block)         return true;
    if (pol.write_on_escalate  && decision == Decision::Escalate)      return true;
    if (pol.write_on_high_drift && drift >= pol.drift_write_threshold) return true;
    return false;
}
```

### 2.5 Scope Selection on Write

When writing, store to multiple scopes based on severity:

```cpp
void write_record(MemoryStore& mem, const MemoryRecord& rec,
                  const MemoryKey& key, float anomaly_score,
                  const WritePolicy& pol) {
    mem.ip_store[key.ip].insert(rec);
    if (!key.user.empty())
        mem.user_store[key.user].insert(rec);
    if (anomaly_score >= 0.50f && !key.host.empty())
        mem.host_store[key.host].insert(rec);
    if (anomaly_score >= pol.memory_force_gate)
        mem.global_store.insert(rec);
    if (!key.session.empty())
        mem.session_store[key.session].insert(rec);
    if (!key.process.empty())
        mem.process_store[key.process].insert(rec);
}
```

This keeps memory local by default and only promotes to global for
confirmed high-severity events.

### 2.6 EvictionPolicy

Each partition has its own `max_size`. Eviction is score-based, not
pure FIFO.

```cpp
struct EvictionConfig {
    size_t max_global_records  = 100'000;
    size_t max_host_records    =  10'000;
    size_t max_ip_records      =   5'000;
    size_t max_user_records    =   5'000;
    size_t max_session_records =   1'000;
    size_t max_process_records =   1'000;
};
```

Eviction order when a partition is full:
1. Records with `age > ttl` (expired)
2. Records with lowest `anomaly_score`
3. Oldest by insertion order (tie-break)

This preserves high-value attack records over stale noise.

### 2.7 Retrieval Scope Order

Retrieval always searches narrow scopes first, then broadens:

```
1. ip_store[ev.source]              ← most specific
2. user_store[ev.metadata.user]
3. session_store[ev.metadata.session]
4. host_store[ev.destination]
5. global_store                     ← least specific
```

Per-scope `top_k` limits:

| Scope   | top_k |
|---------|-------|
| ip      | 3     |
| user    | 2     |
| session | 2     |
| host    | 2     |
| global  | 1     |

Total context records: max 10, matching `kTopKRetrieval + 2`.
Keeps the reasoning attention window bounded.

### 2.8 Time Filtering and Decay

Records older than `retrieval_max_age_s` are excluded from results.
Within the window, recency is weighted by exponential decay:

```cpp
float recency_factor(float age_s, float tau) {
    return expf(-age_s / tau);
}
```

Config:

```cpp
struct RetrievalTimeConfig {
    float retrieval_max_age_s = 3600.f;  // hard cutoff: 1 hour
    float recency_tau         = 600.f;   // half-life: ~10 min
};
```

### 2.9 Priority Weighting

Final retrieval score combines similarity, anomaly value, recency, and
scope weight:

```
final_score = sim * w_sim
            + record.score * w_anomaly
            + recency_factor(age) * w_time
            + scope_weight
```

Default weights:

```cpp
struct RetrievalWeights {
    float w_sim     = 0.50f;
    float w_anomaly = 0.30f;
    float w_time    = 0.20f;
};
```

Scope weights (additive bonus):

| Scope   | scope_weight |
|---------|-------------|
| ip      | 1.00        |
| user    | 0.90        |
| session | 0.85        |
| host    | 0.70        |
| global  | 0.50        |

### 2.10 Merge and Deduplication

After collecting results from all scopes:

```cpp
RetrievedContext merge_results(
    std::vector<ScopedRecord>& candidates,
    size_t max_context,
    const RetrievalWeights& w)
{
    // 1. Deduplicate by record id
    // 2. Sort by final_score descending
    // 3. Take top max_context records
    // 4. Collect matched_rules from all scopes
}
```

`max_context = 8` (matches `kTopKRetrieval`). Fixed upper bound ensures
reasoning attention is never unbounded.

### 2.11 Force Retrieval

In some cases retrieval must happen even if anomaly score is below the
reasoning gate:

| Trigger                          | Action                          |
|----------------------------------|---------------------------------|
| rule matched                     | force retrieve from all scopes  |
| `drift_score > drift_threshold`  | force retrieve from global      |
| decision == Block or Escalate    | force retrieve from global      |
| policy flag `force_retrieve`     | force retrieve from all scopes  |

```cpp
struct ForceRetrievalConfig {
    bool  force_on_rule_match   = true;
    bool  force_on_block        = true;
    float drift_force_threshold = 5.0f;
    bool  force_retrieve        = false;
};
```

Force retrieval feeds the reasoning model with global context even when
local anomaly score is low — important for APT and slow-burn attacks.

### 2.12 Memory Cleanup Rules

| Trigger                        | Action                                      |
|--------------------------------|---------------------------------------------|
| `record.age > record_ttl`      | delete record from all stores               |
| session ended                  | delete `session_store[session_id]`          |
| state instance expired (§1.8)  | delete `ip_store[ip]` if no active state    |
| host removed from inventory    | delete `host_store[host]`                   |
| manual flush                   | delete all records for a given `MemoryKey`  |

```cpp
struct MemoryCleanupConfig {
    float record_ttl_s           = 86400.f;  // 24 hours
    bool  cleanup_on_session_end = true;
    bool  cleanup_on_state_expire= true;
};
```

Cleanup runs as a background sweep, not inline with `ingest()`.

### 2.13 Complete Retrieval Flow

```
event
  ↓ build MemoryKey from event
  ↓ check ForceRetrievalConfig
  ↓ search ip_store[key.ip]           → top_k=3
  ↓ search user_store[key.user]       → top_k=2
  ↓ search session_store[key.session] → top_k=2
  ↓ search host_store[key.host]       → top_k=2
  ↓ search global_store               → top_k=1
  ↓ apply time filter (age > max_age → discard)
  ↓ compute final_score per record
  ↓ deduplicate by id
  ↓ sort by final_score
  ↓ take top max_context=8
  ↓ collect matched_rules
  ↓ return RetrievedContext → reasoning
```

### 2.14 Updated Retriever Interface

```cpp
class Retriever {
public:
    explicit Retriever(MemoryStore& mem,
                       RetrievalTimeConfig  time_cfg  = {},
                       RetrievalWeights     weights   = {},
                       ForceRetrievalConfig force_cfg = {});

    RetrievedContext retrieve(const LocalState&   ls,
                              const SegmentState& ss,
                              const GlobalState&  gs,
                              const Event&        ev) const;

    void write(const LocalState& ls, const Event& ev,
               float anomaly_score, Decision decision,
               const RetrievedContext& ctx,
               const WritePolicy& pol);

    void cleanup(const MemoryKey& key, CleanupReason reason);
    void sweep(float now_s, const MemoryCleanupConfig& cfg);

private:
    MemoryStore&         mem_;
    RetrievalTimeConfig  time_cfg_;
    RetrievalWeights     weights_;
    ForceRetrievalConfig force_cfg_;
};
```

---

## 3. Reasoning Gate & Decision Policy

> This section defines the complete, configurable policy layer: weighted
> multi-signal gate, forced/skip rules, score fusion, decision thresholds,
> override order, hysteresis, cooldown, and the fixed decision flow.

### 3.1 Problem

Current `ids.hpp` gates reasoning with a single float:
```cpp
if (ls.anomaly_score >= cfg_.reasoning_gate) { ... }
```

Current `ids_reasoning.hpp` fuses scores with hardcoded weights:
```cpp
float combined = 0.50f * ls.anomaly_score
               + 0.25f * ss.anomaly_trend
               + 0.15f * gs.anomaly_history
               + 0.10f * clamp(gs.drift_score / 10.f, 0.f, 1.f);
```

Current `ids_decision.hpp` escalates on one condition only:
```cpp
if (gs.anomaly_history >= policy_.escalate_hist_threshold && ...)
```

None of these are sufficient for production IDS.

### 3.2 Signals Available for Gating

All signals are already present in the pipeline — no new data is needed:

| Signal                    | Source              | Range   |
|---------------------------|---------------------|---------|
| `local.anomaly_score`     | `LocalState`        | 0–1     |
| `segment.anomaly_trend`   | `SegmentState`      | 0–1     |
| `segment.rate_mean`       | `SegmentState`      | 0–∞     |
| `global.anomaly_history`  | `GlobalState`       | 0–1     |
| `global.drift_score`      | `GlobalState`       | 0–∞     |
| `retrieval.similarity_max`| `RetrievedContext`  | 0–1     |
| `rule.matched`            | `RetrievedContext`  | bool    |
| `repeat_count`            | `RepeatTracker`     | 0–∞     |
| `time_since_last_alert`   | `RepeatTracker`     | seconds |

### 3.3 Multi-Signal Gate

Replace the single-float gate with a weighted gate score:

```cpp
struct GateWeights {
    float w_local     = 0.35f;
    float w_segment   = 0.25f;
    float w_history   = 0.15f;
    float w_drift     = 0.10f;   // normalized: drift / 10.f
    float w_retrieval = 0.10f;
    float w_rule      = 0.05f;   // 1.0 if any rule matched, else 0
};

struct ReasoningGateConfig {
    float       gate_threshold = 0.35f;
    GateWeights weights        = {};
};

float compute_gate_score(const LocalState&       ls,
                         const SegmentState&     ss,
                         const GlobalState&      gs,
                         const RetrievedContext& ctx,
                         float                   similarity_max,
                         const GateWeights&      w) {
    float rule_signal = ctx.matched_rules.empty() ? 0.f : 1.f;
    float drift_norm  = std::clamp(gs.drift_score / 10.f, 0.f, 1.f);
    return w.w_local     * ls.anomaly_score
         + w.w_segment   * ss.anomaly_trend
         + w.w_history   * gs.anomaly_history
         + w.w_drift     * drift_norm
         + w.w_retrieval * similarity_max
         + w.w_rule      * rule_signal;
}
```

### 3.4 Forced Reasoning Rules

Reasoning must run regardless of gate score when:

| Condition                                    | Config key             | Default |
|----------------------------------------------|------------------------|---------|
| any rule matched                             | `force_on_rule_match`  | true    |
| source on block list                         | `force_on_block_list`  | true    |
| `drift_score > force_drift`                  | `force_drift`          | 6.0     |
| `anomaly_history > force_history`            | `force_history`        | 0.70    |
| `local.anomaly_score > force_local`          | `force_local`          | 0.90    |
| manual policy flag                           | `force_reasoning`      | false   |

```cpp
struct ForcedReasoningConfig {
    bool  force_on_rule_match = true;
    bool  force_on_block_list = true;
    float force_drift         = 6.0f;
    float force_history       = 0.70f;
    float force_local         = 0.90f;
    bool  force_reasoning     = false;
};
```

### 3.5 Skip Rules

Skip reasoning to reduce cost when the event is clearly benign:

```cpp
struct SkipReasoningConfig {
    float skip_local_threshold = 0.10f;
    bool  skip_on_allow_list   = true;
    bool  skip_when_idle       = false;
};

bool should_skip_reason(const LocalState& ls,
                        const RetrievedContext& ctx,
                        bool on_allow_list,
                        const SkipReasoningConfig& cfg) {
    if (cfg.skip_on_allow_list && on_allow_list) return true;
    if (ls.anomaly_score < cfg.skip_local_threshold
        && ctx.matched_rules.empty())            return true;
    return false;
}
```

Priority order: `force > skip > gate`.

### 3.6 Reasoning Input Set

The reasoning model receives a fixed-size token set:

| Token                          | Source                          |
|--------------------------------|---------------------------------|
| current event embedding        | `LocalState.embedding`          |
| segment state vector           | `SegmentState.state_vector`     |
| L2s state (short-term)         | `GlobalState.level_states[0]`   |
| L2l state (long-term)          | `GlobalState.level_states[3]`   |
| retrieved records (up to 8)    | `RetrievedContext.records`      |

```cpp
constexpr size_t kMaxReasoningTokens = 12;  // 4 fixed + 8 retrieved
```

If `ctx.records.size() > 8`, truncate to top-8 by `final_score` before
passing to `ReasoningModel::reason()`.

### 3.7 Score Fusion

Replace hardcoded weights in `ReasoningModel` with configurable fusion:

```cpp
struct ScoreFusionWeights {
    float w_local     = 0.50f;
    float w_segment   = 0.25f;
    float w_history   = 0.15f;
    float w_drift     = 0.10f;
    float w_retrieval = 0.15f;
    float w_rule      = 0.10f;
};

float fuse_score(const LocalState& ls, const SegmentState& ss,
                 const GlobalState& gs, const RetrievedContext& ctx,
                 const ScoreFusionWeights& w) {
    float retrieval_boost = 0.f;
    for (const auto& r : ctx.records)
        if (r.score > 0.8f) retrieval_boost = std::max(retrieval_boost, w.w_retrieval);

    float rule_boost = ctx.matched_rules.empty() ? 0.f : w.w_rule;

    float score = w.w_local   * ls.anomaly_score
                + w.w_segment * ss.anomaly_trend
                + w.w_history * gs.anomaly_history
                + w.w_drift   * std::clamp(gs.drift_score / 10.f, 0.f, 1.f)
                + retrieval_boost
                + rule_boost;

    return std::clamp(score, 0.f, 1.f);
}
```

### 3.8 Decision Thresholds

```cpp
struct DecisionThresholds {
    float ignore_threshold = 0.20f;
    float log_threshold    = 0.40f;
    float alert_threshold  = 0.60f;
    float block_threshold  = 0.85f;
};

Decision score_to_decision(float score, const DecisionThresholds& t) {
    if (score < t.ignore_threshold) return Decision::Ignore;
    if (score < t.log_threshold)    return Decision::Log;
    if (score < t.alert_threshold)  return Decision::Alert;
    return Decision::Block;  // Escalate applied separately (§3.9)
}
```

| Score range | Decision  |
|-------------|-----------|
| < 0.20      | Ignore    |
| 0.20–0.40   | Log       |
| 0.40–0.60   | Alert     |
| 0.60–0.85   | Block     |
| ≥ 0.85      | Block → Escalate if escalation conditions met |

### 3.9 Escalation Rules

Escalation is a post-decision upgrade. Upgrade `Alert` or `Block` to
`Escalate` when **any** of:

| Condition                                      | Config key             | Default |
|------------------------------------------------|------------------------|---------|
| `anomaly_history >= escalate_hist`             | `escalate_hist`        | 0.75    |
| `drift_score >= escalate_drift`                | `escalate_drift`       | 8.0     |
| same source alerted N times in window          | `repeat_escalate_n`    | 3       |
| same attack class on M hosts in window         | `multi_host_threshold` | 3       |
| rule with `action == Escalate` matched         | always                 | —       |

```cpp
struct EscalationConfig {
    float    escalate_hist        = 0.75f;
    float    escalate_drift       = 8.0f;
    uint32_t repeat_escalate_n    = 3;
    float    repeat_window_s      = 300.f;
    uint32_t multi_host_threshold = 3;
    float    campaign_window_s    = 600.f;
};
```

### 3.10 Repeat Detection

```cpp
struct RepeatTracker {
    std::unordered_map<std::string, uint32_t> alert_count;
    std::unordered_map<std::string, Time>     first_alert;
    std::unordered_map<std::string, Time>     last_alert;

    void record(const std::string& source);
    bool should_escalate(const std::string& source,
                         const EscalationConfig& cfg) const;
    void expire(float now_s, float window_s);
};
```

### 3.11 Override Rules

Policy overrides must be applied in a fixed, deterministic order:

```
1. allow_list match  → Decision::Ignore  (hard stop)
2. block_list match  → Decision::Block   (hard override)
3. ML score_to_decision()
4. escalation check  (may upgrade to Escalate)
5. repeat detection  (may upgrade to Escalate)
6. manual override flag (force any decision)
```

```cpp
Decision apply_overrides(Decision ml_decision,
                         const Event& ev,
                         const GlobalState& gs,
                         const RepeatTracker& tracker,
                         const DecisionPolicy& policy,
                         const EscalationConfig& esc_cfg) {
    for (const auto& a : policy.allow_list)
        if (ev.source.find(a) != std::string::npos) return Decision::Ignore;
    for (const auto& b : policy.block_list)
        if (ev.source.find(b) != std::string::npos) return Decision::Block;

    Decision d = ml_decision;
    if (d == Decision::Alert || d == Decision::Block) {
        if (gs.anomaly_history >= esc_cfg.escalate_hist)  d = Decision::Escalate;
        if (gs.drift_score     >= esc_cfg.escalate_drift) d = Decision::Escalate;
        if (tracker.should_escalate(ev.source, esc_cfg))  d = Decision::Escalate;
    }
    return d;
}
```

### 3.12 Decision Stability — Hysteresis

```cpp
struct HysteresisConfig {
    float decision_hysteresis  = 0.05f;
    float decision_hold_time_s = 10.f;
};
```

If the last decision for a source was `Block` and the new score is
`block_threshold - hysteresis`, keep `Block` until `hold_time_s` elapses.

### 3.13 Cooldown Rules

```cpp
struct CooldownConfig {
    float alert_cooldown_s = 5.f;
    float block_cooldown_s = 30.f;
    bool  allow_stronger   = true;
};
```

`allow_stronger = true` means a `Block` always fires even during an
`Alert` cooldown window.

### 3.14 Fixed Decision Flow

```
1.  Compute gate_score (§3.3)
2.  Check should_skip_reason() → if true AND not forced: return Ignore
3.  Check should_force_reason() OR gate_score >= threshold → run reasoning
4.  Truncate ctx.records to top-8 by final_score
5.  fuse_score() → combined [0,1]
6.  score_to_decision() → base Decision
7.  apply_overrides() → allow/block list, escalation, repeat detection
8.  apply_hysteresis() → stability check
9.  apply_cooldown() → suppress if too recent
10. emit decision via callbacks
```

Steps 2–10 are skipped entirely for `Decision::Ignore` from step 2.
Steps 7–9 always run after step 6 regardless of score.

### 3.15 Config Structs Summary

All new config structs to add to `IDSConfig`:

```cpp
struct IDSConfig {
    // ... existing ...
    ReasoningGateConfig    gate        = {};
    ForcedReasoningConfig  force_gate  = {};
    SkipReasoningConfig    skip_gate   = {};
    ScoreFusionWeights     fusion      = {};
    DecisionThresholds     thresholds  = {};
    EscalationConfig       escalation  = {};
    HysteresisConfig       hysteresis  = {};
    CooldownConfig         cooldown    = {};
};
```

---

## 4. Concurrency & Pipeline Execution Model

> This section defines the full operational spec: sharded pipeline
> topology, state ownership, queue policy, backpressure, lock rules,
> latency budget, monitoring, and safe shutdown.

### 4.1 Problem

Current `IDS::ingest()` holds one global `std::mutex mu_` for the entire
pipeline. Every event from every source serializes through a single lock.

Real IDS load:
- 10 000 – 1 000 000 events/sec
- Multiple source IPs, users, hosts simultaneously
- Long-running state that must stay consistent per entity

A single mutex cannot scale.

### 4.2 Pipeline Models

| Model            | Use case              | Parallelism         |
|------------------|-----------------------|---------------------|
| Single pipeline  | dev / low load        | none                |
| Sharded pipeline | production (default)  | N independent lanes |
| Staged pipeline  | extreme load (future) | per-stage threads   |

### 4.3 Recommended Model — Sharded Pipelines

Create N independent pipeline instances. Route each event to exactly one
pipeline by hashing the source key:

```cpp
struct ShardingConfig {
    uint32_t    num_pipelines = 8;
    std::string hash_key      = "ip";  // "ip" | "session" | "user"
};

uint32_t shard_for(const Event& ev, const ShardingConfig& cfg) {
    const std::string& key =
        cfg.hash_key == "session" ? (ev.metadata.count("session")
                                     ? ev.metadata.at("session") : ev.source)
      : cfg.hash_key == "user"    ? (ev.metadata.count("user")
                                     ? ev.metadata.at("user") : ev.source)
      : ev.source;
    return static_cast<uint32_t>(std::hash<std::string>{}(key))
           % cfg.num_pipelines;
}
```

Each shard owns its own:
- `LocalAnalyzer`
- `StateInstanceManager<SegmentSSM>`
- `StateInstanceManager<HierarchicalSSM>` (L2s, L2m)
- `MemoryStore` (ip/user/session partitions)
- `Retriever`
- `ReasoningModel`
- `DecisionEngine`

Shared across shards (read-mostly, protected by `shared_mutex`):
- `global_store` (global memory partition)
- `L2l` global SSM state
- `RuleTable`
- `ConfigHolder`

### 4.4 State Ownership Rule

Each entity (IP, session, user) is always processed by the same shard.
This is guaranteed by consistent hashing on the routing key.

Rule: one entity → single thread → FIFO queue.

Never process the same key on two threads simultaneously. Violation
causes SSM state corruption, wrong drift score, and incorrect repeat
detection.

### 4.5 Queue Policy

```cpp
struct QueueConfig {
    size_t queue_depth  = 4096;
    bool   backpressure = true;
};

enum class BackpressurePolicy {
    Block,     // block producer until space available
    Drop,      // drop event, increment counter
    Priority,  // drop low-anomaly events first
    Sample     // pass 1-in-N events when full
};

struct BackpressureConfig {
    BackpressurePolicy policy              = BackpressurePolicy::Priority;
    float              priority_keep_above = 0.60f;
    uint32_t           sample_rate         = 10;
};
```

### 4.6 Latency Budget

Target latency per stage (p99, single shard, no reasoning):

| Stage                  | Target latency |
|------------------------|---------------|
| L0                     | < 5 µs        |
| L1                     | < 10 µs       |
| L2s/L2m                | < 10 µs       |
| Memory write           | < 5 µs        |
| Retrieval              | < 50 µs       |
| Reasoning (gated)      | < 200 µs      |
| Decision               | < 5 µs        |
| Total (no reasoning)   | < 85 µs       |
| Total (with reasoning) | < 285 µs      |

Reasoning is gated (§3.3–3.5) so it fires on < 20% of events in
normal traffic.

### 4.7 Monitoring Counters

```cpp
struct PipelineStats {
    std::atomic<uint64_t> events_ingested   = 0;
    std::atomic<uint64_t> events_dropped    = 0;
    std::atomic<uint64_t> reasoning_calls   = 0;
    std::atomic<uint64_t> alerts_emitted    = 0;
    std::atomic<uint64_t> blocks_emitted    = 0;
    std::atomic<uint64_t> escalations       = 0;
    std::atomic<uint64_t> state_resets      = 0;
    std::atomic<uint64_t> memory_evictions  = 0;
    std::atomic<uint64_t> queue_full_events = 0;
    std::atomic<uint64_t> fault_count       = 0;
    std::array<size_t, 64> queue_depth      = {};
};
```

Expose via `IDS::stats()`.

### 4.8 Shutdown & Restart Rules

Safe shutdown sequence:

```
1. stop accepting new events (close ingest)
2. drain all shard queues (process remaining events)
3. flush all L1 segments (force-flush pending SegmentState)
4. save state (optional)
5. close memory stores
6. join all threads
```

State persistence:

```cpp
void save_state(const std::string& path);  // serialize all StateInstanceManagers
void load_state(const std::string& path);  // restore on startup
```

If `load_state` fails: log error, start clean. Never crash on load failure.

### 4.9 Fixed Execution Flow

```
external event
  ↓ shard = hash(ev.source) % num_pipelines
  ↓ enqueue(shard_queue[shard], ev)
  ↓ [shard thread dequeues]
  ↓ validate input (§5.8)
  ↓ L0 → L1 → L2 (routing per §1)
  ↓ memory write (gated, scoped per §2)
  ↓ retrieval (scoped per §2)
  ↓ gate check → reasoning (per §3)
  ↓ decision + overrides + cooldown (per §3)
  ↓ emit callbacks
  ↓ update PipelineStats
```

Parallel only across shards. Sequential within each shard.

---

## 5. Fault Handling & Recovery Policy

> Design principle: **fail safe, not fail fast.**

### 5.1 Goals

| Goal                              | Rule                                      |
|-----------------------------------|-------------------------------------------|
| Never crash                       | catch all exceptions at pipeline boundary |
| Never silently corrupt state      | detect and reset, log every fault         |
| Never produce random alerts       | fallback to safe decision on fault        |
| Never grow memory unbounded       | eviction + cleanup always active          |
| Always continue processing        | faults are isolated, not fatal            |

### 5.2 Fault Taxonomy

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

struct FaultRecord {
    FaultType   type;
    std::string key;
    std::string detail;
    Time        time;
};
```

### 5.3 Numeric Fault Detection

After every SSM state update (mandatory, cannot be skipped):

```cpp
// Step 1: NaN / Inf check
for (size_t i = 0; i < SDIM; ++i) {
    if (!std::isfinite(state_[i])) {
        reset_state(key);
        log_fault(FaultType::Numeric, key, "NaN/Inf detected");
        return;
    }
}

// Step 2: energy check
float energy = l2_norm(state_);
if (energy > cfg.max_energy) {
    for (auto& x : state_) x = std::clamp(x, -cfg.clamp_limit, cfg.clamp_limit);
    energy = l2_norm(state_);
    if (energy > cfg.max_energy * 2.f) {
        reset_state(key);
        log_fault(FaultType::Numeric, key, "energy overflow after clamp");
    }
}
```

### 5.4 State Corruption Recovery

Reset the smallest scope possible. Never reset global unless required:

```
Fault in L1[ip]      → reset L1[ip] only
Fault in L2s[ip]     → reset L2s[ip] only
Fault in L2m[host]   → reset L2m[host] only
Fault in L2l[global] → reset L2l (last resort only)
```

```cpp
void recover_state(const StateKey& key, int level) {
    switch (level) {
    case 1: l1_manager_.reset(key);  break;
    case 2: l2s_manager_.reset(key); break;
    case 3: l2m_manager_.reset(key); break;
    case 4: l2l_global_.reset();     break;
    }
    stats_.state_resets++;
}
```

### 5.5 Queue Overflow Handling

```cpp
bool try_enqueue(ShardQueue& q, const Event& ev, float anomaly_score,
                 const BackpressureConfig& cfg) {
    if (!q.full()) { q.push(ev); return true; }

    switch (cfg.policy) {
    case Policy::Drop:
        stats_.events_dropped++;
        return false;
    case Policy::Priority:
        if (anomaly_score < cfg.priority_keep_above) {
            stats_.events_dropped++;
            return false;
        }
        q.pop_front();
        q.push(ev);
        return true;
    case Policy::Block:
        q.wait_and_push(ev);
        return true;
    case Policy::Sample:
        if (++sample_counter_ % cfg.sample_rate != 0) {
            stats_.events_dropped++;
            return false;
        }
        q.push(ev);
        return true;
    }
    return false;
}
```

Always increment `stats_.queue_full_events` on any queue-full event.

### 5.6 Memory Overflow

When a `VectorStore` partition reaches `max_size`, evict by priority:

```
1. Records with age > record_ttl (expired)
2. Records with lowest anomaly_score
3. Records from global_store before ip_store (preserve local context)
4. Oldest by insertion order (tie-break)
```

Never evict records with `score >= memory_force_gate` unless the store
is critically full (> 2× max_size).

### 5.7 State Instance Overflow

When `StateInstanceManager` reaches `max_instances`:

```
Eviction order:
1. phase == Expired
2. phase == Idle (longest idle first)
3. lowest energy
4. oldest last_update
```

| Level | max_instances |
|-------|---------------|
| L1    | 10 000        |
| L2s   | 5 000         |
| L2m   | 1 000         |
| L2l   | 1 (global)    |

### 5.8 Input Validation

Validate every event before it enters L0:

```cpp
bool validate_event(const Event& ev) {
    if (ev.source.empty())                  return false;
    if (ev.type == EventType::Unknown)      return false;
    if (!std::isfinite(ev.payload.entropy)) return false;
    if (!std::isfinite(ev.payload.rate_hz)) return false;
    return true;
}
```

Invalid events are dropped before entering any state. Log and increment
`stats_.fault_count`.

### 5.9 Thread Failure Recovery

```cpp
struct WatchdogConfig {
    float    heartbeat_interval_s = 1.0f;
    uint32_t max_missed_beats     = 3;
    bool     auto_restart         = true;
};
```

If a shard thread misses `max_missed_beats` heartbeats:
1. Log fault
2. If `auto_restart`: spawn replacement thread, resume from queue
3. Shard state is preserved (owned by `StateInstanceManager`, not the thread)

### 5.10 Reasoning Failure

```cpp
ReasoningResult safe_reason(const LocalState& ls, const SegmentState& ss,
                             const GlobalState& gs, const RetrievedContext& ctx) {
    try {
        return reasoner_.reason(ls, ss, gs, ctx);
    } catch (...) {
        stats_.fault_count++;
        ReasoningResult r;
        r.confidence = 0.5f * ls.anomaly_score + 0.5f * ss.anomaly_trend;
        r.decision   = score_to_decision(r.confidence, thresholds_);
        r.explanation = "[fault: reasoning failed, fallback score]";
        return r;
    }
}
```

### 5.11 Retrieval Failure

```cpp
RetrievedContext safe_retrieve(...) {
    try {
        return retriever_.retrieve(ls, ss, gs, ev);
    } catch (...) {
        stats_.fault_count++;
        return RetrievedContext{};  // empty context — reasoning still runs
    }
}
```

### 5.12 Storage Failure

```cpp
bool save_state(const std::string& path) noexcept {
    try { /* serialize */ return true; }
    catch (...) {
        log_fault(FaultType::Storage, "", "save_state failed");
        return false;
    }
}

bool load_state(const std::string& path) noexcept {
    try { /* deserialize */ return true; }
    catch (...) {
        log_fault(FaultType::Storage, "", "load_state failed — starting clean");
        return false;
    }
}
```

### 5.13 Safe Reset Order

When a severe fault requires broader reset, always reset smallest scope first:

```
1. session state
2. ip state (L1 + L2s)
3. user state
4. host state (L2m)
5. global state (L2l)  ← last resort only
```

### 5.14 Panic Mode

If `stats_.fault_count` exceeds `panic_threshold` within a time window,
enter safe mode:

```cpp
struct PanicConfig {
    uint32_t panic_threshold      = 100;
    float    panic_window_s       = 60.f;
    bool     disable_reasoning    = true;
    bool     disable_memory_write = true;
    bool     rules_only           = true;
};
```

In panic mode:
- Reasoning is disabled (use rule-based decision only)
- Memory writes are disabled
- L0 + RuleTable still active — system still detects known attacks
- Auto-exit panic mode after `panic_window_s` if fault rate drops

### 5.15 System Health Monitoring

```cpp
struct HealthStats {
    std::atomic<uint64_t> numeric_faults   = 0;
    std::atomic<uint64_t> state_resets     = 0;
    std::atomic<uint64_t> memory_evictions = 0;
    std::atomic<uint64_t> queue_drops      = 0;
    std::atomic<uint64_t> reasoning_fails  = 0;
    std::atomic<uint64_t> retrieval_fails  = 0;
    std::atomic<uint64_t> storage_fails    = 0;
    std::atomic<uint64_t> thread_restarts  = 0;
    bool                  panic_mode       = false;
};
```

Expose via `IDS::health()`.

### 5.16 Complete Fault Flow

```
event enters pipeline
  ↓ validate_event() → invalid: drop + log
  ↓ process L0–L2
  ↓ after each SSM update: check NaN/Inf/energy
      → fault: reset_state(key, level) + log
  ↓ memory write
      → full: evict by priority + log
  ↓ retrieval
      → fail: empty context + log
  ↓ reasoning
      → fail/timeout: fallback score + log
  ↓ decision
      → exception: log + emit Decision::Log as safe fallback
  ↓ check fault_count → if > panic_threshold: enter panic mode
  ↓ update HealthStats
  ↓ continue (never stop)
```

---

## 6. Training / Parameter Update / Adaptation Policy

> This section defines where SSM parameters come from, how thresholds are
> calibrated, what can adapt online vs. offline, how updates are applied
> safely, and how the system handles invalid or stale parameters.

### 6.1 Problem

Every parameter in the current codebase is a compile-time constant or
a default-initialized struct value:

```cpp
for (auto& a : p.A_log) a = -0.5f;
float reasoning_gate = 0.40f;
float decay_l1       = 0.95f;
cfg.tick_rates = {1, 10, 60, 600};
```

None of these are learned, calibrated, or updatable at runtime. A static
system will degrade as traffic patterns change, new attack types emerge,
and network baselines shift.

### 6.2 Parameter Categories

| Category       | Examples                                           | Update method              |
|----------------|----------------------------------------------------|----------------------------|
| Model params   | `A_log`, `B_proj`, `C_proj`, `delta_proj`          | Offline only               |
| Thresholds     | `alert_threshold`, `gate_threshold`, `flush_anomaly`| Calibration / hot reload  |
| Score weights  | `GateWeights`, `ScoreFusionWeights`                | Calibration / hot reload   |
| Decay factors  | `decay_l1`, `idle_decay_boost`                     | Hot reload                 |
| Routing config | `promote_threshold`, `flush_n`, `mid_tick`         | Hot reload                 |
| Memory limits  | `max_ip_records`, `queue_size`                     | Hot reload                 |
| Rules          | `RuleTable`                                        | Runtime insert/remove      |
| Signatures     | `VectorStore` embeddings                           | Runtime insert/remove      |
| Baseline stats | `baseline_model`, rolling mean/variance            | Online (slow EMA)          |

### 6.3 Offline Training

SSM matrices must be trained offline. Online SSM training in production
is too risky — a bad gradient step corrupts all state for that shard.

```
Offline pipeline:
  traffic logs (labeled + unlabeled)
    ↓ feature extraction (same as ids_level0.hpp embed())
    ↓ SSM training (e.g. S4 / Mamba training loop)
    ↓ export: A_log, B_proj, C_proj, delta_proj, D_skip
    ↓ serialize to binary / JSON
    ↓ load at IDS startup via load_model()
```

```cpp
struct ModelParams {
    std::string              version;
    std::string              checksum;
    Time                     trained_at;
    L1SSM::Params            l1_params;
    HierarchicalSSM::Config  l2_params;
};

bool load_model(const std::string& path, ModelParams& out) noexcept;
```

### 6.4 Threshold Calibration

Calibration modes:

| Mode             | Description                                              |
|------------------|----------------------------------------------------------|
| Manual           | operator sets values in config file                      |
| Baseline profile | observe N minutes of normal traffic, compute percentiles |
| Auto-tune        | adjust thresholds based on false-positive / miss rate    |

```cpp
struct BaselineCalibrator {
    void observe(const LocalState& ls, const SegmentState& ss);
    ThresholdSuggestion compute(float fp_target = 0.01f) const;
};

struct ThresholdSuggestion {
    float gate_threshold;
    float alert_threshold;
    float block_threshold;
    float flush_anomaly;
    float promote_threshold;
};
```

Run calibrator in `learning_mode` (§6.13) before enabling blocking.

### 6.5 Online Adaptation — Allowed vs. Forbidden

| Parameter                  | Online update | Reason                              |
|----------------------------|---------------|-------------------------------------|
| `baseline_model`           | yes (EMA)     | must track normal traffic drift     |
| rolling mean / variance    | yes (Welford) | already done in `LocalAnalyzer`     |
| `anomaly_history` EMA      | yes           | already done in `HierarchicalSSM`   |
| memory record scores       | yes (decay)   | recency weighting                   |
| `A_log`, `B_proj`, etc.    | **no**        | too risky, corrupts all state       |
| decision thresholds        | **no** (online)| use calibration + hot reload       |
| routing logic              | **no**        | must be deterministic               |

Rule: **online = statistics only. offline = model.**

### 6.6 Baseline Learning

```cpp
struct BaselineConfig {
    float alpha     = 0.01f;
    float min_value = -50.f;
    float max_value =  50.f;
    bool  freeze    = false;
};
```

`freeze = true` during confirmed attack periods prevents the baseline
from learning attack patterns as normal. Set automatically when
`anomaly_history > freeze_threshold`.

### 6.7 Safe Update Rules

```
1. Prepare new config in a separate object
2. Validate new config (§6.15)
3. Acquire update lock (brief, not per-event)
4. Swap config pointer atomically
5. Release lock
6. Old config destroyed after all in-flight events complete
```

```cpp
class ConfigHolder {
public:
    std::shared_ptr<IDSConfig> get() const {
        return std::atomic_load(&cfg_);
    }
    void update(std::shared_ptr<IDSConfig> new_cfg) {
        std::atomic_store(&cfg_, std::move(new_cfg));
    }
private:
    std::shared_ptr<IDSConfig> cfg_;
};
```

### 6.8 Versioning

```cpp
struct ParameterVersion {
    std::string model_version;
    std::string rule_version;
    std::string config_version;
    std::string signature_version;
    Time        loaded_at;
    std::string operator_note;
};
```

Store last N versions (default: 3). Allow rollback:

```cpp
void rollback_config(uint32_t steps_back = 1);
void rollback_model(uint32_t steps_back = 1);
```

### 6.9 Hot Reload

| Component             | Hot reload | Method                        |
|-----------------------|------------|-------------------------------|
| Thresholds            | yes        | `ConfigHolder::update()`      |
| Score weights         | yes        | `ConfigHolder::update()`      |
| Decay factors         | yes        | `ConfigHolder::update()`      |
| Routing config        | yes        | `ConfigHolder::update()`      |
| Memory limits         | yes        | `ConfigHolder::update()`      |
| Rules                 | yes        | `RuleTable` copy+swap         |
| Signatures            | yes        | `VectorStore::insert()`       |
| SSM matrix dimensions | **no**     | requires restart + state reset|
| `kSSMStateDim`        | **no**     | compile-time constant         |
| `num_pipelines`       | **no**     | requires restart              |

### 6.10 Signature Update

```cpp
pipeline.load_signature(embedding, "NewRansomware-v2", 1.0f);
pipeline.remove_signature(signature_id);
pipeline.replace_signatures(new_vector_store);  // copy+swap
```

### 6.11 Rule Update Policy

```cpp
class RuleTable {
public:
    void add(Rule r);
    void remove(uint32_t rule_id);
    void set_enabled(uint32_t rule_id, bool enabled);
    void set_priority(uint32_t rule_id, uint32_t priority);
    void replace(std::vector<Rule> new_rules);  // copy+swap
};
```

Never modify the rule vector in-place while a shard is reading it.

### 6.12 Model Update Policy

```
1. Train new model offline
2. Export ModelParams to file
3. Call pipeline.stage_model(path)   ← loads + validates, does not apply yet
4. Call pipeline.apply_model()       ← atomically swaps, resets all SSM state
5. Old model kept for rollback
```

State must be reset on model change because old state was computed with
old matrices — mixing is undefined behavior:

```cpp
void apply_model(const ModelParams& m) {
    validate_model(m);
    reset_all_ssm_state();
    swap_model_params(m);
    version_.model_version = m.version;
}
```

### 6.13 Learning Mode

```cpp
struct LearningModeConfig {
    bool  enabled           = false;
    bool  disable_blocking  = true;
    bool  log_only          = true;
    bool  collect_baseline  = true;
    float duration_s        = 3600.f;
};
```

In learning mode: all events processed through full pipeline, no
`Block` or `Escalate` decisions emitted, `BaselineCalibrator` collects
statistics, `ThresholdSuggestion` logged at end of duration.

### 6.14 Safe Fallback on Invalid Model

```cpp
bool stage_model(const std::string& path) noexcept {
    ModelParams m;
    if (!load_model(path, m))   { log_fault(...); return false; }
    if (!validate_model(m))     { log_fault(...); return false; }
    staged_model_ = m;
    return true;
}
```

If no valid model exists: use rule engine only (§5.14 panic mode).

### 6.15 Parameter Validation

```cpp
bool validate_config(const IDSConfig& cfg) {
    if (cfg.thresholds.ignore_threshold >= cfg.thresholds.log_threshold)   return false;
    if (cfg.thresholds.log_threshold    >= cfg.thresholds.alert_threshold)  return false;
    if (cfg.thresholds.alert_threshold  >= cfg.thresholds.block_threshold)  return false;
    if (cfg.state.decay_l1 <= 0.f || cfg.state.decay_l1 >= 1.f)            return false;
    if (!std::isfinite(cfg.fusion.w_local) || cfg.fusion.w_local < 0.f)    return false;
    return true;
}

bool validate_model(const ModelParams& m) {
    for (float v : m.l1_params.A_log)
        if (!std::isfinite(v)) return false;
    return compute_checksum(m) == m.checksum;
}
```

### 6.16 Update Flow

```
1. Load new config / model from file or API
2. validate_config() / validate_model()
   → if invalid: reject, keep old, log fault
3. Acquire update lock (brief)
4. Swap via ConfigHolder::update() or apply_model()
5. Release lock
6. Log version change to ParameterVersion
7. (Optional) reset affected state if model changed
8. Resume — no pipeline pause required for config-only updates
```

---

## 7. Attack Correlation & Campaign Tracking Layer

> This section defines the correlation engine that sits above reasoning
> and detects multi-stage, distributed, and slow attacks that are
> invisible at the per-event level.

### 7.1 Problem

The current pipeline detects anomalies per-event and per-segment. Each
event is evaluated in isolation. This misses:

- Slow lateral movement (each step scores low individually)
- APT persistence (weeks of low-level activity)
- Multi-host scanning (distributed, low rate per source)
- Staged exfiltration (beacon → privilege → move → exfil)
- Credential stuffing across accounts (many users, same pattern)

### 7.2 Correlation Layer Position

```
L0 → L1 → L2 → Memory → Retriever → Reasoning → Correlation → Decision
```

Correlation receives `ReasoningResult` + `StateKey` + `Event` and
produces a `CorrelationResult` that can upgrade the final decision.

### 7.3 AlertRecord — Correlation Input

```cpp
struct AlertRecord {
    Time        time;
    StateKey    key;
    std::string attack_class;
    float       score;
    Decision    decision;
    std::string source;
    std::string destination;
};
```

Only records with `decision >= Decision::Log` are stored.

### 7.4 Correlation Scopes

```cpp
struct CorrelationStore {
    std::unordered_map<std::string, std::deque<AlertRecord>> ip_records;
    std::unordered_map<std::string, std::deque<AlertRecord>> user_records;
    std::unordered_map<std::string, std::deque<AlertRecord>> host_records;
    std::deque<AlertRecord>                                   global_records;
};
```

| Scope  | Key field   | Use                           |
|--------|-------------|-------------------------------|
| IP     | `key.ip`    | repeated attack from one IP   |
| User   | `key.user`  | account compromise            |
| Host   | `key.host`  | host-level compromise         |
| Global | —           | campaign / distributed attack |

### 7.5 Time Windows

```cpp
struct CorrelationWindowConfig {
    float short_window_s    =    60.f;   // 1 min  — repeat detection
    float mid_window_s      =   600.f;   // 10 min — multi-stage
    float long_window_s     =  3600.f;   // 1 hour — APT / slow attack
    float campaign_window_s = 86400.f;   // 24 hours — campaign lifetime
};
```

Records older than `campaign_window_s` are evicted from all buffers.

### 7.6 Repeat Detection

```cpp
struct RepeatDetectionConfig {
    uint32_t repeat_threshold = 3;
    float    repeat_window_s  = 60.f;
};

bool detect_repeat(const std::string& ip,
                   const CorrelationStore& store,
                   const RepeatDetectionConfig& cfg) {
    auto it = store.ip_records.find(ip);
    if (it == store.ip_records.end()) return false;
    float cutoff = now_s() - cfg.repeat_window_s;
    uint32_t count = 0;
    for (const auto& r : it->second)
        if (r.time >= cutoff) ++count;
    return count >= cfg.repeat_threshold;
}
```

### 7.7 Multi-Stage Attack Detection

```cpp
struct AttackPattern {
    std::string              name;
    std::vector<std::string> sequence;
    float                    max_gap_s;
};

// Example patterns:
AttackPattern lateral_movement {
    "LateralMovement",
    {"PortScan", "BruteForce/CredentialStuffing", "LateralMovement/Persistence"},
    600.f
};

AttackPattern apt_exfil {
    "APT-Exfiltration",
    {"BruteForce/CredentialStuffing", "FileSystemAnomaly/Ransomware",
     "EncryptedC2/Exfiltration"},
    3600.f
};

struct MultiStageConfig {
    std::vector<AttackPattern> patterns;
    bool                       enabled = true;
};
```

### 7.8 Distributed Attack Detection

```cpp
struct DistributedAttackConfig {
    uint32_t    unique_source_threshold = 5;
    float       dist_window_s           = 60.f;
    std::string target_scope            = "host";
};
```

Escalate when N unique source IPs target the same destination within
`dist_window_s`.

### 7.9 Slow Attack Detection

```cpp
struct SlowAttackConfig {
    float    slow_window_s        = 3600.f;
    uint32_t slow_event_threshold = 10;
    float    slow_score_threshold = 0.30f;
};
```

Detect low-score events accumulating over a long window — characteristic
of APT and slow-burn attacks that evade per-event detection.

### 7.10 CorrelationResult

```cpp
struct CorrelationResult {
    float       corr_score;          // 0–1 additive boost
    bool        repeat_detected;
    bool        multi_stage_detected;
    bool        distributed_detected;
    bool        slow_attack_detected;
    std::string campaign_id;
    Decision    upgraded_decision;   // may upgrade base decision
    std::string correlation_type;
};
```

### 7.11 Campaign State

```cpp
struct CampaignState {
    std::string              id;
    std::string              attack_class;
    std::vector<std::string> sources;
    std::vector<std::string> hosts;
    std::vector<std::string> users;
    Time                     first_seen;
    Time                     last_seen;
    uint32_t                 event_count;
    float                    max_score;
    bool                     active;
};
```

### 7.12 Score Contribution

```cpp
struct CorrelationWeights {
    float repeat_weight    = 0.20f;
    float stage_weight     = 0.30f;
    float dist_weight      = 0.25f;
    float slow_weight      = 0.15f;
    float campaign_weight  = 0.10f;
};

float final_score = reasoning_score
                  + corr_weight * corr_score;
final_score = std::clamp(final_score, 0.f, 1.f);
```

### 7.13 Campaign Timeout

```cpp
struct CampaignTimeoutConfig {
    float campaign_idle_timeout_s = 1800.f;  // 30 min no new events → end
    float campaign_max_age_s      = 86400.f; // 24 hours absolute max
};
```

When a campaign ends: mark `active = false`, retain for audit log,
remove from active tracking after `campaign_max_age_s`.

### 7.14 Correlation Memory Limits

```cpp
struct CorrelationLimits {
    size_t max_records_per_ip   = 500;
    size_t max_records_per_user = 500;
    size_t max_records_per_host = 1000;
    size_t max_global_records   = 5000;
    size_t max_active_campaigns = 200;
};
```

### 7.15 CorrelationEngine Interface

```cpp
class CorrelationEngine {
public:
    explicit CorrelationEngine(CorrelationConfig       cfg    = {},
                               CorrelationLimits       limits = {},
                               CorrelationWindowConfig win    = {},
                               MultiStageConfig        ms     = {},
                               DistributedAttackConfig da     = {},
                               SlowAttackConfig        sa     = {});

    CorrelationResult process(const ReasoningResult& res,
                              const Event&           ev,
                              const GlobalState&     gs);

    std::vector<CampaignState> active_campaigns() const;
    void sweep(float now_s);
    void reset(const StateKey& key);
};
```

### 7.16 Fixed Correlation Flow

```
reasoning result
  ↓ record AlertRecord (if decision >= Log)
  ↓ update ip_records[key.ip]
  ↓ update host_records[key.host]
  ↓ update global_records
  ↓ detect_repeat()        → if true: corr_score += repeat_weight
  ↓ detect_multi_stage()   → if true: corr_score += stage_weight
  ↓ detect_distributed()   → if true: corr_score += dist_weight
  ↓ detect_slow_attack()   → if true: corr_score += slow_weight
  ↓ update CampaignState (create or update)
  ↓ compute final_score = reasoning_score + corr_weight * corr_score
  ↓ apply campaign decision upgrade
  ↓ return CorrelationResult → DecisionEngine
```

---

## 8. Adaptive Baseline & Self-Tuning Layer

> This section defines how the IDS adapts its thresholds, decay factors,
> and routing parameters to the observed traffic environment, preventing
> false-positive explosion and missed detections as traffic patterns change.

### 8.1 Problem

Every threshold in the current system is a fixed constant. Real traffic
varies by time of day, day of week, network growth, and seasonal patterns.
Fixed thresholds calibrated for one traffic profile will produce too many
false positives or too many misses when the profile changes.

### 8.2 Baseline Concept

Each scope maintains a statistical baseline of normal behavior:

```cpp
struct ScopeBaseline {
    std::array<float, kEmbeddingDim> mean     = {};
    std::array<float, kEmbeddingDim> variance = {};
    float avg_anomaly_score = 0.f;
    float avg_rate_hz       = 0.f;
    float avg_entropy       = 0.f;
    float avg_drift         = 0.f;
    float avg_state_energy  = 0.f;
    Time  last_update;
    bool  frozen            = false;
};

struct BaselineStore {
    std::unordered_map<std::string, ScopeBaseline> ip_baseline;
    std::unordered_map<std::string, ScopeBaseline> user_baseline;
    std::unordered_map<std::string, ScopeBaseline> host_baseline;
    ScopeBaseline                                   global_baseline;
};
```

### 8.3 Baseline Update Rule

Slow EMA update, applied only when not frozen:

```cpp
void update_baseline(ScopeBaseline& b, const LocalState& ls,
                     const SegmentState& ss, const GlobalState& gs,
                     float alpha) {
    if (b.frozen) return;
    b.avg_anomaly_score += alpha * (ls.anomaly_score - b.avg_anomaly_score);
    b.avg_rate_hz       += alpha * (ss.rate_mean     - b.avg_rate_hz);
    b.avg_entropy       += alpha * (ls.entropy       - b.avg_entropy);
    b.avg_drift         += alpha * (gs.drift_score   - b.avg_drift);
    for (size_t i = 0; i < kEmbeddingDim; ++i)
        b.mean[i] += alpha * (ls.embedding[i] - b.mean[i]);
}
```

Alpha per level:

| Level | alpha  | Rationale                        |
|-------|--------|----------------------------------|
| L1    | 0.050  | fast — tracks per-IP behavior    |
| L2s   | 0.010  | medium — tracks IP trend         |
| L2m   | 0.005  | slow — tracks host behavior      |
| L2l   | 0.001  | very slow — tracks global normal |

### 8.4 Adaptive Thresholds

```cpp
struct AdaptiveThresholdConfig {
    float k_alert  = 3.0f;
    float k_block  = 5.0f;
    float k_gate   = 2.0f;
    float min_alert_threshold = 0.30f;
    float max_alert_threshold = 0.90f;
};

float adaptive_threshold(float baseline_mean, float baseline_std,
                          float k, float min_t, float max_t) {
    return std::clamp(baseline_mean + k * baseline_std, min_t, max_t);
}
```

Thresholds are recomputed after each baseline update and applied via
`ConfigHolder` swap (§6.7).

### 8.5 Adaptive Anomaly Scaling

```cpp
float scale_anomaly(float raw_score, const ScopeBaseline& b, float eps = 1e-6f) {
    float std = sqrtf(std::max(eps, b.variance[0]));
    return std::clamp((raw_score - b.avg_anomaly_score) / std, 0.f, 1.f);
}
```

Prevents a high-traffic network from generating constant alerts and a
low-traffic network from missing real anomalies.

### 8.6 Adaptive Decay

```cpp
float adaptive_decay(float current_rate, float baseline_rate,
                     float decay_slow, float decay_fast) {
    return current_rate > baseline_rate ? decay_slow : decay_fast;
}

struct AdaptiveDecayConfig {
    float decay_slow = 0.99f;
    float decay_fast = 0.90f;
};
```

Per-level: L1 uses `decay_fast=0.90/decay_slow=0.97`, L2l uses
`decay_fast=0.995/decay_slow=0.999`.

### 8.7 Adaptive Routing

```cpp
float adaptive_promote_threshold(float baseline_anomaly, float base, float k) {
    return std::clamp(base + k * baseline_anomaly, 0.20f, 0.90f);
}

struct AdaptiveRoutingConfig {
    float routing_adapt_k = 0.5f;
    float base_promote    = 0.50f;
};
```

Noisy network → raise threshold (promote less). Quiet network → lower
threshold (promote more).

### 8.8 Adaptive Gate

```cpp
float adaptive_gate(float baseline_noise, float base_gate, float k) {
    return std::clamp(base_gate + k * baseline_noise, 0.20f, 0.80f);
}
```

Target: reasoning fires on ~15–20% of events regardless of traffic volume.

### 8.9 Freeze Rule

Baseline must not update during a confirmed attack:

```cpp
void maybe_freeze(ScopeBaseline& b, float anomaly_score,
                  float freeze_threshold = 0.70f) {
    b.frozen = (anomaly_score >= freeze_threshold);
}
```

Freeze is per-scope. IP baseline freezes when that IP's anomaly is high.
Global baseline freezes only when `anomaly_history >= freeze_threshold`.

### 8.10 Drift Detection on Baseline

```cpp
struct BaselineDriftConfig {
    float max_baseline_change_rate = 0.10f;
    float baseline_drift_alert     = 0.30f;
};
```

If `|new_baseline - old_baseline| > max_baseline_change_rate` for N
consecutive updates: log fault, freeze baseline, alert operator.

### 8.11 Safe Adaptation Limits

```cpp
struct AdaptationLimits {
    float threshold_min = 0.10f;
    float threshold_max = 0.95f;
    float decay_min     = 0.80f;
    float decay_max     = 0.999f;
    float alpha_min     = 0.0001f;
    float alpha_max     = 0.10f;
    float gate_min      = 0.15f;
    float gate_max      = 0.85f;
};
```

### 8.12 Per-Scope Adaptation

Each scope has its own `ScopeBaseline`. Adaptation is independent:

- `ip_baseline[ip]` — adapts to that IP's traffic pattern
- `user_baseline[user]` — adapts to that user's behavior
- `host_baseline[host]` — adapts to that host's load
- `global_baseline` — adapts to the whole network

Do not mix scopes.

### 8.13 Adaptation Update Order

```
event processed
  ↓ compute raw anomaly_score (L0)
  ↓ check freeze condition → maybe_freeze(baseline, score)
  ↓ if not frozen: update_baseline(baseline, ls, ss, gs, alpha)
  ↓ recompute adaptive thresholds
  ↓ recompute adaptive decay
  ↓ recompute adaptive gate
  ↓ apply to ConfigHolder (§6.7) if changed beyond update_epsilon=0.005f
```

### 8.14 Baseline Reset Rules

| Trigger                              | Scope reset                  |
|--------------------------------------|------------------------------|
| Session ended                        | `ip_baseline[ip]` (partial)  |
| Host restarted                       | `host_baseline[host]`        |
| User account reset                   | `user_baseline[user]`        |
| Baseline drift alert fired           | freeze + slow reset          |
| Manual operator reset                | any scope                    |
| `anomaly_history > 0.90` for 10 min  | freeze global baseline       |

### 8.15 Monitoring Adaptation

```cpp
struct AdaptationStats {
    std::atomic<uint64_t> baseline_updates  = 0;
    std::atomic<uint64_t> baseline_freezes  = 0;
    std::atomic<uint64_t> threshold_changes = 0;
    std::atomic<uint64_t> decay_changes     = 0;
    std::atomic<uint64_t> gate_changes      = 0;
    std::atomic<uint64_t> baseline_resets   = 0;
    std::atomic<uint64_t> drift_alerts      = 0;
};
```

If `threshold_changes` grows faster than `events_ingested / 100`,
the adaptation is unstable — log fault and freeze adaptation.

### 8.16 AdaptiveLayer Interface

```cpp
class AdaptiveLayer {
public:
    explicit AdaptiveLayer(AdaptiveThresholdConfig threshold_cfg = {},
                           AdaptiveDecayConfig     decay_cfg     = {},
                           AdaptiveRoutingConfig   routing_cfg   = {},
                           AdaptationLimits        limits        = {},
                           BaselineDriftConfig     drift_cfg     = {});

    void update(const LocalState& ls, const SegmentState& ss,
                const GlobalState& gs, const Event& ev,
                float anomaly_score);

    IDSConfig adapted_config() const;

    const ScopeBaseline& baseline_for(const StateKey& key,
                                       MemoryScope scope) const;

    void reset(const StateKey& key, MemoryScope scope);
    AdaptationStats stats() const;
};
```

---

## 9. Telemetry / Visualization / Debug Layer

> This section defines the observability layer. It does not change
> detection logic. It makes every internal decision, state value, and
> routing choice visible so the system can be tuned, trusted, and deployed.

### 9.1 Goals

| Requirement                        | Mechanism                        |
|------------------------------------|----------------------------------|
| See why an alert fired             | Decision trace per event         |
| Inspect SSM state values           | State inspection API             |
| See baseline and drift over time   | Time-series sample buffer        |
| Understand routing decisions       | Routing debug log                |
| Monitor pipeline load              | Per-shard pipeline stats         |
| Measure per-stage latency          | Stage latency tracker            |
| Audit every fault                  | Fault log with history           |
| Export data for UI / SIEM          | Export interface                 |

Rule: no hidden state. Everything observable.

### 9.2 Core Metrics Counters

Thread-safe atomic counters exposed via `IDS::metrics()`:

```cpp
struct Metrics {
    std::atomic<uint64_t> events_total      = 0;
    std::atomic<uint64_t> events_per_sec    = 0;   // rolling 1s window
    std::atomic<uint64_t> alerts_total      = 0;
    std::atomic<uint64_t> blocks_total      = 0;
    std::atomic<uint64_t> escalations_total = 0;
    std::atomic<uint64_t> drops_total       = 0;
    std::atomic<uint64_t> reasoning_calls   = 0;
    std::atomic<uint64_t> forced_reasoning  = 0;
    std::atomic<uint64_t> memory_writes     = 0;
    std::atomic<uint64_t> memory_evictions  = 0;
    std::atomic<uint64_t> state_resets      = 0;
    std::atomic<uint64_t> faults_total      = 0;
    std::atomic<uint64_t> queue_overflows   = 0;
    std::atomic<uint64_t> campaigns_active  = 0;
    std::atomic<uint64_t> baseline_freezes  = 0;
};
```

Updated inline in the hot path using `fetch_add` only — no allocation,
no locking.

### 9.3 Per-Level Stats

```cpp
struct L0Stats {
    size_t window_size;
    float  avg_rate_hz;
    float  avg_entropy;
    float  avg_anomaly_score;
};

struct L1Stats {
    size_t segment_count;
    size_t flush_count;
    float  avg_anomaly_trend;
    size_t active_instances;
};

struct L2Stats {
    float  drift_score;
    float  anomaly_history;
    float  avg_state_energy;
    size_t promotion_count;
    size_t active_l2s_instances;
    size_t active_l2m_instances;
};

struct MemoryStats {
    size_t total_records;
    size_t ip_records;
    size_t user_records;
    size_t host_records;
    size_t global_records;
    size_t evictions;
    size_t search_calls;
};

struct ReasoningStats {
    size_t calls;
    float  avg_latency_us;
    float  max_latency_us;
    size_t forced_calls;
    size_t skipped_calls;
    size_t fallback_calls;
};

struct DecisionStats {
    size_t ignore_count;
    size_t log_count;
    size_t alert_count;
    size_t block_count;
    size_t escalate_count;
};
```

All exposed via `IDS::level_stats()` returning a `PipelineLevelStats`
aggregate.

### 9.4 State Inspection API

```cpp
struct StateSnapshot {
    StateKey    key;
    int         level;
    State       state_vector;
    float       energy;
    StatePhase  phase;
    float       drift_score;
    Time        last_update;
    Time        created;
};

std::optional<StateSnapshot> IDS::get_state(const std::string& ip,
                                              int level = 1) const;
std::optional<StateSnapshot> IDS::get_state(const StateKey& key,
                                              int level = 1) const;
GlobalState                  IDS::get_global_state() const;
ScopeBaseline                IDS::get_baseline(const std::string& ip) const;
```

Reads are lock-free snapshots (copy under `shared_lock`). Never blocks
the ingest path.

### 9.5 Memory Inspection API

```cpp
struct MemoryInspectResult {
    std::vector<MemoryRecord> records;
    size_t                    total_in_scope;
    float                     oldest_age_s;
    float                     newest_age_s;
    float                     avg_score;
};

MemoryInspectResult IDS::inspect_memory(const std::string& ip,
                                         MemoryScope scope = MemoryScope::IP,
                                         size_t max_records = 20) const;
```

### 9.6 Routing Debug Log

```cpp
enum class RoutingEvent {
    Flush, Promote, Skip, Split, Merge, Reset, ForcePromote
};

struct RoutingLogEntry {
    Time         time;
    RoutingEvent event;
    StateKey     key;
    int          from_level;
    int          to_level;
    std::string  reason;
};

struct RoutingDebugConfig {
    bool   enabled   = false;  // off by default (production cost)
    size_t ring_size = 10000;
};
```

Example log entries:
```
[ROUTE] t=1234.5 ip=10.0.0.1 PROMOTE L1→L2s reason=anomaly_high(0.73)
[ROUTE] t=1234.6 ip=10.0.0.2 SKIP    L1→L2s reason=low_anomaly(0.08)
[ROUTE] t=1234.7 ip=10.0.0.3 FLUSH   L1      reason=count_exceeded(100)
```

Access via `IDS::routing_log(size_t last_n)`.

### 9.7 Decision Trace

Every alert/block/escalate must carry a full score trace for SOC review:

```cpp
struct DecisionTrace {
    float    local_score;
    float    segment_trend;
    float    anomaly_history;
    float    drift_score;
    float    retrieval_similarity_max;
    bool     rule_matched;
    float    gate_score;
    bool     forced;
    bool     skipped;
    float    fused_score;
    float    corr_score;
    float    final_score;
    Decision base_decision;
    Decision final_decision;
    std::string attack_class;
    std::string correlation_type;
    std::string campaign_id;
};
```

Attached to every `Alert` struct:

```cpp
struct Alert {
    // ... existing fields ...
    DecisionTrace trace;
};
```

### 9.8 Drift Time Series

```cpp
struct TimeSeriesSample {
    Time  time;
    float drift_score;
    float anomaly_history;
    float alert_threshold;
    float gate_threshold;
    float baseline_energy;
};

struct DriftTimeSeries {
    std::deque<TimeSeriesSample> samples;
    size_t max_samples = 10000;

    void record(const GlobalState& gs, const IDSConfig& cfg);
    std::vector<TimeSeriesSample> last_n(size_t n) const;
    void export_json(std::ostream& out) const;
};
```

Sampled once per segment flush (not per event).

### 9.9 Per-Shard Pipeline Stats

```cpp
struct ShardStats {
    uint32_t shard_id;
    size_t   queue_depth;
    float    events_per_sec;
    float    avg_latency_us;
    size_t   drops;
    size_t   active_states;
    bool     reasoning_pool_saturated;
};

std::vector<ShardStats> IDS::shard_stats() const;
```

### 9.10 Stage Latency Tracker

```cpp
struct StageLatency {
    float l0_avg_us;
    float l1_avg_us;
    float l2_avg_us;
    float memory_write_avg_us;
    float retrieval_avg_us;
    float reasoning_avg_us;
    float correlation_avg_us;
    float decision_avg_us;
    float total_avg_us;
    float l0_p99_us;
    float retrieval_p99_us;
    float reasoning_p99_us;
    float total_p99_us;
};

StageLatency IDS::latency_stats() const;
```

Implemented with `std::chrono::steady_clock` timestamps bracketing each
stage. Averages maintained with EMA (alpha=0.01) to avoid allocation.

### 9.11 Fault Log

```cpp
struct FaultLog {
    std::deque<FaultRecord> records;
    size_t max_records = 1000;

    void append(FaultRecord r);
    std::vector<FaultRecord> last_n(size_t n) const;
    std::vector<FaultRecord> by_type(FaultType t) const;
    void export_json(std::ostream& out) const;
};

FaultLog& IDS::fault_log();
```

### 9.12 Config Dump

```cpp
void IDS::dump_config(std::ostream& out) const;
```

Outputs: thresholds, decay values, routing config, memory limits,
model version, rule version, signature count, shard count.
Format: JSON. Safe to call at any time — reads from `ConfigHolder`
snapshot, no pipeline impact.

### 9.13 Snapshot / Dump API

```cpp
bool IDS::save_state(const std::string& path)    noexcept;
bool IDS::save_memory(const std::string& path)   noexcept;
bool IDS::save_baseline(const std::string& path) noexcept;
bool IDS::save_config(const std::string& path)   noexcept;
bool IDS::save_all(const std::string& dir)        noexcept;
```

All saves are non-blocking: snapshot copy under a brief read lock,
then serialize on a background thread. The ingest path is not paused.

### 9.14 Replay Mode

```cpp
struct ReplayConfig {
    std::string event_log_path;
    bool        compare_to_reference = false;
    std::string reference_output_path;
    float       speed_multiplier     = 0.f;  // 0 = as fast as possible
};

ReplayResult IDS::replay(const ReplayConfig& cfg);

struct ReplayResult {
    size_t events_replayed;
    size_t alert_matches;
    size_t alert_mismatches;
    float  avg_latency_us;
};
```

Used for regression testing after threshold changes or model updates.

### 9.15 Debug Log Levels

```cpp
enum class LogLevel {
    Error,   // faults, crashes, unrecoverable errors
    Warn,    // recoverable faults, threshold violations
    Info,    // alerts, blocks, escalations, state resets
    Debug,   // routing decisions, gate evaluations
    Trace    // every event, every state update (dev only)
};

struct TelemetryConfig {
    LogLevel log_level        = LogLevel::Info;
    bool     routing_debug    = false;
    bool     decision_trace   = true;
    bool     latency_tracking = true;
    bool     drift_series     = true;
    size_t   drift_series_max = 10000;
    size_t   fault_log_max    = 1000;
    size_t   routing_log_max  = 10000;
};
```

`Trace` level must never be enabled in production.

### 9.16 Safe Telemetry Rules

| Rule                                  | Implementation                        |
|---------------------------------------|---------------------------------------|
| No heap allocation in hot path        | pre-allocated ring buffers            |
| No blocking I/O in hot path           | async background writer               |
| No heavy logging per event            | sampling + ring buffer                |
| Counters are lock-free                | `std::atomic::fetch_add`              |
| Snapshots are copy-on-read            | brief `shared_lock`, then serialize   |
| Latency tracking uses EMA             | no vector growth, O(1) update         |
| Routing log is optional               | disabled by default in production     |

### 9.17 Export Interface

```cpp
class TelemetryExporter {
public:
    void export_metrics(std::ostream& out)      const;
    void export_stats(std::ostream& out)        const;
    void export_drift_series(std::ostream& out) const;
    void export_fault_log(std::ostream& out)    const;
    void export_config(std::ostream& out)       const;

    using MetricsSink = std::function<void(const Metrics&)>;
    void set_sink(MetricsSink sink, float interval_s = 1.0f);
};
```

The `MetricsSink` callback fires on a background thread at `interval_s`
intervals. The pipeline is never blocked by export.

---

## 10. Summary — Required Changes per File

| File                  | Changes needed |
|-----------------------|----------------|
| `ids_types.hpp`       | Add `StateKey`, `StateMeta`, `StatePhase`, `StateConfig`, `MemoryScope`, `MemoryKey`, `RoutingConfig` and all sub-rule structs (§1); add `FaultType`, `FaultRecord`, `PipelineStats`, `HealthStats` (§5); add `ModelParams`, `ParameterVersion`, `ThresholdSuggestion` (§6); add `AlertRecord`, `CampaignState`, `CorrelationResult` (§7); add `ScopeBaseline`, `BaselineStore`, `AdaptationStats` (§8); add `DecisionTrace`, `TimeSeriesSample`, `RoutingLogEntry`, `ShardStats`, `StageLatency` (§9) |
| `ids_ssm.hpp`         | Add decay/clamp/normalize/NaN-check to `SSM::step()`; add `StateConfig` param; NaN/Inf check mandatory after every update; add `load_model()` support for `ModelParams` (§6.3) |
| `ids_memory.hpp`      | Replace `ExternalMemory` with `MemoryStore` (partitioned §2.3); replace `Retriever` with scoped, time-filtered, priority-weighted implementation (§2.7–2.9); add `WritePolicy`, `EvictionConfig`, `RetrievalTimeConfig`, `RetrievalWeights`, `ForceRetrievalConfig`, `MemoryCleanupConfig`; add `shared_mutex` to `host_store` and `global_store`; add `replace_signatures()`; add `inspect_memory()` (§9.5) |
| `ids_level1.hpp`      | `SegmentSSM` must be instantiable per-key; add `FlushRules` to `Config` (§1.4); remove global state assumption |
| `ids_reasoning.hpp`   | Replace single-float gate with `MultiSignalGate` + `GateWeights` (§3.3); add `ForcedReasoningConfig`, `SkipReasoningConfig`, `ScoreFusionWeights`, `DecisionThresholds` (§3.4–3.8); enforce `kMaxReasoningTokens=12` cap (§3.6); wrap `reason()` in try/catch with fallback score (§5.10); add `BaselineCalibrator` (§6.4); populate `DecisionTrace` (§9.7) |
| `ids_decision.hpp`    | Add `EscalationConfig`, `RepeatTracker`, `HysteresisConfig`, `CooldownConfig` (§3.9–3.13); implement `apply_overrides()` with fixed 6-step priority order (§3.11); wrap `execute()` in try/catch; add `LearningModeConfig` (§6.13); attach `DecisionTrace` to `Alert` (§9.7) |
| `ids_correlation.hpp` | **New file**: `CorrelationEngine`, `CorrelationStore`, `CampaignState`, `CorrelationResult` (§7); implement repeat/multi-stage/distributed/slow-attack detection; `AttackPattern` list; campaign lifecycle management |
| `ids_adaptive.hpp`    | **New file**: `AdaptiveLayer`, `BaselineStore`, `ScopeBaseline` (§8); adaptive threshold/decay/gate/routing computation; freeze logic; drift detection; `AdaptationStats` |
| `ids_telemetry.hpp`   | **New file**: `Metrics`, `PipelineLevelStats`, `DriftTimeSeries`, `FaultLog`, `RoutingDebugLog`, `StageLatencyTracker`, `TelemetryExporter` (§9); `ReplayConfig`/`ReplayResult`; `TelemetryConfig`; all export methods |
| `ids.hpp`             | Replace single `l1_`/`l2_` with `StateInstanceManager` per level (§1.13); replace `ExternalMemory` with `MemoryStore`; replace single `std::mutex` with sharded pipeline (§4.3); add `CorrelationEngine` stage (§7.2); add `AdaptiveLayer` (§8.16); add `TelemetryExporter` (§9.17); add `ConfigHolder` (§6.7); expose `stats()`, `health()`, `metrics()`, `level_stats()`, `shard_stats()`, `latency_stats()`, `fault_log()`, `routing_log()`, `get_state()`, `inspect_memory()`, `dump_config()`, `save_all()`, `replay()` |
