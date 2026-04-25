# IDS Integration, Embedding & Tuning Guide

This guide covers everything from dropping the library into your project
to tuning it for your specific traffic profile and threat model.

---

# Part 1 — Integration

## 1.1 Adding to Your Project

The core engine is header-only. Copy the `include/` folder into your
project and add it to your include path.

**CMake (recommended):**

```cmake
add_library(ids INTERFACE)
target_include_directories(ids INTERFACE path/to/include)
target_link_libraries(ids INTERFACE Threads::Threads)

target_link_libraries(your_target PRIVATE ids)
```

**Manual compile:**

```bash
g++ -std=c++17 -O2 -Iinclude your_app.cpp -lpthread -o your_app
```

No `.cpp` files to compile for the core. Only `ids_example.cpp` and
`ids_visualizer.cpp` are standalone binaries.

## 1.2 Minimal Integration (Single Pipeline)

```cpp
#include "ids.hpp"

ids::IDSConfig cfg;
ids::IDS pipeline(cfg);   // all defaults — works out of the box

pipeline.on_alert([](const ids::Alert& a) {
    // fires for Alert, Block, and Escalate decisions
    std::cout << a.decision << " " << a.source
              << " conf=" << a.confidence << "\n";
});

pipeline.on_block([](const std::string& src) {
    firewall_block(src);   // your firewall call here
});

pipeline.on_escalate([](const ids::Alert& a) {
    page_soc(a);           // your SOC notification here
});

// Feed events — call from any thread (mutex-protected internally)
pipeline.ingest(ev);
```

That is the entire integration surface. Everything else is optional tuning.

## 1.3 Building an Event from Your Data

`ids::Event` is the only input type. Map your data source to it:

```cpp
ids::Event ev;
ev.source      = "192.168.1.100";   // source IP or user identifier
ev.destination = "10.0.0.1";        // destination host
ev.type        = ids::EventType::NetworkPacket;
ev.time        = std::chrono::steady_clock::now();

// Payload features — fill what you have, leave the rest at 0
ev.payload.bytes_in  = pkt_len;
ev.payload.bytes_out = 0;
ev.payload.port_src  = src_port;
ev.payload.port_dst  = dst_port;
ev.payload.protocol  = ip_proto;   // 6=TCP, 17=UDP, 1=ICMP
ev.payload.flags     = tcp_flags;
ev.payload.entropy   = shannon_entropy;   // 0.0–1.0
ev.payload.rate_hz   = packets_per_sec;

// Optional metadata — used for scoped memory and state isolation
ev.metadata["user"]        = "alice";
ev.metadata["session"]     = "sess-abc123";
ev.metadata["proc"]        = "nginx";
ev.metadata["session_end"] = "1";   // triggers L1 flush + memory cleanup
```

**EventType values:**

| Value | Use for |
|-------|---------|
| `NetworkPacket` | Raw IP/TCP/UDP packets |
| `AuthEvent` | Login attempts, sudo, SSH |
| `SysLog` | Syslog / journald entries |
| `ProcessEvent` | Process create/kill/exec |
| `FileAccess` | File open/read/write/delete |
| `ApiCall` | HTTP API requests |
| `Signal` | Internal pipeline signals |

## 1.4 Live Packet Capture (libpcap bridge)

If you want to feed raw network packets directly, use `ids_capture.hpp`:

```cpp
#include "ids_capture.hpp"

ids::IDS pipeline(cfg);

ids::PacketCapture cap("eth0", "ip");   // interface, BPF filter
cap.on_event([&](const ids::Event& ev) {
    pipeline.ingest(ev);
});

cap.start();   // starts background capture thread
// ... your main loop ...
cap.stop();

// Stats
auto s = cap.stats().snapshot();
std::cout << "captured=" << s.packets_captured
          << " dropped="  << s.packets_dropped << "\n";
```

The capture thread parses Ethernet → IPv4 → TCP/UDP headers and computes
Shannon entropy from the first 256 payload bytes automatically.

**BPF filter examples:**

```bash
"ip"                              # all IPv4
"tcp port 80 or tcp port 443"     # HTTP/HTTPS only
"not tcp port 22"                 # exclude SSH
"host 192.168.1.100"              # single host
"tcp[tcpflags] & tcp-syn != 0"    # SYN packets only (scan detection)
""                                # everything including ARP, ICMP
```

Requires root or `CAP_NET_RAW`. See `VISUALIZER_SETUP.md` for the
capability approach to run without root.

## 1.5 Production: Sharded Multi-Core Pipeline

For high-throughput environments (>100k events/sec), use `ShardedIDS`.
Each shard is an independent pipeline on its own thread — no shared state
between shards, no lock contention on the hot path.

```cpp
#include "ids_sharded.hpp"

ids::IDSConfig cfg;
cfg.sharding.hash_key             = "ip";      // route by source IP
cfg.queue.queue_depth             = 4096;
cfg.backpressure.policy           = ids::BackpressurePolicy::Priority;
cfg.backpressure.priority_keep_above = 0.60f;  // drop low-anomaly under load
cfg.watchdog.heartbeat_interval_s = 1.0f;
cfg.watchdog.max_missed_beats     = 3;
cfg.watchdog.auto_restart         = true;

ids::ShardedIDS ids_sys(cfg, 8);   // 8 shards = 8 CPU cores

ids_sys.on_alert   ([](const ids::Alert& a)      { /* ... */ });
ids_sys.on_block   ([](const std::string& src)   { /* ... */ });
ids_sys.on_escalate([](const ids::Alert& a)      { /* ... */ });

ids_sys.start();
ids_sys.ingest(ev);    // thread-safe, lock-free hash-route
ids_sys.shutdown();    // drain + join all threads
```

**Routing key options:**

| `hash_key` | Routes by | Best for |
|------------|-----------|----------|
| `"ip"` | `ev.source` | Network monitoring |
| `"session"` | `ev.metadata["session"]` | Web/API traffic |
| `"user"` | `ev.metadata["user"]` | Auth/identity monitoring |

The same entity always hits the same shard — this is the state ownership
guarantee. Never route the same IP to two different shards.

## 1.6 Integrating with a SIEM

Every `Alert` carries a `DecisionTrace` with the full signal breakdown.
Serialize it to JSON and push to your SIEM:

```cpp
pipeline.on_alert([](const ids::Alert& a) {
    const auto& t = a.trace;
    nlohmann::json j;
    j["source"]           = a.source;
    j["destination"]      = a.destination;
    j["decision"]         = static_cast<int>(a.decision);
    j["confidence"]       = a.confidence;
    j["attack_class"]     = a.attack_class;
    j["campaign_id"]      = t.campaign_id;
    j["correlation_type"] = t.correlation_type;
    j["local_score"]      = t.local_score;
    j["segment_trend"]    = t.segment_trend;
    j["drift_score"]      = t.drift_score;
    j["gate_score"]       = t.gate_score;
    j["fused_score"]      = t.fused_score;
    j["rule_matched"]     = t.rule_matched;
    j["forced"]           = t.forced;
    siem_client.send(j.dump());
});
```

All alerts from the same campaign share the same `campaign_id` string,
so your SIEM can group them automatically.

## 1.7 Integrating with a Firewall

The `on_block` callback receives the source string (IP or user) that
triggered the block decision. Wire it directly to your firewall API:

```cpp
pipeline.on_block([](const std::string& src) {
    // iptables
    system(("iptables -A INPUT -s " + src + " -j DROP").c_str());

    // or your SDK
    firewall_sdk.block_ip(src, std::chrono::minutes(30));
});
```

For temporary blocks, use the cooldown config to control how long a
source stays blocked before the pipeline re-evaluates it:

```cpp
cfg.cooldown.block_cooldown_s = 300.f;   // 5 minutes between block decisions
cfg.cooldown.allow_stronger   = true;    // Escalate still fires during cooldown
```

---

# Part 2 — Tuning

Tuning has three phases: calibration, threshold adjustment, and
signal weight adjustment. Do them in order.

## 2.1 Phase 1 — Calibration (Always Do This First)

Never deploy with default thresholds on unknown traffic. Run the
`BaselineCalibrator` on a sample of normal traffic first.

```cpp
ids::IDSConfig cfg;
cfg.learning.enabled          = true;
cfg.learning.disable_blocking = true;   // observe only, no blocks
cfg.learning.log_only         = true;
cfg.learning.duration_s       = 3600.f; // 1 hour observation window

ids::IDS pipeline(cfg);
ids::BaselineCalibrator cal;

pipeline.on_alert([&](const ids::Alert& a) {
    // During learning mode these are observations, not real alerts
    auto state = pipeline.segment_state();
    // cal.observe() called below in the ingest loop
});

for (const auto& ev : your_normal_traffic) {
    auto state = pipeline.ingest(ev);
    cal.observe(state.local, state.segment);
}

// Get calibrated thresholds targeting 1% false-positive rate
auto s = cal.compute(0.01f);

// Apply to a new config
cfg.learning.enabled           = false;
cfg.gate.gate_threshold        = s.gate_threshold;
cfg.thresholds.alert_threshold = s.alert_threshold;
cfg.thresholds.block_threshold = s.block_threshold;
cfg.routing.flush.flush_anomaly= s.flush_anomaly;
```

The calibrator observes the distribution of `anomaly_score` and
`anomaly_trend` values and sets thresholds at the 99th percentile of
normal traffic. This is the single most impactful tuning step.

## 2.2 Phase 2 — Decision Thresholds

All four decision boundaries are in `DecisionThresholds`. They must
satisfy: `ignore < log < alert < block`.

```cpp
cfg.thresholds.ignore_threshold = 0.15f;  // below this: silent
cfg.thresholds.log_threshold    = 0.35f;  // log but no alert
cfg.thresholds.alert_threshold  = 0.55f;  // notify SOC
cfg.thresholds.block_threshold  = 0.80f;  // block + notify
```

**Tuning direction:**

| Symptom | Fix |
|---------|-----|
| Too many false positives | Raise `alert_threshold` by 0.05 at a time |
| Missing real attacks | Lower `alert_threshold` |
| Blocks firing too early | Raise `block_threshold` |
| Attacks not escalating | Lower `escalation.escalate_hist` |
| Too many escalations | Raise `escalation.escalate_hist` |

**Escalation conditions** — upgrade Alert/Block to Escalate when any of:

```cpp
cfg.escalation.escalate_hist     = 0.75f;  // global anomaly history
cfg.escalation.escalate_drift    = 8.0f;   // baseline drift score
cfg.escalation.repeat_escalate_n = 3;      // same source alerted N times
cfg.escalation.repeat_window_s   = 300.f;  // within this window (seconds)
```

## 2.3 Phase 3 — Gate & Fusion Weights

The reasoning gate decides whether to run the expensive attention model.
The fusion weights control how signals combine into the final score.

**Gate weights** (must sum to ~1.0, but not enforced):

```cpp
cfg.gate.gate_threshold = 0.35f;   // run reasoning above this gate score

cfg.gate.weights.w_local     = 0.35f;  // per-event anomaly score (most responsive)
cfg.gate.weights.w_segment   = 0.25f;  // segment trend (smoothed)
cfg.gate.weights.w_history   = 0.15f;  // global anomaly history
cfg.gate.weights.w_drift     = 0.10f;  // baseline drift
cfg.gate.weights.w_retrieval = 0.10f;  // similarity to past attacks
cfg.gate.weights.w_rule      = 0.05f;  // rule match bonus
```

**Fusion weights** (combine signals into the final confidence score):

```cpp
cfg.fusion.w_local     = 0.50f;
cfg.fusion.w_segment   = 0.25f;
cfg.fusion.w_history   = 0.15f;
cfg.fusion.w_drift     = 0.10f;
cfg.fusion.w_retrieval = 0.15f;  // boost when retrieved record scores > 0.8
cfg.fusion.w_rule      = 0.10f;  // boost when any rule matched
```

**Tuning direction:**

| Environment | Adjustment |
|-------------|------------|
| High-volume noisy network | Raise `w_segment`, lower `w_local` |
| APT / slow-burn focus | Raise `w_history`, raise `w_drift` |
| Signature-heavy deployment | Raise `w_rule` |
| Low memory / few past records | Lower `w_retrieval` |
| Real-time burst detection | Raise `w_local`, lower `gate_threshold` |

## 2.4 Tuning the Hierarchy Routing

The SSM hierarchy controls how fast anomalies propagate from per-event
(L0) up to global state (L2l). These are the most impactful routing knobs.

**L1 flush rules** — when does a segment flush to L2:

```cpp
cfg.routing.flush.flush_n              = 100;    // flush after N events
cfg.routing.flush.flush_t              = 10.f;   // flush after T seconds
cfg.routing.flush.flush_anomaly        = 0.70f;  // early flush on anomaly spike
cfg.routing.flush.flush_on_session_end = true;
cfg.routing.flush.flush_on_type_change = true;
```

Lower `flush_anomaly` to detect bursts faster (more CPU). Raise it to
reduce noise promotion.

**Promotion rules** — when does state move up the hierarchy:

```cpp
// L1 → L2s (short-term per-IP)
cfg.routing.promote_l1_l2s.promote_on_flush  = true;   // always promote on flush
cfg.routing.promote_l1_l2s.promote_threshold = 0.50f;  // or when trend > this

// L2s → L2m (mid-term per-host)
cfg.routing.promote_l2s_l2m.mid_tick    = 10;     // every 10 segments
cfg.routing.promote_l2s_l2m.mid_anomaly = 0.55f;  // or anomaly history > this
cfg.routing.promote_l2s_l2m.mid_drift   = 3.0f;   // or drift > this

// L2m → L2l (global)
cfg.routing.promote_l2m_l2l.global_tick  = 60;
cfg.routing.promote_l2m_l2l.global_drift = 8.0f;
cfg.routing.promote_l2m_l2l.global_hist  = 0.70f;
```

**Skip rules** — suppress noise from reaching higher levels:

```cpp
cfg.routing.skip.skip_threshold = 0.20f;  // skip L1→L2s if trend below this
cfg.routing.skip.min_segments   = 3;      // and fewer than N segments seen
cfg.routing.skip.skip_drift     = 1.0f;
```

Raise `skip_threshold` in noisy environments to keep global state clean.
Lower it if you're missing slow-burn attacks.

**Force rules** — bypass all tick counters on critical events:

```cpp
cfg.routing.force.force_anomaly  = 0.90f;  // force all levels on spike
cfg.routing.force.force_on_block = true;   // force on Block decision
```

## 2.5 Tuning Memory

Memory controls what context the reasoning model sees when making decisions.

```cpp
// Write gate — minimum score to store an event
cfg.write_policy.memory_write_gate   = 0.50f;
cfg.write_policy.memory_force_gate   = 0.85f;  // also writes to global store
cfg.write_policy.write_on_rule_match = true;
cfg.write_policy.write_on_block      = true;

// Partition sizes — tune to your RAM budget
cfg.eviction.max_global_records  = 100000;
cfg.eviction.max_ip_records      = 5000;
cfg.eviction.max_host_records    = 10000;
cfg.eviction.max_session_records = 1000;

// Retrieval time window
cfg.retrieval_time.retrieval_max_age_s = 3600.f;  // ignore records older than 1h
cfg.retrieval_time.recency_tau         = 600.f;   // recency half-life ~10 min
```

Lower `memory_write_gate` to store more context (better recall, more RAM).
Raise it to keep only high-confidence events (less RAM, faster retrieval).

## 2.6 Tuning the Adaptive Baseline

The adaptive layer maintains per-scope EMA baselines and can
auto-adjust thresholds as traffic patterns change.

```cpp
// How aggressively thresholds adapt (k = standard deviations above mean)
cfg.adaptive_threshold.k_alert  = 3.0f;   // alert = mean + 3σ
cfg.adaptive_threshold.k_block  = 5.0f;   // block = mean + 5σ
cfg.adaptive_threshold.k_gate   = 2.0f;

// Clamp adapted thresholds to sane range
cfg.adaptive_threshold.min_alert_threshold = 0.30f;
cfg.adaptive_threshold.max_alert_threshold = 0.90f;

// Freeze baseline during attacks (prevents attack traffic from shifting normal)
// Freeze fires automatically when anomaly_score >= 0.70
// No config needed — it's automatic
```

The baseline freezes automatically when `anomaly_score >= 0.70` for a
given scope. This prevents an ongoing attack from shifting what the
system considers "normal" for that IP or host.

## 2.7 Tuning Correlation

```cpp
// Repeat detection — escalate after N alerts from same source
cfg.escalation.repeat_escalate_n = 3;
cfg.escalation.repeat_window_s   = 300.f;  // within 5 minutes

// Distributed attack — N unique sources hitting same host
cfg.distributed.unique_source_threshold = 5;
cfg.distributed.dist_window_s           = 60.f;

// Slow attack / APT — N low-score events over a long window
cfg.slow_attack.slow_window_s        = 3600.f;  // 1 hour
cfg.slow_attack.slow_event_threshold = 10;
cfg.slow_attack.slow_score_threshold = 0.30f;   // each scoring >= 0.30

// Correlation score contribution weights
cfg.correlation.weights.repeat_weight   = 0.20f;
cfg.correlation.weights.stage_weight    = 0.30f;
cfg.correlation.weights.dist_weight     = 0.25f;
cfg.correlation.weights.slow_weight     = 0.15f;
cfg.correlation.weights.campaign_weight = 0.10f;
```

## 2.8 Stability Controls

Prevent rapid oscillation and alert storms:

```cpp
// Hysteresis — once Block fires, keep it for hold_time even if score dips
cfg.hysteresis.decision_hysteresis  = 0.05f;  // score margin
cfg.hysteresis.decision_hold_time_s = 10.f;   // hold for 10 seconds

// Cooldown — suppress repeated alerts from same source
cfg.cooldown.alert_cooldown_s = 5.f;    // 5s between Alert decisions
cfg.cooldown.block_cooldown_s = 30.f;   // 30s between Block decisions
cfg.cooldown.allow_stronger   = true;   // Escalate always fires regardless
```

---

# Part 3 — Customisation

## 3.1 Adding Rules

Rules are the fastest path to detecting known patterns. They match on
anomaly score threshold and/or source IP pattern.

```cpp
// Rule struct: { id, name, pattern, threshold, action }
pipeline.add_rule({1, "PortScan",        "",            0.60f, ids::Decision::Alert});
pipeline.add_rule({2, "KnownBadIP",      "10.0.0.99",   0.00f, ids::Decision::Block});
pipeline.add_rule({3, "InternalScanner", "192.168.0.",  0.40f, ids::Decision::Log});
pipeline.add_rule({4, "CriticalHost",    "10.0.0.1",    0.30f, ids::Decision::Alert});
```

- `pattern` is a substring match on `ev.source`. Empty string matches all.
- `threshold` is the minimum `anomaly_score` to trigger the rule.
- `action` sets the minimum decision when the rule fires (can be upgraded
  by the reasoning model but not downgraded).

**Remove or disable a rule at runtime:**

```cpp
pipeline.add_rule({5, "TempBlock", "172.16.0.1", 0.0f, ids::Decision::Block});
// later...
// Rules are matched by id — to remove, replace the full rule table:
auto rules = pipeline.memory_rules();   // get current rules
rules.erase(std::remove_if(...), rules.end());
pipeline.memory_.rules.replace(rules);
```

For `ShardedIDS`, `add_rule()` broadcasts to all shards automatically.

## 3.2 Adding Attack Signatures

Signatures are embedding vectors that represent known attack patterns.
When a new event's embedding is similar to a stored signature, the
retrieval score boosts the reasoning confidence.

```cpp
// Create a signature embedding (64-float vector)
ids::Vec dos_sig{};
dos_sig[0] = 1.0f;   // high bytes_in
dos_sig[9] = 1.0f;   // high burst_metric

pipeline.load_signature(dos_sig, "DoS-signature", 1.0f);

// Multiple signatures
ids::Vec brute_sig{};
brute_sig[8] = 1.0f;   // AuthEvent type
brute_sig[7] = 0.9f;   // high rate_hz
pipeline.load_signature(brute_sig, "BruteForce-signature", 0.9f);
```

Signatures go into `global_store` and are retrieved for every event.
The third argument is the anomaly score stored with the record — use
1.0 for confirmed attack patterns.

In production, generate signature embeddings by running known attack
traffic through `LocalAnalyzer::process()` and capturing the
`ls.embedding` output.

## 3.3 Adding Custom Multi-Stage Attack Patterns

The correlation engine has built-in patterns for lateral movement and
APT exfiltration. Add your own:

```cpp
ids::AttackPattern ransomware_chain;
ransomware_chain.name     = "RansomwareChain";
ransomware_chain.sequence = {
    "FileSystemAnomaly/Ransomware",   // stage 1: file encryption starts
    "EncryptedC2/Exfiltration",       // stage 2: data exfil
    "DoS/DDoS"                        // stage 3: cover tracks / distraction
};
ransomware_chain.max_gap_s = 1800.f;  // stages must occur within 30 minutes

cfg.multi_stage.patterns.push_back(ransomware_chain);
cfg.multi_stage.enabled = true;
```

The sequence is matched in order against the `attack_class` labels
produced by the reasoning model. Stages can have gaps up to `max_gap_s`
between them.

## 3.4 Customising Allow and Block Lists

```cpp
// Hard allow — these sources never trigger reasoning or alerts
cfg.policy.allow_list = {
    "127.0.0.1",
    "10.0.0.254",    // monitoring agent
    "scanner.internal"
};

// Hard block — these sources always get Decision::Block regardless of score
cfg.policy.block_list = {
    "10.0.0.99",
    "185.220.",      // known Tor exit range prefix
};
```

Allow list is checked first. A source on both lists is allowed (allow
takes priority). Lists use substring matching on `ev.source`.

## 3.5 Per-Source State Isolation

By default, every new source IP gets its own `SegmentSSM` instance.
Control what triggers a new instance:

```cpp
cfg.routing.split.split_on_new_ip       = true;   // new IP → new L1 instance
cfg.routing.split.split_on_new_session  = true;   // new session ID → new L1
cfg.routing.split.split_on_new_user     = true;   // new user → new L1
cfg.routing.split.split_on_proto_change = false;  // protocol change on same IP
```

Cap the number of active instances to control memory:

```cpp
cfg.state.max_l1_instances  = 10000;  // max per-IP L1 instances
cfg.state.max_l2s_instances = 5000;
cfg.state.max_l2m_instances = 1000;

// Idle timeout — expire instances that haven't seen traffic
cfg.state.idle_timeout_s   = 300.f;   // 5 minutes idle → Idle phase
cfg.state.expire_timeout_s = 3600.f;  // 1 hour idle → Expired, memory freed
```

## 3.6 Hot-Reloading Config at Runtime

Change thresholds, weights, and routing config without restarting:

```cpp
// Get a copy of the current config
auto new_cfg = std::make_shared<ids::IDSConfig>(current_cfg);

// Modify what you need
new_cfg->thresholds.alert_threshold = 0.65f;
new_cfg->gate.gate_threshold        = 0.40f;

// Validate and apply atomically
std::string reason;
if (!pipeline.hot_reload_config(new_cfg, &reason)) {
    std::cerr << "Config rejected: " << reason << "\n";
}

// Roll back to previous config if the new one causes problems
pipeline.rollback_config(1);
```

What can be hot-reloaded:
- All `DecisionThresholds`
- All `GateWeights` and `ScoreFusionWeights`
- `WritePolicy`, `RoutingConfig`, `EscalationConfig`
- `CooldownConfig`, `HysteresisConfig`

What requires a restart (SSM matrix parameters):
- `SegmentSSM` A/B/C/D matrices
- Use `stage_model()` + `apply_model()` for those (see section 3.7)

## 3.7 Updating the SSM Model Parameters

To deploy a retrained model without downtime:

```cpp
// Stage the new model (validates, does not affect running pipeline)
if (!pipeline.stage_model("/models/ids_v3.bin")) {
    std::cerr << "Staging failed: " << pipeline.model_error() << "\n";
    return;
}

// Check what was staged
const auto& ver = pipeline.model_version();
std::cout << "staged: " << ver.model_version << "\n";

// Apply atomically — resets all SSM state, installs new params
pipeline.apply_model();

// If the new model behaves badly, roll back
pipeline.rollback_model(1);
```

`apply_model()` resets all L1 and L2 SSM state. The pipeline continues
processing immediately with the new parameters. Memory, rules, and
signatures are unaffected.

## 3.8 Fault Tolerance Tuning

```cpp
// Panic mode — enter degraded (rule-only) mode after N faults
cfg.panic.panic_threshold      = 100;   // faults before panic
cfg.panic.panic_window_s       = 60.f;  // re-evaluate after 60s
cfg.panic.disable_reasoning    = true;  // skip ML in panic mode
cfg.panic.rules_only           = true;  // rules still fire in panic mode

// SSM numeric safety
cfg.state.max_energy  = 100.f;   // clamp SSM state energy above this
cfg.state.clamp_limit = 10.f;    // clamp individual state elements to ±this

// State decay (controls how fast SSM state fades without new events)
cfg.state.decay_l1  = 0.95f;   // L1 fades fastest
cfg.state.decay_l2s = 0.98f;
cfg.state.decay_l2m = 0.99f;
cfg.state.decay_l2l = 0.999f;  // global state is most persistent
```

Monitor fault health at runtime:

```cpp
const auto& h = pipeline.health();
if (h.panic_mode) {
    alert_ops("IDS in panic mode — ML disabled, rules only");
}
if (h.numeric_faults.load() > 10) {
    alert_ops("SSM numeric instability detected");
}
```

---

# Part 4 — Environment-Specific Recipes

## 4.1 High-Volume Network Tap (>100k pps)

```cpp
ids::IDSConfig cfg;

// 16 shards for high core count
ids::ShardedIDS ids_sys(cfg, 16);

// Priority backpressure — drop low-anomaly events under load
cfg.backpressure.policy              = ids::BackpressurePolicy::Priority;
cfg.backpressure.priority_keep_above = 0.50f;
cfg.queue.queue_depth                = 8192;

// Raise gate threshold — only run reasoning on clear anomalies
cfg.gate.gate_threshold = 0.45f;

// Raise write gate — only store high-confidence events
cfg.write_policy.memory_write_gate = 0.65f;

// Smaller memory partitions to control RAM
cfg.eviction.max_ip_records     = 2000;
cfg.eviction.max_global_records = 50000;

// Faster flush for burst detection
cfg.routing.flush.flush_n       = 50;
cfg.routing.flush.flush_anomaly = 0.60f;
```

## 4.2 Low-Volume Internal Network (SOC / SIEM Feed)

```cpp
// Single pipeline is fine
ids::IDSConfig cfg;

// Lower thresholds — catch more, false positives acceptable
cfg.gate.gate_threshold        = 0.25f;
cfg.thresholds.alert_threshold = 0.40f;
cfg.thresholds.block_threshold = 0.70f;

// Store more context
cfg.write_policy.memory_write_gate = 0.30f;
cfg.eviction.max_ip_records        = 10000;
cfg.retrieval_time.retrieval_max_age_s = 7200.f;  // 2 hour window

// Aggressive APT detection
cfg.slow_attack.slow_window_s        = 7200.f;
cfg.slow_attack.slow_event_threshold = 5;
cfg.slow_attack.slow_score_threshold = 0.20f;

// Full telemetry for SOC review
cfg.telemetry.routing_debug  = true;
cfg.telemetry.decision_trace = true;
cfg.telemetry.drift_series   = true;
```

## 4.3 Auth / Identity Monitoring

```cpp
ids::IDSConfig cfg;
cfg.sharding.hash_key = "user";   // route by user, not IP

// Auth events dominate — tune fusion toward segment trend
cfg.fusion.w_local   = 0.30f;
cfg.fusion.w_segment = 0.40f;   // segment captures repeated failures
cfg.fusion.w_rule    = 0.15f;

// Aggressive repeat escalation for brute force
cfg.escalation.repeat_escalate_n = 3;
cfg.escalation.repeat_window_s   = 60.f;   // 3 failures in 60s → escalate

// Session-based state isolation
cfg.routing.split.split_on_new_session = true;
cfg.routing.split.split_on_new_user    = true;
```

## 4.4 API Gateway / Web Traffic

```cpp
ids::IDSConfig cfg;
cfg.sharding.hash_key = "session";

// API calls have high rate — normalise rate_hz expectation
cfg.routing.flush.flush_n = 200;   // larger window before flush
cfg.routing.flush.flush_t = 5.f;   // but flush every 5s regardless

// Raise skip threshold — API traffic is noisy
cfg.routing.skip.skip_threshold = 0.30f;
cfg.routing.skip.min_segments   = 5;

// Focus on exfiltration patterns
cfg.fusion.w_history   = 0.20f;
cfg.fusion.w_retrieval = 0.20f;
```

---

# Part 5 — Observability & Debugging

## 5.1 Checking What the Pipeline Is Doing

```cpp
// Overall metrics
const auto& m = pipeline.metrics();
std::cout << "events="     << m.events_total.load()
          << " alerts="    << m.alerts_total.load()
          << " reasoning=" << m.reasoning_calls.load()
          << " faults="    << m.faults_total.load() << "\n";

// Per-stage latency
auto lat = pipeline.latency_stats();
std::cout << "l0="        << lat.l0_avg_us << "µs"
          << " retrieval=" << lat.retrieval_avg_us << "µs"
          << " reasoning=" << lat.reasoning_avg_us << "µs"
          << " total="     << lat.total_avg_us << "µs\n";

// Global state
auto gs = pipeline.global_state();
std::cout << "drift="   << gs.drift_score
          << " history=" << gs.anomaly_history << "\n";

// Active campaigns
for (const auto& c : pipeline.active_campaigns())
    std::cout << "[" << c.id << "] " << c.attack_class
              << " events=" << c.event_count
              << " sources=" << c.sources.size() << "\n";
```

## 5.2 Diagnosing False Positives

Enable `decision_trace` and inspect the breakdown on every alert:

```cpp
cfg.telemetry.decision_trace = true;

pipeline.on_alert([](const ids::Alert& a) {
    const auto& t = a.trace;
    // Which signal is driving the score?
    std::cout << "local="     << t.local_score
              << " segment="  << t.segment_trend
              << " history="  << t.anomaly_history
              << " drift="    << t.drift_score
              << " retrieval="<< t.retrieval_similarity_max
              << " rule="     << t.rule_matched
              << " gate="     << t.gate_score
              << " fused="    << t.fused_score
              << " forced="   << t.forced
              << "\n";
});
```

If `local_score` is high but `segment_trend` and `history` are low,
the event is a one-off spike — raise `gate.weights.w_local` down or
raise `thresholds.alert_threshold`.

If `rule_matched=true` is causing false positives, disable the specific
rule: `pipeline.memory_.rules.set_enabled(rule_id, false)`.

## 5.3 Diagnosing Missed Detections

Enable routing debug to see why events are being skipped:

```cpp
cfg.telemetry.routing_debug = true;

auto log = pipeline.routing_log(100);
for (const auto& e : log) {
    if (e.event == ids::RoutingEvent::Skip)
        std::cout << "SKIP " << e.key.ip
                  << " reason=" << e.reason << "\n";
}
```

Common causes of missed detections:

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Events skipped at L1→L2s | `skip_threshold` too high | Lower `routing.skip.skip_threshold` |
| Reasoning never runs | `gate_threshold` too high | Lower `gate.gate_threshold` |
| Score too low to alert | Fusion weights off | Raise `fusion.w_local` or `fusion.w_rule` |
| Slow attack not detected | `slow_window_s` too short | Raise `slow_attack.slow_window_s` |
| Campaign not forming | Score below 0.4 | Lower `slow_attack.slow_score_threshold` |

## 5.4 Monitoring Shard Health (ShardedIDS)

```cpp
for (const auto& ss : ids_sys.shard_stats()) {
    std::cout << "shard=" << ss.shard_id
              << " queue=" << ss.queue_depth
              << " drops=" << ss.drops
              << " latency=" << ss.avg_latency_us << "µs"
              << " states=" << ss.active_states
              << " saturated=" << ss.reasoning_pool_saturated << "\n";
}

std::cout << "watchdog_restarts=" << ids_sys.watchdog_restarts() << "\n";
```

If `reasoning_pool_saturated=true` on a shard (>80% of events hitting
reasoning), raise `gate.gate_threshold` or add more shards.

If `drops` is growing, either add shards, raise `queue_depth`, or
lower `backpressure.priority_keep_above` to drop more low-value events.

---

# Part 6 — Config Field Quick Reference

Every tunable field in one place. All live in `IDSConfig`.

## Decision & Gate

| Field | Default | Effect |
|-------|---------|--------|
| `gate.gate_threshold` | 0.35 | Minimum gate score to run reasoning |
| `gate.weights.w_local` | 0.35 | Weight of per-event anomaly score in gate |
| `gate.weights.w_segment` | 0.25 | Weight of segment trend in gate |
| `gate.weights.w_history` | 0.15 | Weight of global anomaly history in gate |
| `gate.weights.w_drift` | 0.10 | Weight of drift score in gate |
| `gate.weights.w_retrieval` | 0.10 | Weight of retrieval similarity in gate |
| `gate.weights.w_rule` | 0.05 | Weight of rule match in gate |
| `thresholds.ignore_threshold` | 0.20 | Below this: silent |
| `thresholds.log_threshold` | 0.40 | Log only |
| `thresholds.alert_threshold` | 0.60 | Alert callback fires |
| `thresholds.block_threshold` | 0.85 | Block callback fires |
| `fusion.w_local` | 0.50 | Local score weight in fusion |
| `fusion.w_segment` | 0.25 | Segment trend weight in fusion |
| `fusion.w_history` | 0.15 | History weight in fusion |
| `fusion.w_drift` | 0.10 | Drift weight in fusion |
| `fusion.w_retrieval` | 0.15 | Retrieval boost weight |
| `fusion.w_rule` | 0.10 | Rule match boost weight |

## Escalation & Stability

| Field | Default | Effect |
|-------|---------|--------|
| `escalation.escalate_hist` | 0.75 | Escalate when anomaly_history >= this |
| `escalation.escalate_drift` | 8.0 | Escalate when drift_score >= this |
| `escalation.repeat_escalate_n` | 3 | Escalate after N alerts from same source |
| `escalation.repeat_window_s` | 300 | Repeat window in seconds |
| `hysteresis.decision_hysteresis` | 0.05 | Score margin to hold last decision |
| `hysteresis.decision_hold_time_s` | 10 | Seconds to hold last decision |
| `cooldown.alert_cooldown_s` | 5 | Seconds between Alert decisions per source |
| `cooldown.block_cooldown_s` | 30 | Seconds between Block decisions per source |

## Routing

| Field | Default | Effect |
|-------|---------|--------|
| `routing.flush.flush_n` | 100 | Flush L1 after N events |
| `routing.flush.flush_t` | 10.0 | Flush L1 after T seconds |
| `routing.flush.flush_anomaly` | 0.70 | Early flush when trend > this |
| `routing.skip.skip_threshold` | 0.20 | Skip L1→L2s when trend below this |
| `routing.skip.min_segments` | 3 | And fewer than N segments seen |
| `routing.force.force_anomaly` | 0.90 | Force all levels when score > this |
| `routing.promote_l2s_l2m.mid_tick` | 10 | L2s→L2m every N segments |
| `routing.promote_l2m_l2l.global_tick` | 60 | L2m→L2l every N segments |

## Memory

| Field | Default | Effect |
|-------|---------|--------|
| `write_policy.memory_write_gate` | 0.50 | Min score to write to memory |
| `write_policy.memory_force_gate` | 0.85 | Also write to global store |
| `eviction.max_global_records` | 100000 | Global store size cap |
| `eviction.max_ip_records` | 5000 | Per-IP store size cap |
| `retrieval_time.retrieval_max_age_s` | 3600 | Ignore records older than this |
| `retrieval_time.recency_tau` | 600 | Recency decay half-life (seconds) |

## Fault Tolerance

| Field | Default | Effect |
|-------|---------|--------|
| `panic.panic_threshold` | 100 | Faults before entering panic mode |
| `panic.panic_window_s` | 60 | Re-evaluate panic exit after this |
| `state.max_energy` | 100 | SSM state energy clamp |
| `state.decay_l1` | 0.95 | L1 state decay per step |
| `state.idle_timeout_s` | 300 | Seconds idle before state → Idle |
| `state.expire_timeout_s` | 3600 | Seconds idle before state freed |

## Concurrency

| Field | Default | Effect |
|-------|---------|--------|
| `sharding.hash_key` | "ip" | Route key: "ip", "session", "user" |
| `queue.queue_depth` | 4096 | Per-shard queue capacity |
| `backpressure.policy` | Priority | Drop / Priority / Block / Sample |
| `backpressure.priority_keep_above` | 0.60 | Keep events above this score under load |
| `watchdog.heartbeat_interval_s` | 1.0 | Watchdog check interval |
| `watchdog.max_missed_beats` | 3 | Missed beats before shard restart |
 