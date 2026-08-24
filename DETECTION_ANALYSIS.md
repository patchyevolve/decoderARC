# decoderARC — Detection System Analysis

## Verdict: Detection is REAL, but Validation is ABSENT

The detection engine contains **genuine algorithmic logic** at every layer — no stubs, no placeholders, no TODOs. However, the system has **zero automated tests, zero assertions, and no end-to-end validation**. The detection works; it has never been proven to work.

---

## 1. Detection Engine — What's Real

### L0 LocalAnalyzer (`include/ids_level0.hpp`)

| Algorithm | Lines | What It Does |
|-----------|-------|-------------|
| Welford's online variance | 112-118 | Running mean + variance for anomaly scoring |
| Z-score computation | 120-128 | `|x - mean| / sigma` across 6 features, L2-norm + max-Z |
| Shannon entropy | 149-160 | `-sum(p * log2(p))` on protocol field |
| Burst coefficient of variation | 162-178 | `std_dev / mean` of inter-arrival times |
| SYN flood detection | 132-133 | `syn_count > 5 && ack_count < syn_count/2` → +0.4 boost |
| Small-packet DoS | 134-135 | `packets > 100 && size_mean < 100` → +0.3 boost |
| Burst detection | 136-137 | `iat_mean < 0.001 && packets > 50` → +0.3 boost |
| Asymmetric traffic | 138-139 | `down_up_ratio > 5 && bytes_bwd > 3*bytes_fwd` → +0.3 boost |
| Irregular timing scan | 140-141 | `iat_std > 3 * iat_mean` → +0.25 boost |
| FIN scan | 142-143 | `fin_count > 2*syn_count && syn_count > 3` → +0.3 boost |

**Embedding**: 40-dimensional feature vector from normalized payload features, flow stats, hash-encoded source/destination, and rolling statistics.

### L1 SegmentSSM (`include/ids_level1.hpp`)

- Per-IP segment accumulation with 5 flush conditions: count threshold, anomaly threshold, time window, session boundary, type change
- Calls SSM forward pass on each event
- Extracts segment-level statistics: anomaly trend, rate mean, error frequency, dominant type

### L2 Hierarchical SSM (`include/ids_ssm.hpp`)

This is the core Mamba-style component. The math is real:

```
// Input-dependent step size (softplus activation)
delta[i] = log(1 + exp(d))          if d <= 20
delta[i] = d                        if d > 20

// Zero-Order Hold discretization
A_bar[i] = exp(-delta[i] * exp(A_log[i]))

// State transition (fundamental SSM recurrence)
h_t = A_bar * h_{t-1} + delta * Bx

// Output with skip connection
y = C * h + D * x
```

4-layer hierarchy: L2s → L2m → L2l → L2l-global, with signal-driven promotion rules and EMA baseline tracking (`baseline += 0.01 * (state - baseline)`).

### Memory Store (`include/ids_memory.hpp`)

| Feature | Implementation |
|---------|---------------|
| Vector search | Cosine similarity with precomputed query norm |
| Scoring | `sim * w_sim + score * w_anomaly + recency * w_time + scope_weight` |
| Recency | Exponential decay: `exp(-age / tau)` |
| Multi-scope retrieval | 5 stores (IP, user, session, host, global) with weights 1.0, 0.9, 0.85, 0.7, 0.5 |
| Write gating | Score ≥ threshold OR rule match OR block/escalate decision |
| Eviction | TTL-based + bottom-25% by score when over capacity |

### Reasoning Gate (`include/ids_reasoning.hpp`)

- **6-signal weighted fusion**: `gate = w_local*local + w_segment*trend + w_history*history + w_drift*drift + w_retrieval*similarity + w_rule*rule`
- **Single-head self-attention**: Scaled dot-product attention over token sequence (local embedding, segment state, L2 states, memory records)
- **Attack classification** (lines 169-180): Heuristic classifier mapping multi-signal patterns to attack types (DoS, BruteForce, C2, Ransomware, LateralMovement)

### Decision Engine (`include/ids_decision.hpp`)

- **Hysteresis**: Prevents flapping between Block and Alert near threshold
- **Cooldown**: Block cooldown 30s, Alert cooldown 5s, with `allow_stronger` flag
- **Escalation**: When `anomaly_history >= threshold` AND repeat/drift conditions met
- **Overrides**: Allow list → hard Ignore, Block list → hard Block

### Correlation Engine (`include/ids_correlation.hpp`)

4 independent detection algorithms:
1. **Repeat**: Same IP alerts within 60s window, threshold = 3
2. **Multi-stage**: Ordered attack pattern matching (PortScan → BruteForce → LateralMovement within 600s)
3. **Distributed**: Unique source IPs targeting same host, threshold = 5
4. **Slow**: Low-and-slow alerts over 3600s window, threshold = 10

Campaign tracking with source/attack-class matching and decision upgrade (Alert → Escalate when correlation > 0.4).

### Autoencoder (`include/ids_nn.hpp`)

- 3-layer autoencoder: 40 → 16 → 8 → 16 → 40
- Real backpropagation with MSE loss and SGD optimizer
- Anomaly score: `MSE / (3 * train_mean)`
- Online learning: single SGD step with smaller LR on benign events

---

## 2. End-to-End Data Path

```
Daemon (AF_PACKET capture)
  │  Parses Ethernet → IPv4/IPv6 → TCP/UDP
  │  Constructs ids::Event with IPs, ports, protocol, entropy, rate
  │
  ├──[Mode 1: Local inference]──→ 9-step IDS pipeline → alert → CloudUploader
  │
  └──[Mode 2: Forwarder-only]──→ POST /api/v1/ingest/events (libcurl, JSON)
                                    │
                                    ▼
                              Backend (FastAPI)
                                    │  Stores in traffic_events table
                                    │  UserRuntimeManager (4 workers)
                                    │  Hash-partitioned by user_id
                                    │
                                    ▼
                              ids_bridge.py (ctypes)
                                    │  Loads libids_central.so
                                    │  Calls ids_central_ingest_batch()
                                    │
                                    ▼
                              C API (ids_c_api.cpp)
                                    │  Creates per-user ShardedIDS (4 shards)
                                    │  Runs full IDS pipeline per event
                                    │  Returns JSON alerts
                                    │
                                    ▼
                              central_runtime.py
                                    │  Stores Alert + LogEntry in PostgreSQL
                                    │  Broadcasts via WebSocket/SSE
                                    │
                                    ▼
                              Frontend (index.html)
                                    │  Real-time alert display
                                    │  Dashboard stats, charts, tables
```

---

## 3. What's Broken or Incomplete

### Critical Issues

| Issue | Location | Impact |
|-------|----------|--------|
| **Replay mode is a stub** | `ids_production.cpp:438-456` | `--replay` ignores CSV content, creates identical synthetic events. Not a real replay. |
| **CMakeLists.txt incomplete** | `CMakeLists.txt` | No targets for `ids_production` daemon, `ids_c_api.cpp` → `libids_central.so`, or `ids_collector`. Must compile manually. |
| **Build artifacts from Windows** | `build/Makefile` | Generated by `cmd.exe` on Windows, unusable on Linux. |
| **C API batch attribution bug** | `ids_c_api.cpp:271-275` | When draining batch alerts, always uses `src_ips[0]`/`src_ports[0]` from first event, not the triggering event. Cosmetic but incorrect. |
| **Health endpoint hardcoded uptime** | `ids_production.cpp:152` | Returns `"uptime":0` always, never tracked. |
| **Prometheus metrics hardcoded** | `ids_production.cpp:173-194` | Some metric values appear static/hardcoded rather than live. |

### Fallback Degradation

When `libids_central.so` is missing (`central_runtime.py:131-165`):
- System falls back to: **alert only if `bytes > 1,000,000`**
- No actual IDS inference — all attack patterns silently ignored
- This is a safety net, not a detection system

### Minor Issues

| Issue | Location | Details |
|-------|----------|---------|
| `cybersecurity_threat_detection_logs.csv` | `real_datasets/` | 6M rows, appears synthetic/fake. Labels like `benign`/`suspicious` with `SQLMap/1.6-dev` user agents. |
| `heartbleed.csv` | `real_datasets/` | Only 13 rows (2 actual Heartbleed flows) |
| `web_sql_injection.csv` | `real_datasets/` | Only 25 rows |

---

## 4. Validation Status: No Tests Exist

### Test Infrastructure

| Component | Status |
|-----------|--------|
| C++ unit tests | **NONE** — `ids_model_test.cpp` and `ids_sharded_test.cpp` referenced in CMakeLists.txt but files don't exist |
| Python tests | **NONE** — Zero `test_*.py` or `conftest.py` files anywhere |
| CTest registration | **EMPTY** — CTestTestfile.cmake has zero test commands |
| CI pipeline | **BROKEN** — `ci.yml` defines test jobs but no test files to discover |
| Assertions in demos | **NONE** — All 6 demos print output visually, never assert correctness |

### What the Demos Do

| Demo | Runs Pipeline? | Validates? |
|------|---------------|------------|
| `ids_example.cpp` | Yes | No — prints metrics only |
| `ids_benchmark.cpp` | Yes | No — reports throughput, checks p99 latency once |
| `ids_comprehensive_demo.cpp` | Yes | No — visual output only |
| `ids_parallel_demo.cpp` | Yes | No — visual output only |
| `ids_dataset_demo.cpp` | Yes | **Partial** — computes TP/FP/FN/TN/F1 but never asserts thresholds |
| `ids_specialist_demo.cpp` | Yes | No — visual output only |

### What This Means

- **A pipeline that detects 0% of attacks would still "pass"** (always returns exit code 0)
- **No regression protection** — code changes can silently break detection
- **No reproducibility** — human must visually inspect stdout
- **No CI validation** — the `.github/workflows/ci.yml` runs `pytest -x -v` but finds nothing

---

## 5. Datasets: Real vs Synthetic

| File | Rows | Source | Real? |
|------|------|--------|-------|
| `monday_benign.csv` | 495,339 | CICIDS2017 | **Yes** — real network flow features |
| `tuesday_benign.csv` | 395,977 | CICIDS2017 | **Yes** |
| `wednesday_benign.csv` | 397,054 | CICIDS2017 | **Yes** |
| `thursday_benign.csv` | 133,771 | CICIDS2017 | **Yes** |
| `friday_benign.csv` | 364,103 | CICIDS2017 | **Yes** |
| `dos_slowhttptest.csv` | 6,861 | CICIDS2017 | **Yes** |
| `dos_slowloris.csv` | 5,178 | CICIDS2017 | **Yes** |
| `dos_golden_eye.csv` | 8,365 | CICIDS2017 | **Yes** |
| `dos_hulk.csv` | 349,241 | CICIDS2017 | **Yes** |
| `ddos_loit.csv` | 95,734 | CICIDS2017 | **Yes** |
| `portscan.csv` | 161,324 | CICIDS2017 | **Yes** |
| `ftp_patator.csv` | 9,532 | CICIDS2017 | **Yes** |
| `ssh_patator-new.csv` | 5,950 | CICIDS2017 | **Yes** |
| `web_xss.csv` | 1,359 | CICIDS2017 | **Yes** |
| `web_sql_injection.csv` | 25 | CICIDS2017 | **Yes** (tiny) |
| `web_brute_force.csv` | 2,735 | CICIDS2017 | **Yes** |
| `heartbleed.csv` | 13 | CICIDS2017 | **Yes** (tiny) |
| `botnet_ares.csv` | 5,509 | CICIDS2017 | **Yes** |
| `friday-working-hours-ddos.csv` | 225,746 | CICIDS2017 | **Yes** |
| `friday-working-hours-afternoon-ddos.csv` | 225,746 | CICIDS2017 | **Yes** |
| `cybersecurity_threat_detection_logs.csv` | 6,000,001 | Unknown | **No** — synthetic, fake user agents, inconsistent fields |

**20 of 21 datasets are real CICIDS2017 data.** 1 file (6M rows) appears fabricated.

---

## 6. Summary

### What's Real (Detection)

- Every algorithm (Z-score, SSM, cosine similarity, attention, autoencoder, correlation) has genuine mathematical logic
- Packet capture works with real AF_PACKET raw sockets
- Cloud uploader sends real HTTP requests via libcurl
- C bridge correctly loads and calls `libids_central.so`
- Backend processes events through the full pipeline via 4 worker threads

### What's Missing (Validation)

- Zero unit tests (C++ or Python)
- Zero end-to-end assertions
- CI pipeline has test infrastructure but no test code
- Replay mode is a throughput benchmark, not a data replay
- Build system doesn't compile the daemon or shared library
- No automated way to prove detection accuracy

### What Needs Work

1. **Add unit tests** for each IDS pipeline stage with known inputs/outputs
2. **Add end-to-end tests** using the CICIDS2017 datasets with F1/precision/recall assertions
3. **Fix CMakeLists.txt** to build `ids_production` and `libids_central.so`
4. **Fix the replay mode** to actually parse CSV data
5. **Add regression tests** to prevent silent detection degradation
6. **Wire up CI** to run the dataset demo and assert accuracy thresholds

### Bottom Line

The detection is **architecturally real** — it's not a mock or placeholder. But it's **empirically unproven** — there's no automated evidence it works correctly. The system could detect 0% of attacks or 99% of attacks, and from the code alone, you can't tell which. The CICIDS2017 datasets are real and available; the algorithms are implemented; what's missing is the glue that proves they work together.
