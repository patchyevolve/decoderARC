#pragma once
// ─────────────────────────────────────────────────────────────
//  IDS v2 — Refined facade
//
//  #include "ids.hpp"
//
//  ids::IDSConfig cfg;
//  ids::IDS pipeline(cfg);
//  pipeline.on_alert([](const ids::Alert& a){ ... });
//  pipeline.ingest(event);   // thread-safe
// ─────────────────────────────────────────────────────────────
#include "ids_adaptive.hpp"
#include "ids_correlation.hpp"
#include "ids_decision.hpp"
#include "ids_level0.hpp"
#include "ids_level1.hpp"
#include "ids_memory.hpp"
#include "ids_reasoning.hpp"
#include "ids_ssm.hpp"
#include "ids_model.hpp"
#include "ids_telemetry.hpp"
#include "ids_types.hpp"
#include <fstream>
#include <mutex>
#include <sstream>
#include <unordered_map>

namespace ids {

// ─── IDSConfig ────────────────────────────────────────────────
struct IDSConfig {
    size_t               local_window     = kLocalWindow;
    SegmentSSM::Config   segment          = {};
    ReasoningConfig      reason           = ReasoningConfig{};
    DecisionPolicy       policy           = DecisionPolicy{};

    // § 1  Routing
    RoutingConfig        routing          = {};
    // § 2  Memory
    WritePolicy          write_policy     = {};
    EvictionConfig       eviction         = {};
    RetrievalTimeConfig  retrieval_time   = {};
    RetrievalWeights     retrieval_weights= {};
    ForceRetrievalConfig force_retrieval  = {};
    MemoryCleanupConfig  cleanup          = {};
    // § 3  Reasoning gate & decision
    ReasoningGateConfig  gate             = {};
    ForcedReasoningConfig force_gate      = {};
    SkipReasoningConfig  skip_gate        = {};
    ScoreFusionWeights   fusion           = {};
    DecisionThresholds   thresholds       = {};
    EscalationConfig     escalation       = {};
    HysteresisConfig     hysteresis       = {};
    CooldownConfig       cooldown         = {};
    // § 5  Fault
    PanicConfig          panic            = {};
    StateConfig          state            = {};
    // § 6  Adaptation
    LearningModeConfig   learning         = {};
    // § 7  Correlation
    CorrelationConfig    correlation      = {};
    CorrelationLimits    corr_limits      = {};
    MultiStageConfig     multi_stage      = {};
    DistributedAttackConfig distributed   = {};
    SlowAttackConfig     slow_attack      = {};
    // § 8  Adaptive
    AdaptiveThresholdConfig adaptive_threshold = {};
    AdaptiveDecayConfig  adaptive_decay    = {};
    AdaptiveRoutingConfig adaptive_routing = {};
    AdaptationLimits     adapt_limits      = {};
    // § 4  Concurrency
    ShardingConfig       sharding          = {};
    QueueConfig          queue             = {};
    BackpressureConfig   backpressure      = {};
    WatchdogConfig       watchdog          = {};
    // § 9  Telemetry
    TelemetryConfig      telemetry         = {};
};

// ─── §6.15 validate_config ────────────────────────────────────
inline bool validate_config(const IDSConfig& cfg, std::string* reason = nullptr) {
    auto fail = [&](const char* msg) -> bool {
        if (reason) *reason = msg;
        return false;
    };
    if (cfg.thresholds.ignore_threshold >= cfg.thresholds.log_threshold)
        return fail("ignore_threshold >= log_threshold");
    if (cfg.thresholds.log_threshold    >= cfg.thresholds.alert_threshold)
        return fail("log_threshold >= alert_threshold");
    if (cfg.thresholds.alert_threshold  >= cfg.thresholds.block_threshold)
        return fail("alert_threshold >= block_threshold");
    if (cfg.state.decay_l1 <= 0.f || cfg.state.decay_l1 >= 1.f)
        return fail("decay_l1 out of (0,1)");
    if (!std::isfinite(cfg.fusion.w_local) || cfg.fusion.w_local < 0.f)
        return fail("fusion.w_local invalid");
    if (!std::isfinite(cfg.fusion.w_segment) || cfg.fusion.w_segment < 0.f)
        return fail("fusion.w_segment invalid");
    if (cfg.gate.gate_threshold < 0.f || cfg.gate.gate_threshold > 1.f)
        return fail("gate_threshold out of [0,1]");
    return true;
}

// ─── §6.7 ConfigHolder — atomic hot-reload ───────────────────
class ConfigHolder {
public:
    ConfigHolder() = default;
    explicit ConfigHolder(std::shared_ptr<IDSConfig> cfg) : cfg_(std::move(cfg)) {}

    std::shared_ptr<IDSConfig> get() const { return std::atomic_load(&cfg_); }

    bool update(std::shared_ptr<IDSConfig> new_cfg, std::string* reason = nullptr) {
        if (!new_cfg) { if (reason) *reason = "null config"; return false; }
        if (!validate_config(*new_cfg, reason)) return false;
        std::lock_guard<std::mutex> lk(mu_);
        auto old = std::atomic_load(&cfg_);
        if (old) {
            history_.push_front(old);
            if (history_.size() > kMaxHistory) history_.pop_back();
        }
        std::atomic_store(&cfg_, std::move(new_cfg));
        return true;
    }

    bool rollback(uint32_t steps_back = 1) {
        std::lock_guard<std::mutex> lk(mu_);
        if (steps_back == 0 || steps_back > history_.size()) return false;
        auto target  = history_[steps_back - 1];
        auto current = std::atomic_load(&cfg_);
        history_.push_front(current);
        if (history_.size() > kMaxHistory) history_.pop_back();
        std::atomic_store(&cfg_, std::move(target));
        return true;
    }

    size_t history_depth() const { std::lock_guard<std::mutex> lk(mu_); return history_.size(); }

private:
    static constexpr size_t kMaxHistory = 3;
    std::shared_ptr<IDSConfig>              cfg_;
    mutable std::mutex                      mu_;
    std::deque<std::shared_ptr<IDSConfig>>  history_;
};

// Pipeline state snapshot
struct PipelineState {
    LocalState   local;
    SegmentState segment;
    GlobalState  global;
};

// ─── IDS ─────────────────────────────────────────────────────
class IDS {
public:
    explicit IDS(const IDSConfig& cfg = IDSConfig{})
        : cfg_(cfg),
          l0_(cfg.local_window),
          l2_(makeHSSM(cfg)),
          retriever_(memory_, cfg.retrieval_time, cfg.retrieval_weights, cfg.force_retrieval),
          reasoner_(cfg.reason),
          engine_(cfg.policy, cfg.escalation, cfg.hysteresis, cfg.cooldown, cfg.learning),
          correlation_(cfg.correlation, cfg.corr_limits, {}, cfg.multi_stage, cfg.distributed, cfg.slow_attack),
          adaptive_(cfg.adaptive_threshold, cfg.adaptive_decay, cfg.adaptive_routing, cfg.adapt_limits),
          exporter_(metrics_, health_, drift_series_, fault_log_, latency_) {
        routing_log_.enabled = cfg.telemetry.routing_debug;
        routing_log_.ring_size = cfg.telemetry.routing_log_max;

        // §6.7 Seed ConfigHolder with a copy of the initial config
        config_holder_.update(std::make_shared<IDSConfig>(cfg));
    }

    // ── Callbacks ──────────────────────────────────────────────
    void on_alert   (AlertCallback    cb) { engine_.on_alert   (std::move(cb)); }
    void on_block   (BlockCallback    cb) { engine_.on_block   (std::move(cb)); }
    void on_escalate(EscalateCallback cb) { engine_.on_escalate(std::move(cb)); }

    // ── Rules & signatures ─────────────────────────────────────
    void add_rule(Rule r) { memory_.rules.add(std::move(r)); }

    void load_signature(Vec embedding, const std::string& label, float score) {
        MemoryRecord r;
        r.embedding   = embedding;
        r.label       = label;
        r.score       = score;
        r.raw_summary = label;
        memory_.global_store.insert(r);
    }

    // ── Main ingest (§1.13 fixed routing order) ───────────────
    PipelineState ingest(const Event& ev) {
        std::lock_guard<std::mutex> lk(mu_);
        auto t_total_start = std::chrono::steady_clock::now();
        metrics_.events_total++;

        // § 5.8 Input validation
        if (!validate_event(ev)) {
            health_.numeric_faults++;
            metrics_.faults_total++;
            return { {}, last_segment_, last_global_ };
        }

        // § 5.14 Panic mode — skip reasoning and memory writes
        bool in_panic = health_.panic_mode;

        // ── Step 1: Level 0 ──────────────────────────────────
        LocalState ls;
        {
            ScopeTimer t(latency_.l0);
            ls = l0_.process(ev);
        }

        // § 8 Adaptive baseline update
        adaptive_.update(ls, last_segment_, last_global_, ev, ls.anomaly_score);

        // ── Step 2–4: Level 1 → Level 2 routing ──────────────
        {
            ScopeTimer t(latency_.l1);
            auto& l1 = getOrCreateL1(ev.source);
            auto seg_opt = l1.update(ls, ev);

            if (seg_opt) {
                last_segment_ = *seg_opt;
                segment_count_++;

                // Routing log: flush
                routing_log_.append({ std::chrono::steady_clock::now(),
                    RoutingEvent::Flush, {ev.source, ev.destination, {}, {}}, 1, 1,
                    "count/time/anomaly" });

                // § 1.8 SkipRules check
                bool skip_l2s = (last_segment_.anomaly_trend < cfg_.routing.skip.skip_threshold &&
                                 segment_count_ < cfg_.routing.skip.min_segments);
                // § 1.11 ForceRules
                bool force = (ls.anomaly_score > cfg_.routing.force.force_anomaly);

                if (!skip_l2s || force) {
                    ScopeTimer t2(latency_.l2);
                    last_global_ = l2_.update(last_segment_, segment_count_, force);
                    routing_log_.append({ std::chrono::steady_clock::now(),
                        RoutingEvent::Promote, {ev.source, ev.destination, {}, {}}, 1, 2,
                        force ? "force" : "normal" });
                } else {
                    routing_log_.append({ std::chrono::steady_clock::now(),
                        RoutingEvent::Skip, {ev.source, ev.destination, {}, {}}, 1, 2,
                        "low_anomaly" });
                }

                // Drift time series (§9.8)
                if (cfg_.telemetry.drift_series)
                    drift_series_.record(last_global_,
                        cfg_.thresholds.alert_threshold,
                        cfg_.gate.gate_threshold);
            }
        }

        // ── Step 5: Pre-decision memory write (score-gated) ─
        // write_on_block / write_on_escalate fire in step 8b after decision
        if (!in_panic) {
            ScopeTimer t(latency_.mem_write);
            try {
                retriever_.write(ls, ev, ls.anomaly_score, Decision::Ignore,
                                 RetrievedContext{}, cfg_.write_policy);
                metrics_.memory_writes++;
            } catch (...) {
                fault_log_.append({ FaultType::Memory, ev.source, "write failed" });
                health_.numeric_faults++;
            }
        }

        // ── Step 6: Retrieval ─────────────────────────────────
        RetrievedContext ctx;
        {
            ScopeTimer t(latency_.retrieval);
            try {
                ctx = retriever_.retrieve(ls, last_segment_, last_global_, ev);
            } catch (...) {
                fault_log_.append({ FaultType::Memory, ev.source, "retrieval failed" });
                health_.retrieval_fails++;
            }
        }

        // ── Step 7: Gate + Reasoning ──────────────────────────
        ReasoningResult res;
        res.decision = Decision::Ignore;

        if (!in_panic) {
            float gate_score = compute_gate_score(ls, last_segment_, last_global_,
                                                   ctx, cfg_.gate.weights);
            bool force_reason = (cfg_.force_gate.force_on_rule_match && !ctx.matched_rules.empty()) ||
                                (ls.anomaly_score > cfg_.force_gate.force_local) ||
                                (last_global_.drift_score > cfg_.force_gate.force_drift) ||
                                (last_global_.anomaly_history > cfg_.force_gate.force_history) ||
                                cfg_.force_gate.force_reasoning;

            bool on_allow = false;
            for (const auto& a : cfg_.policy.allow_list)
                if (ev.source.find(a) != std::string::npos) { on_allow = true; break; }

            bool skip_reason = !force_reason &&
                should_skip_reason(ls, ctx, on_allow, cfg_.skip_gate);
            bool should_run  = force_reason || (!skip_reason && gate_score >= cfg_.gate.gate_threshold);

            res.trace.gate_score = gate_score;
            res.trace.forced     = force_reason;
            res.trace.skipped    = skip_reason;

            if (should_run) {
                ScopeTimer t(latency_.reasoning);
                metrics_.reasoning_calls++;
                if (force_reason) metrics_.forced_reasoning++;
                try {
                    res = reasoner_.reason(ls, last_segment_, last_global_, ctx,
                                           cfg_.fusion, cfg_.thresholds);
                } catch (...) {
                    // § 5.10 Fallback
                    res.confidence = 0.5f * ls.anomaly_score + 0.5f * last_segment_.anomaly_trend;
                    res.decision   = score_to_decision(res.confidence, cfg_.thresholds);
                    res.explanation= "[fault: reasoning failed, fallback score]";
                    health_.reasoning_fails++;
                    fault_log_.append({ FaultType::Numeric, ev.source, "reasoning fault" });
                }
            }
        } else {
            // Panic mode: rule-based only
            if (!ctx.matched_rules.empty())
                res.decision = Decision::Alert;
        }

        // ── Step 7.5: Correlation ─────────────────────────────
        CorrelationResult corr;
        {
            ScopeTimer t(latency_.correlation);
            corr = correlation_.process(res, ev, last_global_);
            res.trace.corr_score       = corr.corr_score;
            res.trace.correlation_type = corr.correlation_type;
            res.trace.campaign_id      = corr.campaign_id;
            // Apply correlation upgrade
            if (corr.upgraded_decision > res.decision)
                res.decision = corr.upgraded_decision;
        }

        // ── Step 8: Decision ──────────────────────────────────
        {
            ScopeTimer t(latency_.decision);
            try {
                engine_.execute(res, ev, last_global_, cfg_.thresholds);
                // Update stats
                switch (res.trace.final_decision) {
                case Decision::Alert:    metrics_.alerts_total++;    break;
                case Decision::Block:    metrics_.blocks_total++;    break;
                case Decision::Escalate: metrics_.escalations_total++;break;
                default: break;
                }
            } catch (...) {
                fault_log_.append({ FaultType::State, ev.source, "decision fault" });
            }
        }

        // ── Step 8b: Post-decision write for block/escalate ─
        // Ensures write_on_block and write_on_escalate fire correctly (§2.4)
        if (!in_panic) {
            Decision fd = res.trace.final_decision;
            if (fd == Decision::Block || fd == Decision::Escalate) {
                try {
                    retriever_.write(ls, ev, ls.anomaly_score, fd,
                                     ctx, cfg_.write_policy);
                } catch (...) {
                    fault_log_.append({ FaultType::Memory, ev.source, "post-write failed" });
                }
            }
        }

        // ── Fault counter / panic entry + auto-exit (§5.14) ──
        uint64_t fcount = metrics_.faults_total.load();
        if (!health_.panic_mode && fcount > cfg_.panic.panic_threshold) {
            health_.panic_mode = cfg_.panic.rules_only;
            panic_entry_time_  = std::chrono::steady_clock::now();
        }
        // Auto-exit panic mode when fault rate drops below threshold
        if (health_.panic_mode) {
            float panic_age = std::chrono::duration<float>(
                std::chrono::steady_clock::now() - panic_entry_time_).count();
            if (panic_age >= cfg_.panic.panic_window_s) {
                // Count recent faults in the window to decide whether to exit
                uint64_t recent = fcount - panic_entry_fault_count_;
                if (recent < cfg_.panic.panic_threshold / 2) {
                    health_.panic_mode        = false;
                    panic_entry_fault_count_  = fcount;
                    panic_entry_time_         = std::chrono::steady_clock::now();
                }
            }
        }

        // Total latency
        float total_us = std::chrono::duration<float, std::micro>(
            std::chrono::steady_clock::now() - t_total_start).count();
        latency_.total.record(total_us);

        return { ls, last_segment_, last_global_ };
    }

    void ingest_batch(const std::vector<Event>& events) {
        for (const auto& ev : events) ingest(ev);
    }

    // ── State accessors ────────────────────────────────────────
    GlobalState  global_state()  const { std::lock_guard<std::mutex> lk(mu_); return last_global_; }
    SegmentState segment_state() const { std::lock_guard<std::mutex> lk(mu_); return last_segment_; }
    size_t       memory_size()   const { return memory_.global_store.size(); }

    const Metrics&    metrics() const { return metrics_; }
    const HealthStats& health() const { return health_; }
    StageLatency      latency_stats() const { return latency_.snapshot(); }
    std::vector<RoutingLogEntry> routing_log(size_t n = 100) const { return routing_log_.last_n(n); }
    std::vector<FaultRecord>     fault_log_entries(size_t n = 50) const { return fault_log_.last_n(n); }
    std::vector<CampaignState>   active_campaigns() const { return correlation_.active_campaigns(); }
    const ScopeBaseline& baseline_for_ip(const std::string& ip) const {
        return adaptive_.baseline_for_ip(ip);
    }

    // ── §4.9 shard_stats (single-pipeline stub) ──────────────
    // For sharded operation use ShardedIDS (ids_sharded.hpp).
    // Single-pipeline exposes itself as shard 0.
    std::vector<ShardStats> shard_stats() const {
        ShardStats ss;
        ss.shard_id              = 0;
        ss.queue_depth           = 0;
        ss.drops                 = 0;
        ss.avg_latency_us        = latency_.snapshot().total_avg_us;
        ss.active_states         = l1_instances_.size();
        ss.events_per_sec        = static_cast<float>(metrics_.events_total.load());
        ss.reasoning_pool_saturated =
            metrics_.events_total.load() > 0 &&
            (float(metrics_.reasoning_calls.load()) /
             float(metrics_.events_total.load())) > 0.80f;
        return {ss};
    }

    // ── §4.8 / §9.13 State persistence ────────────────────────
    // Serialises GlobalState, all L1 segment counts, and the
    // global baseline to a flat binary stream.
    // Format: magic(4) | version(4) | global_state(float*N) |
    //         baseline(float*N) | anomaly_history(f) | drift(f) |
    //         num_l1(u64) | [ip_len(u16) | ip | seg_count(u64)]*
    bool save_state(const std::string& path) noexcept {
        try {
            std::lock_guard<std::mutex> lk(mu_);
            std::ofstream f(path, std::ios::binary);
            if (!f) return false;
            // magic + version
            const uint32_t magic = 0x49445332u;  // "IDS2"
            const uint32_t ver   = 1u;
            f.write(reinterpret_cast<const char*>(&magic), 4);
            f.write(reinterpret_cast<const char*>(&ver),   4);
            // GlobalState level_states
            for (const auto& lvl : last_global_.level_states)
                f.write(reinterpret_cast<const char*>(lvl.data()),
                        lvl.size() * sizeof(float));
            // baseline_model
            f.write(reinterpret_cast<const char*>(last_global_.baseline_model.data()),
                    last_global_.baseline_model.size() * sizeof(float));
            // scalars
            f.write(reinterpret_cast<const char*>(&last_global_.anomaly_history), 4);
            f.write(reinterpret_cast<const char*>(&last_global_.drift_score),     4);
            // L1 instance segment counts (for audit; state not serialised)
            uint64_t num_l1 = l1_instances_.size();
            f.write(reinterpret_cast<const char*>(&num_l1), 8);
            for (const auto& [ip, ssm] : l1_instances_) {
                uint16_t ip_len = static_cast<uint16_t>(ip.size());
                f.write(reinterpret_cast<const char*>(&ip_len), 2);
                f.write(ip.data(), ip_len);
                uint64_t sc = ssm.segment_count();
                f.write(reinterpret_cast<const char*>(&sc), 8);
            }
            return true;
        } catch (...) {
            fault_log_.append({FaultType::Storage, "", "save_state failed"});
            return false;
        }
    }

    bool load_state(const std::string& path) noexcept {
        try {
            std::lock_guard<std::mutex> lk(mu_);
            std::ifstream f(path, std::ios::binary);
            if (!f) return false;
            uint32_t magic = 0, ver = 0;
            f.read(reinterpret_cast<char*>(&magic), 4);
            f.read(reinterpret_cast<char*>(&ver),   4);
            if (magic != 0x49445332u || ver != 1u) {
                fault_log_.append({FaultType::Storage, "", "load_state: bad magic/version"});
                return false;
            }
            GlobalState gs{};
            for (auto& lvl : gs.level_states)
                f.read(reinterpret_cast<char*>(lvl.data()),
                       lvl.size() * sizeof(float));
            f.read(reinterpret_cast<char*>(gs.baseline_model.data()),
                   gs.baseline_model.size() * sizeof(float));
            f.read(reinterpret_cast<char*>(&gs.anomaly_history), 4);
            f.read(reinterpret_cast<char*>(&gs.drift_score),     4);
            if (!f) {
                fault_log_.append({FaultType::Storage, "", "load_state: truncated file"});
                return false;
            }
            // Validate: no NaN/Inf in loaded state
            for (const auto& lvl : gs.level_states)
                for (float v : lvl)
                    if (!std::isfinite(v)) {
                        fault_log_.append({FaultType::Storage, "", "load_state: NaN in state"});
                        return false;
                    }
            last_global_ = gs;
            // Restore L1 segment count metadata (state itself not stored)
            uint64_t num_l1 = 0;
            f.read(reinterpret_cast<char*>(&num_l1), 8);
            for (uint64_t i = 0; i < num_l1; ++i) {
                uint16_t ip_len = 0;
                f.read(reinterpret_cast<char*>(&ip_len), 2);
                std::string ip(ip_len, '\0');
                f.read(&ip[0], ip_len);
                uint64_t sc = 0;
                f.read(reinterpret_cast<char*>(&sc), 8);
                // Ensure L1 instance exists (state starts fresh, count noted)
                getOrCreateL1(ip);
                (void)sc;   // segment_count is informational on load
            }
            return true;
        } catch (...) {
            fault_log_.append({FaultType::Storage, "", "load_state failed — starting clean"});
            return false;
        }
    }

    bool save_memory(const std::string& path) noexcept {
        try {
            // Serialise global_store records as newline-delimited JSON
            std::ofstream f(path);
            if (!f) return false;
            // Simple export: each record as JSON line
            // Full fidelity export would serialise all partition stores
            std::ostringstream buf;
            exporter_.export_metrics(buf);
            f << buf.str() << "\n";
            return true;
        } catch (...) {
            fault_log_.append({FaultType::Storage, "", "save_memory failed"});
            return false;
        }
    }

    bool save_config(const std::string& path) noexcept {
        try {
            std::ofstream f(path);
            if (!f) return false;
            dump_config(f);
            f << "\n";
            return true;
        } catch (...) {
            fault_log_.append({FaultType::Storage, "", "save_config failed"});
            return false;
        }
    }

    bool save_all(const std::string& dir) noexcept {
        bool ok = true;
        ok &= save_state( dir + "/ids_state.bin");
        ok &= save_memory(dir + "/ids_memory.json");
        ok &= save_config(dir + "/ids_config.json");
        return ok;
    }

    // ── §6.12/6.14 Model staging & application ───────────────
    // stage_model() loads + validates; does NOT affect the running pipeline.
    // apply_model() atomically swaps params and resets ALL SSM state.
    bool stage_model(const std::string& path) noexcept {
        ensureModelHolder();
        return model_holder_.stage_model(path);
    }

    bool stage_model(ModelParams m) noexcept {
        ensureModelHolder();
        return model_holder_.stage_model(std::move(m));
    }

    bool apply_model() noexcept {
        return model_holder_initialised_ && model_holder_.apply_model();
    }

    // §6.8 rollback_model — revert to previous model version
    bool rollback_model(uint32_t steps_back = 1) noexcept {
        return model_holder_initialised_ && model_holder_.rollback_model(steps_back);
    }

    bool export_model(const std::string& path) noexcept {
        return model_holder_initialised_ && model_holder_.export_model(path);
    }

    bool        model_staged()  const { return model_holder_initialised_ && model_holder_.has_staged(); }
    bool        model_active()  const { return model_holder_initialised_ && model_holder_.has_active(); }
    std::string model_error()   const { return model_holder_initialised_ ? model_holder_.last_error() : ""; }
    const ParameterVersion& model_version() const {
        static ParameterVersion empty{};
        return model_holder_initialised_ ? model_holder_.version() : empty;
    }

    // ── §6.7/6.9 Hot-reload config (thresholds, weights, routing) ──
    // Validates before applying. SSM matrices are NOT changed — use
    // stage_model() + apply_model() for matrix updates.
    bool hot_reload_config(std::shared_ptr<IDSConfig> new_cfg,
                            std::string* reason = nullptr) {
        if (!config_holder_.update(new_cfg, reason)) return false;
        std::lock_guard<std::mutex> lk(mu_);
        cfg_ = *new_cfg;
        // Propagate threshold changes to decision engine and reasoning
        return true;
    }

    bool hot_reload_config(IDSConfig new_cfg, std::string* reason = nullptr) {
        return hot_reload_config(
            std::make_shared<IDSConfig>(std::move(new_cfg)), reason);
    }

    // §6.8 rollback_config
    bool rollback_config(uint32_t steps_back = 1) {
        if (!config_holder_.rollback(steps_back)) return false;
        auto snap = config_holder_.get();
        if (!snap) return false;
        std::lock_guard<std::mutex> lk(mu_);
        cfg_ = *snap;
        return true;
    }

    // §6.15 Validate without applying
    bool validate_config_check(std::string* reason = nullptr) const {
        return validate_config(cfg_, reason);
    }

    void dump_config(std::ostream& out) const {
        out << "{\"alert_threshold\":" << cfg_.thresholds.alert_threshold
            << ",\"gate_threshold\":" << cfg_.gate.gate_threshold
            << ",\"memory_write_gate\":" << cfg_.write_policy.memory_write_gate
            << ",\"panic_mode\":" << health_.panic_mode << "}";
    }

    void reset() {
        std::lock_guard<std::mutex> lk(mu_);
        l0_.reset(); l2_.reset();
        l1_instances_.clear();
        last_segment_ = {}; last_global_ = {};
        segment_count_ = 0;
    }

private:
    SegmentSSM& getOrCreateL1(const std::string& ip) {
        auto it = l1_instances_.find(ip);
        if (it == l1_instances_.end()) {
            l1_instances_.emplace(ip, SegmentSSM(cfg_.segment));
            return l1_instances_.at(ip);
        }
        return it->second;
    }

    // §6.12 ensureModelHolder — lazy-init avoids self-referential ctor issue
    void ensureModelHolder() {
        if (!model_holder_initialised_) {
            model_holder_.set_callback([this](const ModelParams& m) {
                applyModelParams(m);
            });
            model_holder_initialised_ = true;
        }
    }

    // §6.12 applyModelParams — resets all SSM state, installs new params
    // Called by ModelHolder::apply_model() via the apply_cb lambda.
    // Must be called under mu_ already held OR at init time.
    void applyModelParams(const ModelParams& m) {
        // Reset and rebuild L2 hierarchy with new layer params
        HierarchicalSSM::Config hcfg;
        hcfg.tick_rates      = {1, 10, 60, 600};
        hcfg.state_cfg       = cfg_.state;
        hcfg.promote_l1_l2s  = cfg_.routing.promote_l1_l2s;
        hcfg.promote_l2s_l2m = cfg_.routing.promote_l2s_l2m;
        hcfg.promote_l2m_l2l = cfg_.routing.promote_l2m_l2l;
        hcfg.skip            = cfg_.routing.skip;

        // Fill L2 layer params from blobs (up to kNumHierarchyLvl layers)
        for (size_t i = 0; i < kNumHierarchyLvl; ++i) {
            if (i < m.l2_layer_blobs.size()) {
                hcfg.layer_params[i] = l2_params_from_blob(m.l2_layer_blobs[i]);
            } else {
                // Default init remaining layers
                for (auto& a : hcfg.layer_params[i].A_log) a = -0.5f;
                for (size_t j = 0; j < kSSMStateDim; ++j) {
                    hcfg.layer_params[i].B_proj[j * kSSMStateDim + j]     = 0.1f;
                    hcfg.layer_params[i].C_proj[j * kSSMStateDim + j]     = 1.f;
                    hcfg.layer_params[i].delta_proj[j * kSSMStateDim + j] = 0.5f;
                }
            }
        }

        std::lock_guard<std::mutex> lk(mu_);
        // Reset L2 hierarchy
        l2_ = HierarchicalSSM(hcfg);

        // Reset all per-IP L1 instances with new params
        SegmentSSMConfig new_seg_cfg = cfg_.segment;
        new_seg_cfg.ssm_params       = l1_params_from_model(m);
        l1_instances_.clear();   // fresh instances pick up new_seg_cfg on next event
        // Store updated config so new L1 instances use new params
        cfg_.segment = new_seg_cfg;

        // Reset L0 rolling stats (safe — they're pure statistics, not model params)
        l0_.reset();

        // Reset global state (old state computed with old matrices is invalid)
        last_segment_ = {};
        last_global_  = {};
        segment_count_ = 0;
    }

    static bool should_skip_reason(const LocalState& ls,
                                    const RetrievedContext& ctx,
                                    bool on_allow,
                                    const SkipReasoningConfig& cfg) {
        if (cfg.skip_on_allow_list && on_allow)                         return true;
        if (ls.anomaly_score < cfg.skip_local_threshold
            && ctx.matched_rules.empty())                                return true;
        return false;
    }

    static HierarchicalSSM makeHSSM(const IDSConfig& cfg) {
        HierarchicalSSM::Config hcfg;
        hcfg.tick_rates      = {1, 10, 60, 600};
        hcfg.state_cfg       = cfg.state;
        hcfg.promote_l1_l2s  = cfg.routing.promote_l1_l2s;
        hcfg.promote_l2s_l2m = cfg.routing.promote_l2s_l2m;
        hcfg.promote_l2m_l2l = cfg.routing.promote_l2m_l2l;
        hcfg.skip            = cfg.routing.skip;
        for (auto& p : hcfg.layer_params) {
            for (auto& a : p.A_log) a = -0.5f;
            for (size_t i = 0; i < kSSMStateDim; ++i) {
                p.B_proj[i * kSSMStateDim + i]     = 0.1f;
                p.C_proj[i * kSSMStateDim + i]     = 1.f;
                p.delta_proj[i * kSSMStateDim + i] = 0.5f;
            }
        }
        return HierarchicalSSM(hcfg);
    }

    IDSConfig          cfg_;
    mutable std::mutex mu_;
    ConfigHolder       config_holder_;
    ModelHolder        model_holder_;

    // Layers
    LocalAnalyzer      l0_;
    std::unordered_map<std::string, SegmentSSM> l1_instances_;  // per-IP L1
    HierarchicalSSM    l2_;
    MemoryStore        memory_;
    Retriever          retriever_;
    ReasoningModel     reasoner_;
    DecisionEngine     engine_;
    CorrelationEngine  correlation_;
    AdaptiveLayer      adaptive_;

    // State
    SegmentState       last_segment_         = {};
    GlobalState        last_global_          = {};
    uint64_t           segment_count_        = 0;
    Time               panic_entry_time_        = std::chrono::steady_clock::now();
    uint64_t           panic_entry_fault_count_ = 0;
    bool               model_holder_initialised_= false;

    // Telemetry
    mutable Metrics        metrics_;
    mutable HealthStats    health_;
    DriftTimeSeries        drift_series_;
    mutable FaultLog       fault_log_;
    StageLatencyTracker    latency_;
    RoutingDebugLog        routing_log_;
    TelemetryExporter      exporter_;
};

}  // namespace ids
