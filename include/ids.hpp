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
#include "ids_nn.hpp"
#include "ids_correlation.hpp"
#include "ids_decision.hpp"
#include "ids_level0.hpp"
#include "ids_specialist.hpp"
#include "ids_level1.hpp"
#include "ids_memory.hpp"
#include "ids_reasoning.hpp"
#include "ids_ssm.hpp"
#include "ids_model.hpp"
#include "ids_telemetry.hpp"
#include "ids_types.hpp"
#include <array>
#include <fstream>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <unordered_map>

// ─── CRC32 (simple table-based) ───────────────────────────────
inline uint32_t crc32(const void* data, size_t len, uint32_t init = 0) {
    static const uint32_t table[256] = {
        0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
        0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
        0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
        0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
        0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
        0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
        0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
        0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
        0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
        0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
        0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
        0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
        0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
        0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
        0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
        0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
        0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
        0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
        0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
        0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
        0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
        0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
        0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
        0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
        0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
        0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
        0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
        0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
        0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
        0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
        0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
        0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
        0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
        0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
        0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
        0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
        0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
        0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
        0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
        0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
        0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
        0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
        0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
    };
    uint32_t c = init ^ 0xFFFFFFFF;
    auto bytes = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; ++i)
        c = table[(c ^ bytes[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFF;
}

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
    OnlineLearningConfig online_learning  = {};
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
    if (!std::isfinite(cfg.state.decay_l1) || cfg.state.decay_l1 <= 0.f || cfg.state.decay_l1 >= 1.f)
        return fail("decay_l1 out of (0,1)");
    if (!std::isfinite(cfg.fusion.w_local) || cfg.fusion.w_local < 0.f)
        return fail("fusion.w_local invalid");
    if (!std::isfinite(cfg.fusion.w_segment) || cfg.fusion.w_segment < 0.f)
        return fail("fusion.w_segment invalid");
    if (!std::isfinite(cfg.gate.gate_threshold) || cfg.gate.gate_threshold < 0.f || cfg.gate.gate_threshold > 1.f)
        return fail("gate_threshold out of [0,1]");
    return true;
}

// ─── §6.7 ConfigHolder — atomic hot-reload ───────────────────
class ConfigHolder {
public:
    ConfigHolder() = default;
    explicit ConfigHolder(std::shared_ptr<IDSConfig> cfg) : cfg_(std::move(cfg)) {}

    std::shared_ptr<IDSConfig> get() const {
        std::lock_guard<std::mutex> lk(mu_);
        return cfg_;
    }

    bool update(std::shared_ptr<IDSConfig> new_cfg, std::string* reason = nullptr) {
        if (!new_cfg) { if (reason) *reason = "null config"; return false; }
        if (!validate_config(*new_cfg, reason)) return false;
        std::lock_guard<std::mutex> lk(mu_);
        if (cfg_) {
            history_.push_front(cfg_);
            if (history_.size() > kMaxHistory) history_.pop_back();
        }
        cfg_ = std::move(new_cfg);
        return true;
    }

    bool rollback(uint32_t steps_back = 1) {
        std::lock_guard<std::mutex> lk(mu_);
        if (steps_back == 0 || steps_back > history_.size()) return false;
        auto target  = history_[steps_back - 1];
        history_.push_front(cfg_);
        if (history_.size() > kMaxHistory) history_.pop_back();
        cfg_ = target;
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
          adaptive_(cfg.adaptive_threshold, cfg.adapt_limits),
          exporter_(metrics_, drift_series_, fault_log_, latency_) {
        routing_log_.enabled = cfg.telemetry.routing_debug;
        routing_log_.ring_size = cfg.telemetry.routing_log_max;

        // §6.7 Seed ConfigHolder with a copy of the initial config
        config_holder_.update(std::make_shared<IDSConfig>(cfg));
    }

    // ── Callbacks ──────────────────────────────────────────────
    void on_alert   (AlertCallback    cb) { std::lock_guard<std::mutex> lk(mu_); engine_.on_alert   (std::move(cb)); }
    void on_block   (BlockCallback    cb) { std::lock_guard<std::mutex> lk(mu_); engine_.on_block   (std::move(cb)); }
    void on_escalate(EscalateCallback cb) { std::lock_guard<std::mutex> lk(mu_); engine_.on_escalate(std::move(cb)); }

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

    // ── Specialists (§3.14) ────────────────────────────────────
    void add_specialist(std::unique_ptr<Specialist> s) {
        std::lock_guard<std::mutex> lk(mu_);
        specialists_.push_back(std::move(s));
    }

    // ── Per-class fusion weights (§3.8) ───────────────────────
    void set_class_weights(const std::string& attack_class, const ScoreFusionWeights& w) {
        std::lock_guard<std::mutex> lk(mu_);
        class_weights_[attack_class] = w;
    }

    // ── Autoencoder training (§3.15) — uses collected embeddings ──
    size_t embedding_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return embeddings_.size();
    }

    void train_autoencoder(size_t epochs = 5) {
        std::lock_guard<std::mutex> lk(mu_);
        if (embeddings_.empty()) return;
        ae_.train_batch(embeddings_, epochs);
        ae_.record_stats(embeddings_);
    }

    // ── Production save/load (§9.13) ───────────────────────────
    bool train_and_save(const std::string& state_dir) {
        return save_all(state_dir);
    }

    bool load_and_detect(const std::string& state_dir) {
        return load_all(state_dir);
    }

    // ── Main ingest (§1.13 fixed routing order) ───────────────
    PipelineState ingest(const Event& ev) {
        std::unique_lock<std::shared_mutex> write_lock(state_mu_);
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

        // ── Step 1.5: Autoencoder anomaly score ────────────
        {
            ScopeTimer t(latency_.ae);
            ls.ae_score = ae_.anomaly_score(
                std::vector<float>(ls.embedding.begin(), ls.embedding.end()));
            // Fuse AE score into local score for backward compat
            ls.anomaly_score = std::clamp(
                ls.anomaly_score * 0.85f + ls.ae_score * 0.15f, 0.f, 1.f);
        }

        // Collect embedding for autoencoder training (ring buffer)
        {
            if (embeddings_.size() < 2000)
                embeddings_.push_back(
                    std::vector<float>(ls.embedding.begin(), ls.embedding.end()));
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
                retriever_.write(ls, ev, ls.anomaly_score, last_global_.drift_score,
                                 Decision::Ignore, RetrievedContext{}, cfg_.write_policy);
                metrics_.memory_writes++;
            } catch (...) {
                fault_log_.append({ FaultType::Memory, ev.source, "write failed" });
                health_.numeric_faults++;
            }
        }

        // ── Step 6: Retrieval (gated + IP cooldown) ────────
        RetrievedContext ctx;
        {
            auto& last_ret = last_retrieval_time_[ev.source];
            float now_s = static_cast<float>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count()) / 1000.f;
            bool cooldown_ok = (now_s - last_ret) > 1.0f; // max 1 Hz per IP
            if (ls.anomaly_score >= cfg_.gate.gate_threshold * 0.5f && cooldown_ok) {
                ScopeTimer t(latency_.retrieval);
                try {
                    ctx = retriever_.retrieve(ls, last_segment_, last_global_, ev);
                    last_ret = now_s;
                } catch (...) {
                    fault_log_.append({ FaultType::Memory, ev.source, "retrieval failed" });
                    health_.retrieval_fails++;
                }
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
                    // Use per-class fusion weights if configured
                    ScoreFusionWeights fusion_w = cfg_.fusion;
                    auto lit = ev.metadata.find("_label");
                    if (lit != ev.metadata.end()) {
                        for (const auto& [cls, w] : class_weights_) {
                            if (lit->second.find(cls) != std::string::npos) {
                                fusion_w = w;
                                break;
                            }
                        }
                    }
                    res = reasoner_.reason(ls, last_segment_, last_global_, ctx,
                                           fusion_w, cfg_.thresholds);
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

        // ── Step 7.3: Specialist fusion (§3.14) ──────────────
        {
        ScopeTimer t_spec(latency_.specialist);
        if (!specialists_.empty() && res.confidence > 0.f) {
            float max_spec_conf = 0.f;
            std::string spec_class;
            for (auto& s : specialists_) {
                try {
                    auto sr = s->analyze(ev);
                    if (sr.validated && sr.confidence > max_spec_conf) {
                        max_spec_conf = sr.confidence;
                        spec_class    = sr.attack_class;
                    }
                } catch (...) {}
            }
            if (max_spec_conf > 0.3f) {
                // Boost — specialist influences but does not override
                res.confidence = std::clamp(res.confidence + max_spec_conf * 0.5f, 0.f, 1.f);
                if (!spec_class.empty()) res.attack_class = spec_class;
                res.decision = score_to_decision(res.confidence, cfg_.thresholds);
                res.explanation += " [specialist:" + spec_class + "@" +
                    std::to_string(max_spec_conf).substr(0, 4) + "]";
            }
        }

        } // ScopeTimer specialist
        // ── Step 7.4: Near-miss & aggregate detection ────────
        {
        ScopeTimer t_nm(latency_.near_miss);
        if (res.confidence < cfg_.thresholds.alert_threshold) {
            float near_boost = near_miss_.check(ev.source, res.confidence) ? 0.4f : 0.f;
            float agg_boost  = aggregator_.score(ev.source, ev) * 0.5f;
            float total_boost = std::max(near_boost, agg_boost);
            if (total_boost > 0.f) {
                res.confidence = std::clamp(res.confidence + total_boost, 0.f, 1.f);
                res.decision   = score_to_decision(res.confidence, cfg_.thresholds);
                res.explanation += " [agg+" + std::to_string(total_boost).substr(0, 4) + "]";
            }
        }
        } // ScopeTimer near_miss

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
                    retriever_.write(ls, ev, ls.anomaly_score, last_global_.drift_score,
                                     fd, ctx, cfg_.write_policy);
                } catch (...) {
                    fault_log_.append({ FaultType::Memory, ev.source, "post-write failed" });
                }
            }
        }

        // ── Step 8c: Online autoencoder learning ──────────────
        // Single SGD step on confirmed-benign events adapts to
        // gradual traffic drift without offline retraining.
        // Only events well below the alert threshold and with
        // stochastic 1:N sampling to avoid catastrophic forgetting.
        {
            auto& ol = cfg_.online_learning;
            if (ol.enabled &&
                res.confidence < ol.min_confidence &&
                !in_panic &&
                ++online_step_counter_ % ol.sample_rate == 0) {
                ScopeTimer t(latency_.online);
                try {
                    auto emb = std::vector<float>(ls.embedding.begin(),
                                                  ls.embedding.end());
                    ae_.online_update(emb, ol.learning_rate);
                    metrics_.online_updates++;
                } catch (...) {
                    health_.numeric_faults++;
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
    // Use shared_lock to allow concurrent reads without blocking the ingest path
    GlobalState  global_state()  const {
        std::shared_lock<std::shared_mutex> lk(state_mu_);
        return last_global_;
    }
    SegmentState segment_state() const {
        std::shared_lock<std::shared_mutex> lk(state_mu_);
        return last_segment_;
    }
    size_t       memory_size()   const {
        std::shared_lock<std::shared_mutex> lk(state_mu_);
        return memory_.global_store.size();
    }

    const Metrics&    metrics() const { std::shared_lock<std::shared_mutex> lk(state_mu_); return metrics_; }
    const HealthStats& health() const { std::shared_lock<std::shared_mutex> lk(state_mu_); return health_; }
    StageLatency      latency_stats() const { std::shared_lock<std::shared_mutex> lk(state_mu_); return latency_.snapshot(); }
    std::vector<RoutingLogEntry> routing_log(size_t n = 100) const { std::shared_lock<std::shared_mutex> lk(state_mu_); return routing_log_.last_n(n); }
    std::vector<FaultRecord>     fault_log_entries(size_t n = 50) const { std::shared_lock<std::shared_mutex> lk(state_mu_); return fault_log_.last_n(n); }
    std::vector<CampaignState>   active_campaigns() const { std::shared_lock<std::shared_mutex> lk(state_mu_); return correlation_.active_campaigns(); }
    const ScopeBaseline& baseline_for_ip(const std::string& ip) const {
        std::shared_lock<std::shared_mutex> lk(state_mu_);
        return adaptive_.baseline_for_ip(ip);
    }

    // ── §4.9 shard_stats (single-pipeline stub) ──────────────
    // For sharded operation use ShardedIDS (ids_sharded.hpp).
    // Single-pipeline exposes itself as shard 0.
    std::vector<ShardStats> shard_stats() const {
        std::shared_lock<std::shared_mutex> lk(state_mu_);
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
    // Format v3: magic(4) | version(4) | global_state(float*N) |
    // baseline(float*N) | anomaly_history(f) | drift(f) |
    // num_l1(u64) | [ip_len(u16) | ip | seg_count(u64) | count(u64) |
    //   score_acc(f) | rate_acc(f) | error_count(u64) | type_freq(8*i32)]*
    // crc32(4) — appended at the end for integrity verification
    bool save_state(const std::string& path) noexcept {
        try {
            std::lock_guard<std::mutex> lk(mu_);
            std::stringstream buf(std::ios::binary | std::ios::out);
            const uint32_t magic = 0x49445332u;
            const uint32_t ver   = 3u;
            buf.write(reinterpret_cast<const char*>(&magic), 4);
            buf.write(reinterpret_cast<const char*>(&ver),   4);
            for (const auto& lvl : last_global_.level_states)
                buf.write(reinterpret_cast<const char*>(lvl.data()),
                        lvl.size() * sizeof(float));
            buf.write(reinterpret_cast<const char*>(last_global_.baseline_model.data()),
                    last_global_.baseline_model.size() * sizeof(float));
            buf.write(reinterpret_cast<const char*>(&last_global_.anomaly_history), 4);
            buf.write(reinterpret_cast<const char*>(&last_global_.drift_score),     4);
            uint64_t num_l1 = l1_instances_.size();
            buf.write(reinterpret_cast<const char*>(&num_l1), 8);
            for (const auto& [ip, ssm] : l1_instances_) {
                uint16_t ip_len = static_cast<uint16_t>(ip.size());
                buf.write(reinterpret_cast<const char*>(&ip_len), 2);
                buf.write(ip.data(), ip_len);
                auto ac = ssm.save_accum();
                buf.write(reinterpret_cast<const char*>(&ac.segment_count), 8);
                buf.write(reinterpret_cast<const char*>(&ac.count), sizeof(size_t));
                buf.write(reinterpret_cast<const char*>(&ac.score_acc), 4);
                buf.write(reinterpret_cast<const char*>(&ac.rate_acc), 4);
                buf.write(reinterpret_cast<const char*>(&ac.error_count), sizeof(size_t));
                buf.write(reinterpret_cast<const char*>(ac.type_freq.data()),
                        ac.type_freq.size() * sizeof(int));
            }
            // CRC32 of all data
            auto str = buf.str();
            uint32_t crc = crc32(str.data(), str.size());
            buf.write(reinterpret_cast<const char*>(&crc), 4);
            std::ofstream f(path, std::ios::binary);
            if (!f) return false;
            f << buf.rdbuf();
            return true;
        } catch (...) {
            fault_log_.append({FaultType::Storage, "", "save_state failed"});
            return false;
        }
    }

    bool load_state(const std::string& path) noexcept {
        try {
            std::lock_guard<std::mutex> lk(mu_);
            std::ifstream f(path, std::ios::binary | std::ios::ate);
            if (!f) return false;
            size_t file_size = static_cast<size_t>(f.tellg());
            f.seekg(0);
            if (file_size < 8) {
                fault_log_.append({FaultType::Storage, "", "load_state: file too small"});
                return false;
            }
            // Read entire file into buffer for CRC verification
            std::string buffer(file_size, '\0');
            f.read(&buffer[0], file_size);
            f.close();

            size_t pos = 0;
            auto read_raw = [&](void* dst, size_t n) -> bool {
                if (pos + n > buffer.size()) return false;
                std::memcpy(dst, buffer.data() + pos, n);
                pos += n;
                return true;
            };

            uint32_t magic = 0, ver = 0;
            if (!read_raw(&magic, 4) || !read_raw(&ver, 4)) {
                fault_log_.append({FaultType::Storage, "", "load_state: failed to read header"});
                return false;
            }
            if (magic != 0x49445332u || (ver != 1u && ver != 2u && ver != 3u)) {
                fault_log_.append({FaultType::Storage, "", "load_state: bad magic/version"});
                return false;
            }

            // CRC verification for v3+
            if (ver >= 3) {
                size_t crc_pos = buffer.size() - 4;
                uint32_t stored_crc = 0;
                std::memcpy(&stored_crc, buffer.data() + crc_pos, 4);
                uint32_t computed_crc = crc32(buffer.data(), crc_pos);
                if (stored_crc != computed_crc) {
                    fault_log_.append({FaultType::Storage, "", "load_state: CRC mismatch — corrupted file"});
                    return false;
                }
            }

            GlobalState gs{};
            for (auto& lvl : gs.level_states)
                if (!read_raw(lvl.data(), lvl.size() * sizeof(float))) {
                    fault_log_.append({FaultType::Storage, "", "load_state: failed to read level_state"});
                    return false;
                }
            if (!read_raw(gs.baseline_model.data(), gs.baseline_model.size() * sizeof(float)) ||
                !read_raw(&gs.anomaly_history, 4) ||
                !read_raw(&gs.drift_score, 4)) {
                fault_log_.append({FaultType::Storage, "", "load_state: failed to read global state fields"});
                return false;
            }
            if (pos >= buffer.size() - (ver >= 3 ? 4 : 0)) {
                fault_log_.append({FaultType::Storage, "", "load_state: truncated file"});
                return false;
            }
            for (const auto& lvl : gs.level_states)
                for (float v : lvl)
                    if (!std::isfinite(v)) {
                        fault_log_.append({FaultType::Storage, "", "load_state: NaN in state"});
                        return false;
                    }
            last_global_ = gs;
            uint64_t num_l1 = 0;
            if (!read_raw(&num_l1, 8)) {
                fault_log_.append({FaultType::Storage, "", "load_state: failed to read num_l1"});
                return false;
            }
            for (uint64_t i = 0; i < num_l1; ++i) {
                uint16_t ip_len = 0;
                if (!read_raw(&ip_len, 2)) {
                    fault_log_.append({FaultType::Storage, "", "load_state: failed to read ip_len"});
                    return false;
                }
                std::string ip(ip_len, '\0');
                if (!read_raw(&ip[0], ip_len)) {
                    fault_log_.append({FaultType::Storage, "", "load_state: failed to read ip"});
                    return false;
                }
                auto& l1 = getOrCreateL1(ip);
                if (ver >= 2) {
                    SegmentSSM::AccumState ac{};
                    if (!read_raw(&ac.segment_count, 8) ||
                        !read_raw(&ac.count, sizeof(size_t)) ||
                        !read_raw(&ac.score_acc, 4) ||
                        !read_raw(&ac.rate_acc, 4) ||
                        !read_raw(&ac.error_count, sizeof(size_t)) ||
                        !read_raw(ac.type_freq.data(), ac.type_freq.size() * sizeof(int))) {
                        fault_log_.append({FaultType::Storage, "", "load_state: failed to read accum state"});
                        return false;
                    }
                    l1.restore_accum(ac);
                }
            }
            return true;
        } catch (...) {
            fault_log_.append({FaultType::Storage, "", "load_state failed — starting clean"});
            return false;
        }
    }

    bool save_memory(const std::string& path) noexcept {
        try {
            std::ofstream f(path);
            if (!f) return false;
            std::lock_guard<std::mutex> lk(mu_);
            auto records = memory_.global_store.all_records();
            f << "{\"records\":[";
            bool first = true;
            for (const auto& r : records) {
                if (!first) f << ",";
                f << "{\"id\":" << r.id
                  << ",\"score\":" << r.score
                  << ",\"label\":\"" << r.label
                  << "\",\"summary\":\"" << r.raw_summary
                  << "\",\"ip\":\"" << r.key.ip
                  << "\",\"host\":\"" << r.key.host
                  << "\"}";
                first = false;
            }
            f << "]}";
            return true;
        } catch (...) {
            fault_log_.append({FaultType::Storage, "", "save_memory failed"});
            return false;
        }
    }

    bool save_config(const std::string& path) noexcept {
        try {
            std::lock_guard<std::mutex> lk(mu_);
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

    bool load_memory(const std::string& path) noexcept {
        try {
            std::ifstream f(path);
            if (!f) return false;
            std::lock_guard<std::mutex> lk(mu_);
            std::stringstream buf;
            buf << f.rdbuf();
            auto json = buf.str();
            // Simple parser: extract record fields
            size_t pos = 0;
            while ((pos = json.find("\"id\":", pos)) != std::string::npos) {
                pos += 5;
                MemoryRecord r;
                r.id = static_cast<uint64_t>(std::stoull(json.data() + pos));
                auto s = json.find("\"score\":", pos);
                if (s == std::string::npos) break;
                r.score = std::stof(json.data() + s + 7);
                auto l = json.find("\"label\":\"", s);
                if (l == std::string::npos) break;
                l += 9;
                auto le = json.find("\"", l);
                r.label = json.substr(l, le - l);
                auto ip = json.find("\"ip\":\"", le);
                if (ip == std::string::npos) break;
                ip += 6;
                auto ipe = json.find("\"", ip);
                r.key.ip = json.substr(ip, ipe - ip);
                auto h = json.find("\"host\":\"", ipe);
                if (h == std::string::npos) break;
                h += 8;
                auto he = json.find("\"", h);
                r.key.host = json.substr(h, he - h);
                memory_.global_store.insert(r);
            }
            return true;
        } catch (...) {
            fault_log_.append({FaultType::Storage, "", "load_memory failed"});
            return false;
        }
    }

    bool load_config(const std::string& path) noexcept {
        try {
            std::ifstream f(path);
            if (!f) return false;
            IDSConfig c;
            std::string line;
            while (std::getline(f, line)) {
                auto eq = line.find('=');
                if (eq == std::string::npos) continue;
                std::string key = line.substr(0, eq);
                std::string val = line.substr(eq + 1);
                if (key == "local_window") c.local_window = std::stoul(val);
                else if (key == "w_local") c.fusion.w_local = std::stof(val);
                else if (key == "w_segment") c.fusion.w_segment = std::stof(val);
                else if (key == "w_history") c.fusion.w_history = std::stof(val);
                else if (key == "w_drift") c.fusion.w_drift = std::stof(val);
                else if (key == "w_retrieval") c.fusion.w_retrieval = std::stof(val);
                else if (key == "w_rule") c.fusion.w_rule = std::stof(val);
                else if (key == "alert_threshold") c.thresholds.alert_threshold = std::stof(val);
                else if (key == "block_threshold") c.thresholds.block_threshold = std::stof(val);
                else if (key == "escalate_threshold") c.thresholds.escalate_threshold = std::stof(val);
            }
            hot_reload_config(std::make_shared<IDSConfig>(c));
            return true;
        } catch (...) {
            fault_log_.append({FaultType::Storage, "", "load_config failed"});
            return false;
        }
    }

    bool save_all(const std::string& dir) noexcept {
        bool ok = true;
        ok &= save_state( dir + "/ids_state.bin");
        ok &= save_memory(dir + "/ids_memory.json");
        ok &= save_config(dir + "/ids_config.json");
        ok &= l0_.save_state(dir + "/ids_l0.bin");
        ok &= ae_.save(dir + "/ids_ae.bin");
        return ok;
    }

    bool load_all(const std::string& dir) noexcept {
        bool ok = true;
        ok &= load_state( dir + "/ids_state.bin");
        ok &= load_memory(dir + "/ids_memory.json");
        ok &= load_config(dir + "/ids_config.json");
        ok &= l0_.load_state(dir + "/ids_l0.bin");
        ok &= ae_.load(dir + "/ids_ae.bin");
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
        engine_.reconfig(cfg_.policy, cfg_.escalation, cfg_.hysteresis,
                         cfg_.cooldown, cfg_.learning);
        correlation_.reconfig(cfg_.correlation, cfg_.corr_limits,
                              cfg_.multi_stage, cfg_.distributed,
                              cfg_.slow_attack);
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
        out << "local_window=" << cfg_.local_window << "\n"
            << "w_local=" << cfg_.fusion.w_local << "\n"
            << "w_segment=" << cfg_.fusion.w_segment << "\n"
            << "w_history=" << cfg_.fusion.w_history << "\n"
            << "w_drift=" << cfg_.fusion.w_drift << "\n"
            << "w_retrieval=" << cfg_.fusion.w_retrieval << "\n"
            << "w_rule=" << cfg_.fusion.w_rule << "\n"
            << "alert_threshold=" << cfg_.thresholds.alert_threshold << "\n"
            << "block_threshold=" << cfg_.thresholds.block_threshold << "\n"
            << "escalate_threshold=" << cfg_.thresholds.escalate_threshold << "\n"
            << "gate_threshold=" << cfg_.gate.gate_threshold << "\n"
            << "memory_write_gate=" << cfg_.write_policy.memory_write_gate << "\n"
            << "panic_mode=" << health_.panic_mode;
    }

    void reset() {
        std::unique_lock<std::shared_mutex> state_lock(state_mu_);
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
    mutable std::mutex mu_;             // exclusive lock for ingest()
    mutable std::shared_mutex state_mu_; // shared lock for read-only state access
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
    std::atomic<bool>  model_holder_initialised_{false};

    // Specialists (§3.14)
    std::vector<std::unique_ptr<Specialist>> specialists_;

    // Per-class fusion weights (§3.8)
    std::unordered_map<std::string, ScoreFusionWeights> class_weights_;

    // Neural autoencoder (§3.15)
    Autoencoder        ae_{40, 16, 8, 0.01f};
    std::vector<std::vector<float>> embeddings_; // ring buffer for AE training
    size_t             online_step_counter_ = 0;

    // Retrieval cooldown (max 1 Hz per IP)
    std::unordered_map<std::string, float> last_retrieval_time_;

    // Near-miss & aggregate detectors (§4.5)
    NearMissDetector   near_miss_{60.f, 5, 0.25f};
    PerIPAggregator    aggregator_{20};

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
