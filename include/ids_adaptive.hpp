#pragma once
#include "ids_types.hpp"
#include <algorithm>
#include <cmath>
#include <unordered_map>

namespace ids {

struct AdaptiveThresholdConfig {
    float k_alert  = 3.0f;
    float k_block  = 5.0f;
    float k_gate   = 2.0f;
    float min_alert_threshold = 0.30f;
    float max_alert_threshold = 0.90f;
};

struct AdaptiveDecayConfig {
    float decay_slow = 0.99f;
    float decay_fast = 0.90f;
};

struct AdaptiveRoutingConfig {
    float routing_adapt_k = 0.5f;
    float base_promote    = 0.50f;
};

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

struct BaselineDriftConfig {
    float max_baseline_change_rate = 0.10f;
    float baseline_drift_alert     = 0.30f;
};

// ─── Per-scope baseline update ────────────────────────────────
inline void update_baseline(ScopeBaseline& b,
                             const LocalState& ls,
                             const SegmentState& ss,
                             const GlobalState& gs,
                             float alpha) {
    if (b.frozen) return;
    b.avg_anomaly_score += alpha * (ls.anomaly_score - b.avg_anomaly_score);
    b.avg_rate_hz       += alpha * (ss.rate_mean     - b.avg_rate_hz);
    b.avg_entropy       += alpha * (ls.entropy       - b.avg_entropy);
    b.avg_drift         += alpha * (gs.drift_score   - b.avg_drift);
    for (size_t i = 0; i < kEmbeddingDim; ++i)
        b.mean[i] += alpha * (ls.embedding[i] - b.mean[i]);
    b.last_update = std::chrono::steady_clock::now();
}

inline void maybe_freeze(ScopeBaseline& b, float anomaly_score,
                          float freeze_threshold = 0.70f) {
    b.frozen = (anomaly_score >= freeze_threshold);
}

inline float adaptive_threshold(float baseline_mean, float baseline_std,
                                  float k, float min_t, float max_t) {
    return std::clamp(baseline_mean + k * baseline_std, min_t, max_t);
}

inline float scale_anomaly(float raw_score, const ScopeBaseline& b, float eps = 1e-6f) {
    float std_val = sqrtf(std::max(eps, b.variance[0]));
    return std::clamp((raw_score - b.avg_anomaly_score) / std_val, 0.f, 1.f);
}

inline float adaptive_decay(float current_rate, float baseline_rate,
                              float decay_slow, float decay_fast) {
    return current_rate > baseline_rate ? decay_slow : decay_fast;
}

inline float adaptive_promote_threshold(float baseline_anomaly, float base, float k) {
    return std::clamp(base + k * baseline_anomaly, 0.20f, 0.90f);
}

inline float adaptive_gate(float baseline_noise, float base_gate, float k) {
    return std::clamp(base_gate + k * baseline_noise, 0.20f, 0.80f);
}

// ─── AdaptiveLayer ────────────────────────────────────────────
class AdaptiveLayer {
public:
    explicit AdaptiveLayer(AdaptiveThresholdConfig threshold_cfg = {},
                           AdaptiveDecayConfig     decay_cfg     = {},
                           AdaptiveRoutingConfig   routing_cfg   = {},
                           AdaptationLimits        limits        = {},
                           BaselineDriftConfig     drift_cfg     = {})
        : threshold_cfg_(threshold_cfg), decay_cfg_(decay_cfg),
          routing_cfg_(routing_cfg), limits_(limits), drift_cfg_(drift_cfg) {}

    void update(const LocalState& ls, const SegmentState& ss,
                const GlobalState& gs, const Event& ev,
                float anomaly_score) {
        // §8.12 per-scope independent adaptation

        // Global baseline (very slow EMA, alpha=0.001)
        bool global_was_frozen = store_.global_baseline.frozen;
        maybe_freeze(store_.global_baseline, gs.anomaly_history);
        update_baseline(store_.global_baseline, ls, ss, gs, 0.001f);
        if (store_.global_baseline.frozen && !global_was_frozen)
            stats_.baseline_freezes++;

        // IP baseline (fast EMA, alpha=0.05)
        {
            auto& ip_b = store_.ip_baseline[ev.source];
            bool was_frozen = ip_b.frozen;
            maybe_freeze(ip_b, anomaly_score);
            if (ip_b.frozen && !was_frozen) stats_.baseline_freezes++;
            update_baseline(ip_b, ls, ss, gs, 0.05f);
        }

        // User baseline — §8.12 user scope (medium EMA, alpha=0.02)
        if (ev.metadata.count("user") && !ev.metadata.at("user").empty()) {
            const auto& user = ev.metadata.at("user");
            auto& user_b = store_.user_baseline[user];
            bool was_frozen = user_b.frozen;
            maybe_freeze(user_b, anomaly_score);
            if (user_b.frozen && !was_frozen) stats_.baseline_freezes++;
            update_baseline(user_b, ls, ss, gs, 0.02f);
        }

        // Host baseline (slow EMA, alpha=0.005)
        if (!ev.destination.empty()) {
            auto& host_b = store_.host_baseline[ev.destination];
            bool was_frozen = host_b.frozen;
            maybe_freeze(host_b, anomaly_score);
            if (host_b.frozen && !was_frozen) stats_.baseline_freezes++;
            update_baseline(host_b, ls, ss, gs, 0.005f);
        }

        stats_.baseline_updates++;

        // Track threshold/gate changes when adaptive values shift notably
        auto new_thresh = adapted_thresholds();
        if (std::fabs(new_thresh.alert_threshold - last_alert_threshold_) > 0.005f) {
            stats_.threshold_changes++;
            last_alert_threshold_ = new_thresh.alert_threshold;
        }
        float new_gate = adaptive_gate(store_.global_baseline.avg_anomaly_score,
                                        0.35f, 0.5f);
        if (std::fabs(new_gate - last_gate_) > 0.005f) {
            stats_.gate_changes++;
            last_gate_ = new_gate;
        }
    }

    // Returns suggested adapted thresholds based on global baseline
    DecisionThresholds adapted_thresholds() const {
        DecisionThresholds t;
        float mean = store_.global_baseline.avg_anomaly_score;
        float std_val = sqrtf(std::max(1e-6f, store_.global_baseline.variance[0]));
        t.alert_threshold = adaptive_threshold(
            mean, std_val, threshold_cfg_.k_alert,
            threshold_cfg_.min_alert_threshold,
            threshold_cfg_.max_alert_threshold);
        t.block_threshold = std::clamp(t.alert_threshold +
            threshold_cfg_.k_block * std_val, t.alert_threshold + 0.05f,
            limits_.threshold_max);
        t.log_threshold   = std::clamp(t.alert_threshold * 0.6f,
            limits_.threshold_min, t.alert_threshold - 0.05f);
        t.ignore_threshold= std::clamp(t.log_threshold * 0.5f,
            limits_.threshold_min, t.log_threshold - 0.05f);
        return t;
    }

    // §8.16 baseline_for(StateKey, MemoryScope) variants
    const ScopeBaseline& baseline_for_ip(const std::string& ip) const {
        auto it = store_.ip_baseline.find(ip);
        return it != store_.ip_baseline.end() ? it->second : store_.global_baseline;
    }
    const ScopeBaseline& baseline_for_user(const std::string& user) const {
        auto it = store_.user_baseline.find(user);
        return it != store_.user_baseline.end() ? it->second : store_.global_baseline;
    }
    const ScopeBaseline& baseline_for_host(const std::string& host) const {
        auto it = store_.host_baseline.find(host);
        return it != store_.host_baseline.end() ? it->second : store_.global_baseline;
    }
    const ScopeBaseline& baseline_for(const StateKey& key, MemoryScope scope) const {
        switch (scope) {
        case MemoryScope::IP:      return baseline_for_ip(key.ip);
        case MemoryScope::User:    return baseline_for_user(key.user);
        case MemoryScope::Host:    return baseline_for_host(key.host);
        default:                   return store_.global_baseline;
        }
    }
    const ScopeBaseline& global_baseline() const { return store_.global_baseline; }

    void reset(const std::string& ip) {
        store_.ip_baseline.erase(ip);
        stats_.baseline_resets++;
    }

    AdaptationStats& stats() { return stats_; }
    const BaselineStore& baseline_store() const { return store_; }

private:
    AdaptiveThresholdConfig threshold_cfg_;
    AdaptiveDecayConfig     decay_cfg_;
    AdaptiveRoutingConfig   routing_cfg_;
    AdaptationLimits        limits_;
    BaselineDriftConfig     drift_cfg_;
    BaselineStore           store_;
    mutable AdaptationStats stats_;
    float                   last_alert_threshold_ = 0.f;
    float                   last_gate_            = 0.f;
};

}  // namespace ids
