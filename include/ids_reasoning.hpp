#pragma once
#include "ids_memory.hpp"
#include "ids_types.hpp"
#include <cmath>
#include <sstream>

namespace ids {

namespace detail {
inline float dot(const Vec& a, const Vec& b) {
    float s = 0.f;
    for (size_t i = 0; i < kEmbeddingDim; ++i) s += a[i]*b[i];
    return s;
}
inline void softmax(std::vector<float>& v) {
    float m = *std::max_element(v.begin(), v.end());
    float s = 0.f;
    for (auto& x : v) { x = expf(x - m); s += x; }
    for (auto& x : v) x /= s + 1e-9f;
}
inline Vec attention_pool(const std::vector<Vec>& tokens, const std::vector<float>& w) {
    Vec out{};
    for (size_t i = 0; i < tokens.size(); ++i)
        for (size_t d = 0; d < kEmbeddingDim; ++d)
            out[d] += w[i] * tokens[i][d];
    return out;
}
inline Vec stateToVec(const State& s) {
    Vec v{};
    for (size_t i = 0; i < kEmbeddingDim && i < kStateVecDim; ++i) v[i] = s[i];
    return v;
}
}  // namespace detail

// § 3.3 Gate score computation
inline float compute_gate_score(const LocalState& ls, const SegmentState& ss,
                                 const GlobalState& gs, const RetrievedContext& ctx,
                                 const GateWeights& w) {
    float rule_signal = ctx.matched_rules.empty() ? 0.f : 1.f;
    float drift_norm  = std::clamp(gs.drift_score / 10.f, 0.f, 1.f);
    return w.w_local     * ls.anomaly_score
         + w.w_segment   * ss.anomaly_trend
         + w.w_history   * gs.anomaly_history
         + w.w_drift     * drift_norm
         + w.w_retrieval * ctx.similarity_max
         + w.w_rule      * rule_signal;
}

// § 3.7 Score fusion
inline float fuse_score(const LocalState& ls, const SegmentState& ss,
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
                + retrieval_boost + rule_boost;
    return std::clamp(score, 0.f, 1.f);
}

// Baseline calibrator (§6.4)
struct BaselineCalibrator {
    std::vector<float> local_samples;
    std::vector<float> trend_samples;

    void observe(const LocalState& ls, const SegmentState& ss) {
        local_samples.push_back(ls.anomaly_score);
        trend_samples.push_back(ss.anomaly_trend);
        if (local_samples.size() > 100000) {
            local_samples.erase(local_samples.begin(),
                                local_samples.begin() + 50000);
        }
    }

    ThresholdSuggestion compute(float fp_target = 0.01f) const {
        ThresholdSuggestion s{};
        if (local_samples.empty()) return s;
        auto sorted = local_samples;
        std::sort(sorted.begin(), sorted.end());
        float pct = static_cast<float>(sorted.size()) * (1.f - fp_target);
        size_t idx = std::min(static_cast<size_t>(pct), sorted.size()-1);
        s.gate_threshold  = std::clamp(sorted[idx] * 0.7f, 0.2f, 0.6f);
        s.alert_threshold = std::clamp(sorted[idx] * 1.0f, 0.3f, 0.8f);
        s.block_threshold = std::clamp(sorted[idx] * 1.3f, 0.5f, 0.95f);
        s.flush_anomaly   = std::clamp(sorted[idx] * 0.9f, 0.3f, 0.85f);
        s.promote_threshold = s.gate_threshold;
        return s;
    }
};

// ─── Reasoning model ──────────────────────────────────────────
struct ReasoningConfig {
    float alert_threshold = 0.6f;
    float block_threshold = 0.85f;
    float fp_suppression  = 0.2f;
};

class ReasoningModel {
public:
    explicit ReasoningModel(const ReasoningConfig& cfg = ReasoningConfig{})
        : cfg_(cfg) {}

    ReasoningResult reason(const LocalState& ls, const SegmentState& ss,
                           const GlobalState& gs,
                           const RetrievedContext& ctx_in,
                           const ScoreFusionWeights& fusion = {},
                           const DecisionThresholds& thresholds = {}) const {
        // § 3.6 Truncate to kMaxReasoningTokens
        RetrievedContext ctx = ctx_in;
        if (ctx.records.size() > kTopKRetrieval) ctx.records.resize(kTopKRetrieval);

        // Build bounded token sequence
        std::vector<Vec> tokens;
        tokens.push_back(ls.embedding);
        tokens.push_back(detail::stateToVec(ss.state_vector));
        tokens.push_back(detail::stateToVec(gs.level_states[0]));
        tokens.push_back(detail::stateToVec(gs.level_states[kNumHierarchyLvl-1]));
        for (const auto& r : ctx.records) tokens.push_back(r.embedding);

        // Single-head attention
        float scale = 1.f / sqrtf(static_cast<float>(kEmbeddingDim));
        std::vector<float> scores(tokens.size());
        for (size_t i = 0; i < tokens.size(); ++i)
            scores[i] = detail::dot(tokens[0], tokens[i]) * scale;
        detail::softmax(scores);
        (void)detail::attention_pool(tokens, scores);

        // § 3.7 Configurable fusion
        float combined = fuse_score(ls, ss, gs, ctx, fusion);

        // Rule override
        if (!ctx.matched_rules.empty())
            combined = std::max(combined, thresholds.alert_threshold);

        ReasoningResult res;
        res.false_positive = (combined < cfg_.fp_suppression);
        res.confidence     = combined;

        res.decision = score_to_decision(combined, thresholds);
        if (res.false_positive) res.decision = Decision::Ignore;

        res.attack_class = classifyAttack(ls, ss, gs, ctx, combined);
        res.explanation  = buildExplanation(res, ls, ss, gs, ctx, combined);

        // Populate trace
        res.trace.local_score             = ls.anomaly_score;
        res.trace.segment_trend           = ss.anomaly_trend;
        res.trace.anomaly_history         = gs.anomaly_history;
        res.trace.drift_score             = gs.drift_score;
        res.trace.retrieval_similarity_max= ctx.similarity_max;
        res.trace.rule_matched            = !ctx.matched_rules.empty();
        res.trace.fused_score             = combined;
        res.trace.attack_class            = res.attack_class;
        res.trace.base_decision           = res.decision;
        res.trace.final_decision          = res.decision;

        return res;
    }

private:
    std::string classifyAttack(const LocalState& ls, const SegmentState& ss,
                               const GlobalState& gs,
                               const RetrievedContext& ctx, float score) const {
        if (score < 0.3f) return "none";
        if (ls.burst_metric > 0.8f && ss.rate_mean > 500.f)      return "DoS/DDoS";
        if (ls.entropy > 0.9f && ss.error_freq > 0.5f)            return "EncryptedC2/Exfiltration";
        if (ss.dominant_type == "auth" && ss.anomaly_trend > 0.6f)return "BruteForce/CredentialStuffing";
        if (ss.dominant_type == "file" && ls.anomaly_score > 0.7f)return "FileSystemAnomaly/Ransomware";
        if (ss.dominant_type == "proc" && gs.drift_score > 5.f)   return "LateralMovement/Persistence";
        if (!ctx.matched_rules.empty())return "RuleMatch:" + ctx.matched_rules[0];
        return score > cfg_.block_threshold ? "UnknownHighSeverity" : "UnknownLowSeverity";
    }

    std::string buildExplanation(const ReasoningResult& res,
                                  const LocalState& ls, const SegmentState& ss,
                                  const GlobalState& gs, const RetrievedContext& ctx,
                                  float combined) const {
        std::ostringstream oss;
        oss << "[IDS] decision=" << decisionName(res.decision)
            << " class=" << res.attack_class
            << " conf="  << combined
            << " local=" << ls.anomaly_score
            << " trend=" << ss.anomaly_trend
            << " hist="  << gs.anomaly_history
            << " drift=" << gs.drift_score;
        if (!ctx.matched_rules.empty()) {
            oss << " rules=";
            for (const auto& r : ctx.matched_rules) oss << r << ",";
        }
        if (res.false_positive) oss << " [FP-suppressed]";
        return oss.str();
    }

    static std::string decisionName(Decision d) {
        switch (d) {
        case Decision::Ignore:   return "IGNORE";
        case Decision::Log:      return "LOG";
        case Decision::Alert:    return "ALERT";
        case Decision::Block:    return "BLOCK";
        case Decision::Escalate: return "ESCALATE";
        }
        return "?";
    }

    ReasoningConfig cfg_;
};

}  // namespace ids
