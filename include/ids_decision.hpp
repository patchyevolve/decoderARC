#pragma once
#include "ids_reasoning.hpp"
#include <chrono>
#include <unordered_map>

namespace ids {

// ─── Repeat tracker (§3.10) ───────────────────────────────────
struct RepeatTracker {
    std::unordered_map<std::string, uint32_t> alert_count;
    std::unordered_map<std::string, Time>     first_alert;
    std::unordered_map<std::string, Time>     last_alert;

    void record(const std::string& source) {
        alert_count[source]++;
        if (!first_alert.count(source))
            first_alert[source] = std::chrono::steady_clock::now();
        last_alert[source] = std::chrono::steady_clock::now();
    }

    bool should_escalate(const std::string& source,
                         const EscalationConfig& cfg) const {
        auto it = alert_count.find(source);
        if (it == alert_count.end()) return false;
        if (it->second < cfg.repeat_escalate_n) return false;
        auto fa = first_alert.find(source);
        if (fa == first_alert.end()) return false;
        float elapsed = std::chrono::duration<float>(
            std::chrono::steady_clock::now() - fa->second).count();
        return elapsed <= cfg.repeat_window_s;
    }

    void expire(float window_s) {
        auto now = std::chrono::steady_clock::now();
        std::vector<std::string> to_remove;
        for (auto& [src, t] : last_alert) {
            if (std::chrono::duration<float>(now - t).count() > window_s)
                to_remove.push_back(src);
        }
        for (const auto& k : to_remove) {
            alert_count.erase(k); first_alert.erase(k); last_alert.erase(k);
        }
    }
};

// § 3.11 Apply overrides in fixed priority order
inline Decision apply_overrides(Decision ml_decision,
                                 const Event& ev,
                                 const GlobalState& gs,
                                 const RepeatTracker& tracker,
                                 const DecisionPolicy& policy,
                                 const EscalationConfig& esc_cfg) {
    // 1. Allow list → hard ignore
    for (const auto& a : policy.allow_list)
        if (ev.source.find(a) != std::string::npos) return Decision::Ignore;
    // 2. Block list → hard block
    for (const auto& b : policy.block_list)
        if (ev.source.find(b) != std::string::npos) return Decision::Block;

    Decision d = ml_decision;
    // 3–5. Escalation checks — require non-Ignore AND confidence above block threshold
    if (d != Decision::Ignore && d != Decision::Log) {
        float base_conf = 0.f;
        if (gs.anomaly_history >= esc_cfg.escalate_hist &&
            gs.anomaly_history >= esc_cfg.escalate_hist * 0.9f) {
            if (tracker.should_escalate(ev.source, esc_cfg) ||
                gs.drift_score >= esc_cfg.escalate_drift * 0.5f)
                d = Decision::Escalate;
        }
        if (gs.drift_score >= esc_cfg.escalate_drift) d = Decision::Escalate;
        if (tracker.should_escalate(ev.source, esc_cfg)) d = Decision::Escalate;
    }
    return d;
}

// ─── Decision engine ──────────────────────────────────────────
class DecisionEngine {
public:
    explicit DecisionEngine(DecisionPolicy      policy    = DecisionPolicy{},
                            EscalationConfig    esc_cfg   = EscalationConfig{},
                            HysteresisConfig    hyst_cfg  = HysteresisConfig{},
                            CooldownConfig      cool_cfg  = CooldownConfig{},
                            LearningModeConfig  learn_cfg = LearningModeConfig{})
        : policy_(std::move(policy)),
          esc_cfg_(esc_cfg),
          hyst_cfg_(hyst_cfg),
          cool_cfg_(cool_cfg),
          learn_cfg_(learn_cfg) {}

    void on_alert   (AlertCallback    cb) { on_alert_    = std::move(cb); }
    void on_block   (BlockCallback    cb) { on_block_    = std::move(cb); }
    void on_escalate(EscalateCallback cb) { on_escalate_ = std::move(cb); }

    void reconfig(DecisionPolicy      policy,
                  EscalationConfig    esc_cfg,
                  HysteresisConfig    hyst_cfg,
                  CooldownConfig      cool_cfg,
                  LearningModeConfig  learn_cfg) {
        policy_   = std::move(policy);
        esc_cfg_  = esc_cfg;
        hyst_cfg_ = hyst_cfg;
        cool_cfg_ = cool_cfg;
        learn_cfg_ = learn_cfg;
    }

    void execute(ReasoningResult& res,  // non-const — we write trace.final_decision
                 const Event& ev,
                 const GlobalState& gs,
                 const DecisionThresholds& thresholds = {}) {
        try {
            if (res.false_positive || res.confidence < policy_.min_confidence)
                return;

            // § 3.11 Fixed override order
            Decision final_d = apply_overrides(
                res.decision, ev, gs, tracker_, policy_, esc_cfg_);

            // § 3.12 Hysteresis
            final_d = apply_hysteresis(ev.source, final_d, res.confidence, thresholds);

            // § 3.13 Cooldown
            if (!allow_by_cooldown(ev.source, final_d)) return;

            // Learning mode suppresses blocking (§6.13)
            if (learn_cfg_.enabled && learn_cfg_.disable_blocking) {
                if (final_d == Decision::Block || final_d == Decision::Escalate)
                    final_d = Decision::Alert;
            }

            res.trace.final_decision = final_d;

            Alert alert{ final_d, res.confidence, res.attack_class,
                         res.explanation, ev.source, ev.destination,
                         ev.payload.port_src, ev.payload.port_dst,
                         std::to_string(ev.payload.protocol),
                         ev.type, ev.time, res.trace };

            tracker_.record(ev.source);
            tracker_.expire(esc_cfg_.repeat_window_s);

            // Dispatch
            switch (final_d) {
            case Decision::Block:
                if (on_block_) on_block_(ev.source);
                if (on_alert_) on_alert_(alert);
                break;
            case Decision::Escalate:
                if (on_escalate_) on_escalate_(alert);
                if (on_alert_)    on_alert_(alert);
                break;
            case Decision::Alert:
            case Decision::Log:
                if (on_alert_) on_alert_(alert);
                break;
            case Decision::Ignore: break;
            }

            last_decision_[ev.source]      = final_d;
            last_decision_time_[ev.source] = std::chrono::steady_clock::now();

        } catch (...) {
            // § 5 fault — emit safe fallback log
            Alert fallback{ Decision::Log, 0.f, "fault", "[decision fault]",
                            ev.source, ev.destination,
                            ev.payload.port_src, ev.payload.port_dst,
                            std::to_string(ev.payload.protocol),
                            ev.type, ev.time, {} };
            if (on_alert_) on_alert_(fallback);
        }
    }

private:
    Decision apply_hysteresis(const std::string& src, Decision d,
                               float score, const DecisionThresholds& t) {
        auto it = last_decision_.find(src);
        if (it == last_decision_.end()) return d;
        auto tt = last_decision_time_.find(src);
        if (tt == last_decision_time_.end()) return d;
        float age = std::chrono::duration<float>(
            std::chrono::steady_clock::now() - tt->second).count();
        if (age < hyst_cfg_.decision_hold_time_s) {
            if (it->second == Decision::Block &&
                score >= t.block_threshold - hyst_cfg_.decision_hysteresis)
                return Decision::Block;
        }
        return d;
    }

    bool allow_by_cooldown(const std::string& src, Decision d) {
        auto it = last_decision_time_.find(src);
        if (it == last_decision_time_.end()) return true;
        float age = std::chrono::duration<float>(
            std::chrono::steady_clock::now() - it->second).count();
        auto ld = last_decision_.count(src) ? last_decision_.at(src) : Decision::Ignore;

        if (ld == Decision::Block && age < cool_cfg_.block_cooldown_s) {
            if (!cool_cfg_.allow_stronger || d != Decision::Escalate)
                return false;
        }
        if (ld == Decision::Alert && age < cool_cfg_.alert_cooldown_s) {
            if (!cool_cfg_.allow_stronger ||
                (d != Decision::Block && d != Decision::Escalate))
                return false;
        }
        return true;
    }

    DecisionPolicy      policy_;
    EscalationConfig    esc_cfg_;
    HysteresisConfig    hyst_cfg_;
    CooldownConfig      cool_cfg_;
    LearningModeConfig  learn_cfg_;
    RepeatTracker       tracker_;
    AlertCallback       on_alert_;
    BlockCallback       on_block_;
    EscalateCallback    on_escalate_;
    std::unordered_map<std::string, Decision> last_decision_;
    std::unordered_map<std::string, Time>     last_decision_time_;
};

}  // namespace ids
