#pragma once
#include "ids_types.hpp"
#include <algorithm>
#include <chrono>
#include <deque>
#include <unordered_map>

namespace ids {

// ─── Correlation config ───────────────────────────────────────
struct CorrelationWindowConfig {
    float short_window_s    =    60.f;
    float mid_window_s      =   600.f;
    float long_window_s     =  3600.f;
    float campaign_window_s = 86400.f;
};

struct RepeatDetectionConfig {
    uint32_t repeat_threshold = 3;
    float    repeat_window_s  = 60.f;
};

struct AttackPattern {
    std::string              name;
    std::vector<std::string> sequence;
    float                    max_gap_s;
};

struct MultiStageConfig {
    std::vector<AttackPattern> patterns = {
        { "LateralMovement",
          {"PortScan","BruteForce/CredentialStuffing","LateralMovement/Persistence"},
          600.f },
        { "APT-Exfiltration",
          {"BruteForce/CredentialStuffing","FileSystemAnomaly/Ransomware",
           "EncryptedC2/Exfiltration"},
          3600.f }
    };
    bool enabled = true;
};

struct DistributedAttackConfig {
    uint32_t    unique_source_threshold = 5;
    float       dist_window_s           = 60.f;
    std::string target_scope            = "host";
};

struct SlowAttackConfig {
    float    slow_window_s        = 3600.f;
    uint32_t slow_event_threshold = 10;
    float    slow_score_threshold = 0.30f;
};

struct CorrelationWeights {
    float repeat_weight   = 0.20f;
    float stage_weight    = 0.30f;
    float dist_weight     = 0.25f;
    float slow_weight     = 0.15f;
    float campaign_weight = 0.10f;
};

struct CorrelationLimits {
    size_t max_records_per_ip   = 500;
    size_t max_records_per_user = 500;
    size_t max_records_per_host = 1000;
    size_t max_global_records   = 5000;
    size_t max_active_campaigns = 200;
};

struct CampaignTimeoutConfig {
    float campaign_idle_timeout_s = 1800.f;
    float campaign_max_age_s      = 86400.f;
};

struct CorrelationConfig {
    CorrelationWeights weights;
    CampaignTimeoutConfig campaign;
};

// ─── Store ────────────────────────────────────────────────────
struct CorrelationStore {
    std::unordered_map<std::string, std::deque<AlertRecord>> ip_records;
    std::unordered_map<std::string, std::deque<AlertRecord>> user_records;
    std::unordered_map<std::string, std::deque<AlertRecord>> host_records;
    std::deque<AlertRecord>                                   global_records;
};

inline float now_s() {
    return std::chrono::duration<float>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

// ─── CorrelationEngine ────────────────────────────────────────
class CorrelationEngine {
public:
    explicit CorrelationEngine(CorrelationConfig       cfg        = {},
                               CorrelationLimits       limits     = {},
                               CorrelationWindowConfig win        = {},
                               MultiStageConfig        ms         = {},
                               DistributedAttackConfig da         = {},
                               SlowAttackConfig        sa         = {},
                               RepeatDetectionConfig   repeat_cfg = {})
        : cfg_(cfg), limits_(limits), win_(win), ms_(ms), da_(da), sa_(sa),
          repeat_cfg_(repeat_cfg) {}

    void reconfig(CorrelationConfig       cfg,
                  CorrelationLimits       limits,
                  MultiStageConfig        ms,
                  DistributedAttackConfig da,
                  SlowAttackConfig        sa) {
        cfg_   = cfg;
        limits_= limits;
        ms_    = ms;
        da_    = da;
        sa_    = sa;
    }

    CorrelationResult process(const ReasoningResult& res,
                              const Event& ev,
                              const GlobalState& gs) {
        (void)gs;  // reserved for global anomaly context weighting
        CorrelationResult cr;
        if (res.decision == Decision::Ignore) return cr;

        // Build AlertRecord
        AlertRecord ar;
        ar.attack_class  = res.attack_class;
        ar.score         = res.confidence;
        ar.decision      = res.decision;
        ar.source        = ev.source;
        ar.destination   = ev.destination;
        ar.key.ip        = ev.source;
        ar.key.host      = ev.destination;
        if (ev.metadata.count("user")) ar.key.user = ev.metadata.at("user");

        // Store
        auto& ip_dq = store_.ip_records[ev.source];
        ip_dq.push_back(ar);
        if (ip_dq.size() > limits_.max_records_per_ip) ip_dq.pop_front();

        auto& host_dq = store_.host_records[ev.destination];
        host_dq.push_back(ar);
        if (host_dq.size() > limits_.max_records_per_host) host_dq.pop_front();

        store_.global_records.push_back(ar);
        if (store_.global_records.size() > limits_.max_global_records)
            store_.global_records.pop_front();

        float score = 0.f;

        // Repeat detection
        cr.repeat_detected = detect_repeat(ev.source);
        if (cr.repeat_detected) {
            score += cfg_.weights.repeat_weight;
            cr.correlation_type = "repeat";
        }

        // Multi-stage
        if (ms_.enabled) {
            cr.multi_stage_detected = detect_multi_stage(ev.source, res.attack_class);
            if (cr.multi_stage_detected) {
                score += cfg_.weights.stage_weight;
                cr.correlation_type = "multi_stage";
            }
        }

        // Distributed
        cr.distributed_detected = detect_distributed(ev.destination);
        if (cr.distributed_detected) {
            score += cfg_.weights.dist_weight;
            cr.correlation_type = "distributed";
        }

        // Slow attack
        cr.slow_attack_detected = detect_slow(ev.source);
        if (cr.slow_attack_detected) {
            score += cfg_.weights.slow_weight;
            cr.correlation_type = "slow_attack";
        }

        cr.corr_score = std::clamp(score, 0.f, 1.f);

        // Campaign management
        update_campaign(ar, cr);
        cr.campaign_id = active_campaign_for(ev.source);

        // Decision upgrade
        if (score > 0.4f && res.decision == Decision::Alert)
            cr.upgraded_decision = Decision::Escalate;
        else
            cr.upgraded_decision = res.decision;

        return cr;
    }

    std::vector<CampaignState> active_campaigns() const {
        std::vector<CampaignState> out;
        for (const auto& [id, c] : campaigns_)
            if (c.active) out.push_back(c);
        return out;
    }

    void sweep(float ts_now_s) {
        // Expire old records
        float cutoff = ts_now_s - win_.campaign_window_s;
        for (auto& [k, dq] : store_.ip_records)
            while (!dq.empty() &&
                   std::chrono::duration<float>(dq.front().time.time_since_epoch()).count() < cutoff)
                dq.pop_front();

        // Expire campaigns — erase inactive
        std::vector<std::string> expired;
        for (auto& [id, c] : campaigns_) {
            if (!c.active) { expired.push_back(id); continue; }
            float idle = std::chrono::duration<float>(
                std::chrono::steady_clock::now() - c.last_seen).count();
            if (idle > cfg_.campaign.campaign_idle_timeout_s)
                expired.push_back(id);
        }
        for (const auto& eid : expired) campaigns_.erase(eid);
    }

    void reset(const StateKey& key) {
        store_.ip_records.erase(key.ip);
        store_.host_records.erase(key.host);
    }

private:
    bool detect_repeat(const std::string& ip) const {
        auto it = store_.ip_records.find(ip);
        if (it == store_.ip_records.end()) return false;
        float cutoff = now_s() - repeat_cfg_.repeat_window_s;
        uint32_t count = 0;
        for (const auto& r : it->second) {
            if (std::chrono::duration<float>(r.time.time_since_epoch()).count() >= cutoff)
                ++count;
        }
        return count >= repeat_cfg_.repeat_threshold;
    }

    bool detect_multi_stage(const std::string& ip, const std::string& cls) const {
        (void)cls;  // stage class matched via pattern sequence below
        auto it = store_.ip_records.find(ip);
        if (it == store_.ip_records.end()) return false;
        for (const auto& pat : ms_.patterns) {
            // Check if sequence appears in order in the record deque
            size_t matched = 0;
            float  last_t  = 0.f;
            for (const auto& r : it->second) {
                if (matched < pat.sequence.size() &&
                    r.attack_class == pat.sequence[matched]) {
                    float t = std::chrono::duration<float>(r.time.time_since_epoch()).count();
                    if (matched == 0 || (t - last_t) <= pat.max_gap_s) {
                        ++matched; last_t = t;
                    }
                }
            }
            if (matched == pat.sequence.size()) return true;
        }
        return false;
    }

    bool detect_distributed(const std::string& host) const {
        auto it = store_.host_records.find(host);
        if (it == store_.host_records.end()) return false;
        float cutoff = now_s() - da_.dist_window_s;
        std::unordered_map<std::string, bool> sources;
        for (const auto& r : it->second)
            if (std::chrono::duration<float>(r.time.time_since_epoch()).count() >= cutoff)
                sources[r.source] = true;
        return sources.size() >= da_.unique_source_threshold;
    }

    bool detect_slow(const std::string& ip) const {
        auto it = store_.ip_records.find(ip);
        if (it == store_.ip_records.end()) return false;
        float cutoff = now_s() - sa_.slow_window_s;
        uint32_t count = 0;
        for (const auto& r : it->second)
            if (std::chrono::duration<float>(r.time.time_since_epoch()).count() >= cutoff &&
                r.score >= sa_.slow_score_threshold)
                ++count;
        return count >= sa_.slow_event_threshold;
    }

    void update_campaign(const AlertRecord& ar, CorrelationResult& cr) {
        (void)cr;
        for (auto& [id, c] : campaigns_) {
            if (!c.active) continue;
            bool src_match = false;
            for (const auto& s : c.sources) if (s == ar.source) { src_match = true; break; }
            if (!src_match && c.attack_class != ar.attack_class) continue;
            c.last_seen   = std::chrono::steady_clock::now();
            c.event_count++;
            c.max_score   = std::max(c.max_score, ar.score);
            if (c.sources.empty() || c.sources.back() != ar.source)
                c.sources.push_back(ar.source);
            if (c.hosts.empty() || c.hosts.back() != ar.destination)
                c.hosts.push_back(ar.destination);
            constexpr size_t kMaxCampaignSources = 2048;
            if (c.sources.size() > kMaxCampaignSources) c.sources.erase(c.sources.begin(),
                c.sources.end() - kMaxCampaignSources / 2);
            if (c.hosts.size() > kMaxCampaignSources) c.hosts.erase(c.hosts.begin(),
                c.hosts.end() - kMaxCampaignSources / 2);
            return;
        }

        if (ar.score < 0.4f) return;
        if (campaigns_.size() >= limits_.max_active_campaigns) return;

        CampaignState camp;
        camp.id          = "camp_" + std::to_string(campaigns_.size());
        camp.attack_class= ar.attack_class;
        camp.sources     = {ar.source};
        camp.hosts       = {ar.destination};
        camp.first_seen  = std::chrono::steady_clock::now();
        camp.last_seen   = camp.first_seen;
        camp.event_count = 1;
        camp.max_score   = ar.score;
        campaigns_[camp.id] = camp;
    }

    std::string active_campaign_for(const std::string& ip) const {
        for (const auto& [id, c] : campaigns_) {
            if (!c.active) continue;
            for (const auto& s : c.sources) if (s == ip) return id;
        }
        return "";
    }

    CorrelationConfig       cfg_;
    CorrelationLimits       limits_;
    CorrelationWindowConfig win_;
    MultiStageConfig        ms_;
    DistributedAttackConfig da_;
    SlowAttackConfig        sa_;
    RepeatDetectionConfig   repeat_cfg_;
    CorrelationStore        store_;
    std::unordered_map<std::string, CampaignState> campaigns_;
};

}  // namespace ids
