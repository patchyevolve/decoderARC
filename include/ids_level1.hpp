#pragma once
#include "ids_ssm.hpp"
#include "ids_types.hpp"
#include <optional>

namespace ids {

// Top-level config to avoid GCC CWG-2631 default-arg restriction
struct SegmentSSMConfig {
    FlushRules    flush      = {};
    L1SSM::Params ssm_params = {};
};

// ─── Level 1 — Segment SSM (per-key, §1.4 flush rules) ───────
class SegmentSSM {
public:
    // Expose for IDS::IDSConfig compatibility
    using Config = SegmentSSMConfig;

    explicit SegmentSSM(const SegmentSSMConfig& cfg = SegmentSSMConfig{})
        : cfg_(cfg), ssm_(makeDefaultSSM(cfg.ssm_params)) {}

    std::optional<SegmentState> update(const LocalState& ls, const Event& ev) {
        auto out = ssm_.step(ls.embedding);

        ++count_;
        score_acc_ += ls.anomaly_score;
        rate_acc_  += ev.payload.rate_hz;
        type_freq_[static_cast<uint8_t>(ev.type)]++;
        if (ls.anomaly_score > 0.5f) ++error_count_;

        // § 1.4 FlushRules — any condition triggers flush
        bool by_count   = (count_ >= cfg_.flush.flush_n);
        bool by_anomaly = count_ > 0 &&
                          (score_acc_ / static_cast<float>(count_) >
                           cfg_.flush.flush_anomaly);
        bool by_time = false;
        if (last_flush_time_) {
            float dt = std::chrono::duration<float>(
                           ev.time - *last_flush_time_).count();
            by_time = (dt >= cfg_.flush.flush_t);
        } else {
            last_flush_time_ = ev.time;
        }
        bool by_session_end = cfg_.flush.flush_on_session_end &&
                              ev.metadata.count("session_end");
        bool by_type_change = cfg_.flush.flush_on_type_change &&
                              (last_dominant_type_ != EventType::Unknown &&
                               ev.type != last_dominant_type_);

        last_dominant_type_ = ev.type;

        if (by_count || by_anomaly || by_time || by_session_end || by_type_change)
            return flush(out, ev.time);
        return std::nullopt;
    }

    void reset() {
        ssm_.reset();
        count_ = 0; score_acc_ = 0.f; rate_acc_ = 0.f; error_count_ = 0;
        type_freq_ = {}; last_flush_time_ = std::nullopt;
        last_dominant_type_ = EventType::Unknown;
        segment_count_ = 0;
    }

    uint64_t segment_count() const { return segment_count_; }

    // Serialisable accumulator state (SSM internal state is not persisted)
    struct AccumState {
        uint64_t segment_count;
        size_t   count;
        float    score_acc;
        float    rate_acc;
        size_t   error_count;
        std::array<int, 8> type_freq;
    };

    AccumState save_accum() const {
        return { segment_count_, count_, score_acc_, rate_acc_,
                 error_count_, type_freq_ };
    }

    void restore_accum(const AccumState& s) {
        segment_count_ = s.segment_count;
        count_         = s.count;
        score_acc_     = s.score_acc;
        rate_acc_      = s.rate_acc;
        error_count_   = s.error_count;
        type_freq_     = s.type_freq;
    }

private:
    SegmentState flush(const std::array<float, kSSMStateDim>& ssm_out, Time now) {
        SegmentState s;
        for (size_t i = 0; i < kSSMStateDim; ++i) s.state_vector[i] = ssm_out[i];
        float n = static_cast<float>(std::max(count_, size_t(1)));
        s.anomaly_trend = score_acc_ / n;
        s.rate_mean     = rate_acc_  / n;
        s.error_freq    = static_cast<float>(error_count_) / n;
        uint8_t dom = 0; int mx = 0;
        for (int i = 0; i < 8; ++i)
            if (type_freq_[i] > mx) { mx = type_freq_[i]; dom = uint8_t(i); }
        s.dominant_type = eventTypeName(static_cast<EventType>(dom));
        count_ = 0; score_acc_ = 0.f; rate_acc_ = 0.f; error_count_ = 0;
        type_freq_ = {}; last_flush_time_ = now;
        ++segment_count_;
        return s;
    }

    static L1SSM makeDefaultSSM(const L1SSM::Params& p_in) {
        L1SSM::Params p = p_in;
        bool zero = true;
        for (float v : p.A_log) if (v != 0.f) { zero = false; break; }
        if (zero) {
            for (auto& a : p.A_log) a = -0.5f;
            for (size_t i = 0; i < kSSMStateDim; ++i) {
                p.B_proj[i * kEmbeddingDim + (i % kEmbeddingDim)] = 0.1f;
                p.C_proj[i * kSSMStateDim  + i]                   = 1.f;
                p.delta_proj[i * kEmbeddingDim + (i % kEmbeddingDim)] = 0.5f;
            }
        }
        return L1SSM(p);
    }

    static std::string eventTypeName(EventType t) {
        switch (t) {
        case EventType::NetworkPacket: return "net";
        case EventType::SysLog:        return "log";
        case EventType::ProcessEvent:  return "proc";
        case EventType::AuthEvent:     return "auth";
        case EventType::FileAccess:    return "file";
        case EventType::ApiCall:       return "api";
        case EventType::Signal:        return "sig";
        default:                       return "unk";
        }
    }

    SegmentSSMConfig    cfg_;
    L1SSM               ssm_;
    size_t              count_        = 0;
    float               score_acc_    = 0.f;
    float               rate_acc_     = 0.f;
    size_t              error_count_  = 0;
    std::array<int, 8>  type_freq_    = {};
    std::optional<Time> last_flush_time_;
    EventType           last_dominant_type_ = EventType::Unknown;
    uint64_t            segment_count_ = 0;
};

}  // namespace ids
