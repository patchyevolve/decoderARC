#pragma once
#include "ids_types.hpp"
#include <cmath>
#include <stdexcept>
#include <vector>

namespace ids {

// ─── SSM (Mamba-style selective state space model) ────────────
template <size_t SDIM, size_t IDIM, size_t ODIM>
class SSM {
public:
    using SVec = std::array<float, SDIM>;
    using IVec = std::array<float, IDIM>;
    using OVec = std::array<float, ODIM>;

    struct Params {
        std::array<float, SDIM>          A_log       = {};
        std::array<float, SDIM * IDIM>   B_proj      = {};
        std::array<float, ODIM * SDIM>   C_proj      = {};
        std::array<float, ODIM>          D_skip      = {};
        std::array<float, SDIM * IDIM>   delta_proj  = {};
    };

    explicit SSM(const Params& p) : params_(p) { reset(); }

    void reset() { state_.fill(0.f); }
    SVec state() const { return state_; }

    float energy() const {
        float e = 0.f;
        for (float v : state_) e += v * v;
        return sqrtf(e);
    }

    // step() with mandatory §5.3 NaN/energy checks
    OVec step(const IVec& x,
              float max_energy  = 100.f,
              float clamp_limit = 10.f) {
        // Input-dependent delta (softplus)
        std::array<float, SDIM> delta{};
        for (size_t i = 0; i < SDIM; ++i) {
            float d = 0.f;
            for (size_t j = 0; j < IDIM; ++j)
                d += params_.delta_proj[i * IDIM + j] * x[j];
            delta[i] = d > 20.f ? d : std::log1pf(expf(d));
        }

        // ZOH discretization: A_bar = exp(-delta * exp(A_log))
        std::array<float, SDIM> A_bar{};
        for (size_t i = 0; i < SDIM; ++i)
            A_bar[i] = expf(-delta[i] * expf(params_.A_log[i]));

        // B(x) * x
        std::array<float, SDIM> Bx{};
        for (size_t i = 0; i < SDIM; ++i)
            for (size_t j = 0; j < IDIM; ++j)
                Bx[i] += params_.B_proj[i * IDIM + j] * x[j];

        // h_t = A_bar * h_{t-1} + delta * B * x
        for (size_t i = 0; i < SDIM; ++i)
            state_[i] = A_bar[i] * state_[i] + delta[i] * Bx[i];

        // §5.3 NaN/Inf check
        for (size_t i = 0; i < SDIM; ++i) {
            if (!std::isfinite(state_[i])) {
                state_.fill(0.f);
                throw std::runtime_error("SSM NaN/Inf in state");
            }
        }

        // §5.3 Energy clamp
        float e = energy();
        if (e > max_energy) {
            for (auto& s : state_)
                s = std::clamp(s, -clamp_limit, clamp_limit);
            if (energy() > max_energy * 2.f) {
                state_.fill(0.f);
                throw std::runtime_error("SSM energy overflow after clamp");
            }
        }

        // y = C * h + D * x
        OVec y{};
        for (size_t i = 0; i < ODIM; ++i) {
            for (size_t k = 0; k < SDIM; ++k)
                y[i] += params_.C_proj[i * SDIM + k] * state_[k];
            if (i < IDIM)
                y[i] += params_.D_skip[i] * x[i];
        }
        return y;
    }

private:
    Params params_;
    SVec   state_;
};

using L1SSM = SSM<kSSMStateDim, kEmbeddingDim, kSSMStateDim>;

// ─── Hierarchical SSM with signal-driven promotion (§1.5–1.7) ─
class HierarchicalSSM {
public:
    using LayerSSM = SSM<kSSMStateDim, kSSMStateDim, kSSMStateDim>;

    struct Config {
        // Tick rates kept as fallback / floor for time-based promotion
        std::array<uint32_t, kNumHierarchyLvl>         tick_rates   = {1, 10, 60, 600};
        std::array<LayerSSM::Params, kNumHierarchyLvl> layer_params = {};
        StateConfig                                     state_cfg    = {};
        // §1.5–1.7 signal-driven promotion rules (wired in update())
        L1ToL2sPromotionRules  promote_l1_l2s  = {};
        L2sToL2mPromotionRules promote_l2s_l2m = {};
        L2mToL2lPromotionRules promote_l2m_l2l = {};
        SkipRules              skip             = {};
    };

    explicit HierarchicalSSM(const Config& cfg) : cfg_(cfg) {
        for (size_t i = 0; i < kNumHierarchyLvl; ++i)
            layers_.emplace_back(cfg_.layer_params[i]);
    }

    // §1.13 step 4 — conditional promotion through the hierarchy
    // seg:          fresh SegmentState from L1
    // seg_count:    total segments processed so far (for skip.min_segments)
    // force_all:    §1.11 ForceRules override — bypasses all skip/tick checks
    GlobalState update(const SegmentState& seg,
                       uint64_t seg_count = 0,
                       bool force_all     = false) {
        ++tick_;

        // ── Layer 0 (L2s) — §1.5 PromotionRules L1→L2s ──────
        bool promote_l2s = force_all
            || cfg_.promote_l1_l2s.promote_on_flush  // always on flush by default
            || (seg.anomaly_trend > cfg_.promote_l1_l2s.promote_threshold);

        // §1.8 SkipRules — suppress noise from reaching L2s
        bool skip_l2s = !force_all
            && (seg.anomaly_trend < cfg_.skip.skip_threshold)
            && (seg_count < cfg_.skip.min_segments);

        if (promote_l2s && !skip_l2s) {
            std::array<float, kSSMStateDim> inp{};
            for (size_t i = 0; i < kSSMStateDim; ++i) inp[i] = seg.state_vector[i];
            try {
                auto out = layers_[0].step(
                    inp, cfg_.state_cfg.max_energy, cfg_.state_cfg.clamp_limit);
                global_.level_states[0] = stateFromArr(out);
            } catch (...) {
                layers_[0].reset();
                global_.level_states[0] = {};
            }
        }

        // ── Layer 1 (L2m) — §1.6 PromotionRules L2s→L2m ─────
        bool promote_l2m = force_all
            || (tick_ % cfg_.tick_rates[1] == 0)               // tick fallback
            || (global_.anomaly_history > cfg_.promote_l2s_l2m.mid_anomaly)
            || (global_.drift_score     > cfg_.promote_l2s_l2m.mid_drift);

        bool skip_l2m = !force_all
            && (global_.anomaly_history < cfg_.skip.skip_threshold)
            && (global_.drift_score     < cfg_.skip.skip_drift);

        if (promote_l2m && !skip_l2m) {
            std::array<float, kSSMStateDim> inp{};
            for (size_t k = 0; k < kSSMStateDim; ++k)
                inp[k] = global_.level_states[0][k];
            try {
                auto out = layers_[1].step(
                    inp, cfg_.state_cfg.max_energy, cfg_.state_cfg.clamp_limit);
                global_.level_states[1] = stateFromArr(out);
            } catch (...) {
                layers_[1].reset();
                global_.level_states[1] = {};
            }
        }

        // ── Layer 2 (L2l short) — §1.7 L2m→L2l ──────────────
        bool promote_l2l = force_all
            || (tick_ % cfg_.tick_rates[2] == 0)
            || (global_.drift_score     > cfg_.promote_l2m_l2l.global_drift)
            || (global_.anomaly_history > cfg_.promote_l2m_l2l.global_hist);

        bool skip_l2l = !force_all
            && (global_.anomaly_history < cfg_.promote_l2m_l2l.global_hist)
            && (global_.drift_score     < cfg_.promote_l2m_l2l.global_drift);

        if (promote_l2l && !skip_l2l) {
            std::array<float, kSSMStateDim> inp{};
            for (size_t k = 0; k < kSSMStateDim; ++k)
                inp[k] = global_.level_states[1][k];
            try {
                auto out = layers_[2].step(
                    inp, cfg_.state_cfg.max_energy, cfg_.state_cfg.clamp_limit);
                global_.level_states[2] = stateFromArr(out);
            } catch (...) {
                layers_[2].reset();
                global_.level_states[2] = {};
            }
        }

        // ── Layer 3 (L2l global) — slowest, §1.7 global tick ─
        bool promote_global = force_all
            || (tick_ % cfg_.tick_rates[3] == 0)
            || (global_.drift_score > cfg_.promote_l2m_l2l.global_drift * 1.5f);

        if (promote_global) {
            std::array<float, kSSMStateDim> inp{};
            for (size_t k = 0; k < kSSMStateDim; ++k)
                inp[k] = global_.level_states[2][k];
            try {
                auto out = layers_[3].step(
                    inp, cfg_.state_cfg.max_energy, cfg_.state_cfg.clamp_limit);
                global_.level_states[3] = stateFromArr(out);
            } catch (...) {
                layers_[3].reset();
                global_.level_states[3] = {};
            }
        }

        // Baseline EMA on deepest promoted state
        constexpr float alpha = 0.01f;
        for (size_t k = 0; k < kStateVecDim; ++k) {
            size_t src = k < kSSMStateDim ? k : k - kSSMStateDim;
            global_.baseline_model[k] +=
                alpha * (global_.level_states[kNumHierarchyLvl - 1][src]
                         - global_.baseline_model[k]);
        }

        // Drift = L2(deepest_state, baseline)
        float drift = 0.f;
        for (size_t k = 0; k < kSSMStateDim; ++k) {
            float d = global_.level_states[kNumHierarchyLvl - 1][k]
                      - global_.baseline_model[k];
            drift += d * d;
        }
        global_.drift_score = sqrtf(drift);

        // Anomaly history EMA (τ = 0.05)
        global_.anomaly_history +=
            0.05f * (seg.anomaly_trend - global_.anomaly_history);

        return global_;
    }

    GlobalState state() const { return global_; }

    void reset() {
        for (auto& l : layers_) l.reset();
        global_ = {};
        tick_   = 0;
    }

    // Per-layer energy for health monitoring
    std::array<float, kNumHierarchyLvl> layer_energies() const {
        std::array<float, kNumHierarchyLvl> e{};
        for (size_t i = 0; i < kNumHierarchyLvl; ++i)
            e[i] = layers_[i].energy();
        return e;
    }

private:
    static State stateFromArr(const std::array<float, kSSMStateDim>& a) {
        State s{};
        for (size_t i = 0; i < kSSMStateDim; ++i) s[i] = a[i];
        return s;
    }

    Config                 cfg_;
    std::vector<LayerSSM>  layers_;
    GlobalState            global_;
    uint64_t               tick_ = 0;
};

}  // namespace ids
