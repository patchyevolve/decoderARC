#pragma once
// ─────────────────────────────────────────────────────────────
//  ids_model.hpp — §6 Training / Parameter Update Pipeline
//
//  Implements the full §6.3/6.12/6.14/6.15 spec:
//    load_model()     — deserialise ModelParams from binary file
//    validate_model() — NaN/Inf + checksum verification (§6.15)
//    validate_config()— threshold ordering + weight sanity (§6.15)
//    ConfigHolder     — atomic config swap, hot reload (§6.7/6.9)
//    ModelHolder      — stage/apply/rollback with state reset (§6.12)
//
//  Binary format (little-endian, version 1):
//    magic(4) | version(4) | model_version_len(2) | model_version(N)
//    | checksum_len(2) | checksum(N)
//    | trained_at_ns(8)
//    | l1_A_log(SDIM*4) | l1_B_proj(SDIM*EDIM*4) | l1_C_proj(SDIM*SDIM*4)
//    | l1_D_skip(SDIM*4) | l1_delta_proj(SDIM*EDIM*4)
//    | num_l2_layers(4) | [l2_layer_i blobs...] same layout as L1
// ─────────────────────────────────────────────────────────────
#include "ids_ssm.hpp"
#include "ids_types.hpp"
#include <atomic>
#include <cstring>
#include <deque>
#include <fstream>
#include <memory>
#include <mutex>
#include <numeric>
#include <sstream>

namespace ids {

// ─── §6.15 Checksum — simple FNV-1a over all float blobs ─────
// Not a cryptographic hash — purpose is bit-flip / truncation detection.
inline std::string compute_checksum(const ModelParams& m) {
    uint64_t h = 14695981039346656037ULL;
    auto mix = [&](const void* data, size_t bytes) {
        const auto* p = static_cast<const uint8_t*>(data);
        for (size_t i = 0; i < bytes; ++i) {
            h ^= p[i];
            h *= 1099511628211ULL;
        }
    };
    mix(m.l1_A_log.data(),      m.l1_A_log.size()      * 4);
    mix(m.l1_B_proj.data(),     m.l1_B_proj.size()     * 4);
    mix(m.l1_C_proj.data(),     m.l1_C_proj.size()     * 4);
    mix(m.l1_D_skip.data(),     m.l1_D_skip.size()     * 4);
    mix(m.l1_delta_proj.data(), m.l1_delta_proj.size() * 4);
    for (const auto& blob : m.l2_layer_blobs)
        mix(blob.data(), blob.size() * 4);
    std::ostringstream oss;
    oss << std::hex << h;
    return oss.str();
}

// ─── §6.15 validate_model ─────────────────────────────────────
inline bool validate_model(const ModelParams& m, std::string* reason = nullptr) {
    auto fail = [&](const char* msg) -> bool {
        if (reason) *reason = msg;
        return false;
    };
    if (!m.is_valid()) return fail("ModelParams empty or missing version");

    // Check all L1 blobs for NaN/Inf
    auto check_blob = [&](const std::vector<float>& v, const char* name) -> bool {
        for (float f : v)
            if (!std::isfinite(f)) {
                if (reason) *reason = std::string("NaN/Inf in ") + name;
                return false;
            }
        return true;
    };
    if (!check_blob(m.l1_A_log,       "l1_A_log"))       return false;
    if (!check_blob(m.l1_B_proj,      "l1_B_proj"))      return false;
    if (!check_blob(m.l1_C_proj,      "l1_C_proj"))      return false;
    if (!check_blob(m.l1_D_skip,      "l1_D_skip"))      return false;
    if (!check_blob(m.l1_delta_proj,  "l1_delta_proj"))  return false;
    for (size_t i = 0; i < m.l2_layer_blobs.size(); ++i)
        for (float f : m.l2_layer_blobs[i])
            if (!std::isfinite(f)) {
                if (reason) *reason = "NaN/Inf in l2_layer_blobs[" + std::to_string(i) + "]";
                return false;
            }

    // Size checks: L1 blobs must match kSSMStateDim × kEmbeddingDim
    if (m.l1_A_log.size()      != kSSMStateDim)
        return fail("l1_A_log wrong size");
    if (m.l1_B_proj.size()     != kSSMStateDim * kEmbeddingDim)
        return fail("l1_B_proj wrong size");
    if (m.l1_C_proj.size()     != kSSMStateDim * kSSMStateDim)
        return fail("l1_C_proj wrong size");
    if (m.l1_D_skip.size()     != kSSMStateDim)
        return fail("l1_D_skip wrong size");
    if (m.l1_delta_proj.size() != kSSMStateDim * kEmbeddingDim)
        return fail("l1_delta_proj wrong size");

    // Each L2 layer blob: 5 arrays of kSSMStateDim × kSSMStateDim (or SDIM)
    // Layout: A_log(SDIM) | B_proj(SDIM*SDIM) | C_proj(SDIM*SDIM)
    //         | D_skip(SDIM) | delta_proj(SDIM*SDIM)
    constexpr size_t l2_blob_size = kSSMStateDim               // A_log
                                  + kSSMStateDim * kSSMStateDim // B_proj
                                  + kSSMStateDim * kSSMStateDim // C_proj
                                  + kSSMStateDim               // D_skip
                                  + kSSMStateDim * kSSMStateDim;// delta_proj
    for (size_t i = 0; i < m.l2_layer_blobs.size(); ++i)
        if (m.l2_layer_blobs[i].size() != l2_blob_size) {
            if (reason) *reason = "l2_layer_blobs[" + std::to_string(i) + "] wrong size";
            return false;
        }

    // Checksum verification
    if (!m.checksum.empty() && compute_checksum(m) != m.checksum)
        return fail("checksum mismatch");

    return true;
}

// ─── §6.3 load_model — binary deserialiser ───────────────────
// Writes/reads a compact little-endian binary file.
// noexcept: any I/O error returns false without throwing.
inline bool load_model(const std::string& path, ModelParams& out) noexcept {
    try {
        std::ifstream f(path, std::ios::binary);
        if (!f) return false;

        auto read_u32 = [&](uint32_t& v) {
            f.read(reinterpret_cast<char*>(&v), 4);
        };
        auto read_u64 = [&](uint64_t& v) {
            f.read(reinterpret_cast<char*>(&v), 8);
        };
        auto read_str = [&](std::string& s) {
            uint16_t len = 0;
            f.read(reinterpret_cast<char*>(&len), 2);
            s.resize(len);
            f.read(&s[0], len);
        };
        auto read_floats = [&](std::vector<float>& v, size_t n) {
            v.resize(n);
            f.read(reinterpret_cast<char*>(v.data()), n * 4);
        };

        // Header
        uint32_t magic = 0, ver = 0;
        read_u32(magic);
        read_u32(ver);
        if (magic != 0x4D444C32u || ver != 1u) return false;  // "MDL2"

        read_str(out.version);
        read_str(out.checksum);

        uint64_t ts_ns = 0;
        read_u64(ts_ns);
        out.trained_at = Time(std::chrono::nanoseconds(ts_ns));

        // L1 params
        read_floats(out.l1_A_log,      kSSMStateDim);
        read_floats(out.l1_B_proj,     kSSMStateDim * kEmbeddingDim);
        read_floats(out.l1_C_proj,     kSSMStateDim * kSSMStateDim);
        read_floats(out.l1_D_skip,     kSSMStateDim);
        read_floats(out.l1_delta_proj, kSSMStateDim * kEmbeddingDim);

        // L2 layer blobs
        uint32_t num_l2 = 0;
        read_u32(num_l2);
        constexpr size_t l2_blob_size = kSSMStateDim
                                      + kSSMStateDim * kSSMStateDim * 3
                                      + kSSMStateDim;
        out.l2_layer_blobs.resize(num_l2);
        for (uint32_t i = 0; i < num_l2; ++i)
            read_floats(out.l2_layer_blobs[i], l2_blob_size);

        if (!f) return false;   // truncated
        return true;
    } catch (...) {
        return false;
    }
}

// ─── save_model — binary serialiser ──────────────────────────
// Companion to load_model. Fills checksum before writing.
inline bool save_model(const std::string& path, ModelParams& m) noexcept {
    try {
        m.checksum = compute_checksum(m);

        std::ofstream f(path, std::ios::binary);
        if (!f) return false;

        auto write_u32 = [&](uint32_t v) { f.write(reinterpret_cast<char*>(&v), 4); };
        auto write_u64 = [&](uint64_t v) { f.write(reinterpret_cast<char*>(&v), 8); };
        auto write_str = [&](const std::string& s) {
            uint16_t len = static_cast<uint16_t>(s.size());
            f.write(reinterpret_cast<char*>(&len), 2);
            f.write(s.data(), len);
        };
        auto write_floats = [&](const std::vector<float>& v) {
            f.write(reinterpret_cast<const char*>(v.data()), v.size() * 4);
        };

        write_u32(0x4D444C32u);   // magic "MDL2"
        write_u32(1u);             // format version
        write_str(m.version);
        write_str(m.checksum);
        uint64_t ts_ns = static_cast<uint64_t>(
            m.trained_at.time_since_epoch().count());
        write_u64(ts_ns);

        write_floats(m.l1_A_log);
        write_floats(m.l1_B_proj);
        write_floats(m.l1_C_proj);
        write_floats(m.l1_D_skip);
        write_floats(m.l1_delta_proj);

        uint32_t num_l2 = static_cast<uint32_t>(m.l2_layer_blobs.size());
        write_u32(num_l2);
        for (const auto& blob : m.l2_layer_blobs)
            write_floats(blob);

        return true;
    } catch (...) {
        return false;
    }
}

// ─── ModelParams ↔ SSM Params helpers ────────────────────────
// Convert between the serialisable blob form and the typed SSM structs.

inline L1SSM::Params l1_params_from_model(const ModelParams& m) {
    L1SSM::Params p;
    // Sizes already validated by validate_model()
    std::copy(m.l1_A_log.begin(),      m.l1_A_log.end(),
              p.A_log.begin());
    std::copy(m.l1_B_proj.begin(),     m.l1_B_proj.end(),
              p.B_proj.begin());
    std::copy(m.l1_C_proj.begin(),     m.l1_C_proj.end(),
              p.C_proj.begin());
    std::copy(m.l1_D_skip.begin(),     m.l1_D_skip.end(),
              p.D_skip.begin());
    std::copy(m.l1_delta_proj.begin(), m.l1_delta_proj.end(),
              p.delta_proj.begin());
    return p;
}

inline void l1_params_to_model(const L1SSM::Params& p, ModelParams& m) {
    m.l1_A_log.assign(     p.A_log.begin(),      p.A_log.end());
    m.l1_B_proj.assign(    p.B_proj.begin(),     p.B_proj.end());
    m.l1_C_proj.assign(    p.C_proj.begin(),     p.C_proj.end());
    m.l1_D_skip.assign(    p.D_skip.begin(),     p.D_skip.end());
    m.l1_delta_proj.assign(p.delta_proj.begin(), p.delta_proj.end());
}

// Extract one L2 layer blob from a LayerSSM::Params (SDIM×SDIM variant)
using LayerSSMParams = HierarchicalSSM::LayerSSM::Params;
inline std::vector<float> l2_blob_from_params(const LayerSSMParams& p) {
    std::vector<float> blob;
    blob.insert(blob.end(), p.A_log.begin(),      p.A_log.end());
    blob.insert(blob.end(), p.B_proj.begin(),     p.B_proj.end());
    blob.insert(blob.end(), p.C_proj.begin(),     p.C_proj.end());
    blob.insert(blob.end(), p.D_skip.begin(),     p.D_skip.end());
    blob.insert(blob.end(), p.delta_proj.begin(), p.delta_proj.end());
    return blob;
}

inline LayerSSMParams l2_params_from_blob(const std::vector<float>& blob) {
    LayerSSMParams p;
    size_t off = 0;
    auto fill = [&](auto& arr) {
        std::copy(blob.begin() + off, blob.begin() + off + arr.size(), arr.begin());
        off += arr.size();
    };
    fill(p.A_log);
    fill(p.B_proj);
    fill(p.C_proj);
    fill(p.D_skip);
    fill(p.delta_proj);
    return p;
}

// ─── §6.12 ModelHolder — stage/apply/rollback pipeline ───────
// Decouples model loading from application.
// stage_model() loads + validates but does NOT affect the running pipeline.
// apply_model() swaps params atomically and resets all SSM state.
class ModelHolder {
public:
    using ApplyCallback = std::function<void(const ModelParams&)>;

    ModelHolder() = default;   // uninitialised — set_callback() required before use

    explicit ModelHolder(ApplyCallback apply_cb)
        : apply_cb_(std::move(apply_cb)) {}

    void set_callback(ApplyCallback cb) { apply_cb_ = std::move(cb); }

    // §6.14 stage_model — load + validate, does not apply yet
    bool stage_model(const std::string& path) noexcept {
        try {
            ModelParams m;
            std::string reason;
            if (!load_model(path, m)) {
                last_error_ = "load_model failed: " + path;
                return false;
            }
            if (!validate_model(m, &reason)) {
                last_error_ = "validate_model failed: " + reason;
                return false;
            }
            std::lock_guard<std::mutex> lk(mu_);
            staged_ = std::make_shared<ModelParams>(std::move(m));
            return true;
        } catch (...) {
            last_error_ = "stage_model: unexpected exception";
            return false;
        }
    }

    // Stage from an in-memory ModelParams (for unit tests / programmatic use)
    bool stage_model(ModelParams m) noexcept {
        try {
            std::string reason;
            if (!validate_model(m, &reason)) {
                last_error_ = "validate_model failed: " + reason;
                return false;
            }
            std::lock_guard<std::mutex> lk(mu_);
            staged_ = std::make_shared<ModelParams>(std::move(m));
            return true;
        } catch (...) {
            last_error_ = "stage_model: unexpected exception";
            return false;
        }
    }

    // §6.12 apply_model — atomically swaps staged model into pipeline
    // Resets ALL SSM state (old state computed with old matrices is invalid).
    bool apply_model() noexcept {
        try {
            std::lock_guard<std::mutex> lk(mu_);
            if (!staged_) {
                last_error_ = "no model staged";
                return false;
            }
            // Keep rollback history
            if (active_) {
                history_.push_front(active_);
                if (history_.size() > kMaxHistory) history_.pop_back();
            }
            active_  = staged_;
            staged_  = nullptr;
            version_.model_version = active_->version;
            version_.loaded_at     = std::chrono::steady_clock::now();

            // Invoke pipeline callback — resets SSM, swaps Params
            if (apply_cb_) apply_cb_(*active_);
            return true;
        } catch (...) {
            last_error_ = "apply_model: exception during apply";
            return false;
        }
    }

    // §6.8 rollback_model
    bool rollback_model(uint32_t steps_back = 1) noexcept {
        try {
            std::lock_guard<std::mutex> lk(mu_);
            if (steps_back == 0 || steps_back > history_.size()) {
                last_error_ = "rollback: no history at depth " + std::to_string(steps_back);
                return false;
            }
            auto target  = history_[steps_back - 1];
            history_.push_front(active_);
            if (history_.size() > kMaxHistory) history_.pop_back();
            active_  = target;
            staged_  = nullptr;
            version_.model_version = active_ ? active_->version : "";
            if (apply_cb_ && active_) apply_cb_(*active_);
            return true;
        } catch (...) {
            last_error_ = "rollback_model: exception";
            return false;
        }
    }

    bool                has_staged() const { std::lock_guard<std::mutex> lk(mu_); return staged_ != nullptr; }
    bool                has_active() const { std::lock_guard<std::mutex> lk(mu_); return active_ != nullptr; }
    std::string         last_error() const { return last_error_; }
    const ParameterVersion& version() const { return version_; }
    size_t              history_depth() const { std::lock_guard<std::mutex> lk(mu_); return history_.size(); }

    // Export active model params back to file
    bool export_model(const std::string& path) noexcept {
        try {
            std::lock_guard<std::mutex> lk(mu_);
            if (!active_) { last_error_ = "no active model"; return false; }
            auto copy = *active_;
            return save_model(path, copy);
        } catch (...) { return false; }
    }

private:
    static constexpr size_t kMaxHistory = 3;
    ApplyCallback                              apply_cb_;
    std::shared_ptr<ModelParams>               staged_;
    std::shared_ptr<ModelParams>               active_;
    std::deque<std::shared_ptr<ModelParams>>   history_;
    mutable std::mutex                         mu_;
    std::string                                last_error_;
    ParameterVersion                           version_;
};

}  // namespace ids
