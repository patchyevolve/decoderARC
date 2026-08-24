#pragma once
#include "ids_types.hpp"
#include <algorithm>
#include <cmath>
#include <deque>
#include <fstream>
#include <numeric>

namespace ids {

// ─── Level 0 — Local Analyzer ────────────────────────────────
class LocalAnalyzer {
public:
    explicit LocalAnalyzer(size_t window = kLocalWindow) : window_(window) {}

    LocalState process(const Event& ev) {
        buffer_.push_back(ev);
        if (buffer_.size() > window_) buffer_.pop_front();

        LocalState ls;
        ls.embedding     = embed(ev);
        ls.entropy       = computeEntropy();
        ls.burst_metric  = burstMetric();
        ls.anomaly_score = scoreAnomaly(ev, ls);
        return ls;
    }

    void reset() {
        buffer_.clear();
        for (auto& m : rolling_mean_) m = 0.f;
        for (auto& v : rolling_var_)  v = 0.f;
    }

public:
    bool save_state(const std::string& path) const {
        std::ofstream f(path, std::ios::binary);
        if (!f) return false;
        uint32_t n = static_cast<uint32_t>(window_);
        f.write(reinterpret_cast<const char*>(&n), sizeof(n));
        f.write(reinterpret_cast<const char*>(rolling_mean_), sizeof(rolling_mean_));
        f.write(reinterpret_cast<const char*>(rolling_var_),  sizeof(rolling_var_));
        return f.good();
    }

    bool load_state(const std::string& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return false;
        uint32_t n = 0;
        f.read(reinterpret_cast<char*>(&n), sizeof(n));
        if (!f) return false;
        window_ = n;
        f.read(reinterpret_cast<char*>(rolling_mean_), sizeof(rolling_mean_));
        f.read(reinterpret_cast<char*>(rolling_var_),  sizeof(rolling_var_));
        return f.good();
    }

private:
    static constexpr int kFeatures = 6;

    Vec embed(const Event& ev) const {
        Vec v{};
        const auto& p = ev.payload;
        const auto& f = ev.flow;
        v[0]  = normalize(p.bytes_in,  0, 65535);
        v[1]  = normalize(p.bytes_out, 0, 65535);
        v[2]  = normalize(p.port_src,  0, 65535);
        v[3]  = normalize(p.port_dst,  0, 65535);
        v[4]  = static_cast<float>(p.protocol) / 255.f;
        v[5]  = static_cast<float>(p.flags)    / 255.f;
        v[6]  = std::clamp(p.entropy, 0.f, 1.f);
        v[7]  = std::clamp(p.rate_hz / 1000.f, 0.f, 1.f);
        v[8]  = static_cast<float>(ev.type) / 8.f;
        v[9]  = burstMetric();
        v[10] = computeEntropy();
        // Flow stats
        v[11] = normalize(static_cast<float>(f.packets_total), 0, 1000);
        v[12] = normalize(f.packet_size_mean, 0, 1500);
        v[13] = normalize(f.iat_mean, 0, 10);
        v[14] = normalize(static_cast<float>(f.syn_count), 0, 50);
        v[15] = normalize(f.duration, 0, 100);
        v[16] = normalize(f.down_up_ratio, 0, 10);
        size_t sh = std::hash<std::string>{}(ev.source);
        size_t dh = std::hash<std::string>{}(ev.destination);
        for (size_t i = 17; i < 22; ++i)
            v[i] = static_cast<float>((sh >> ((i - 17) * 5)) & 0x1F) / 31.f;
        for (size_t i = 22; i < 27; ++i)
            v[i] = static_cast<float>((dh >> ((i - 22) * 5)) & 0x1F) / 31.f;
        if (buffer_.size() >= 2) {
            auto& prev = buffer_[buffer_.size() - 2];
            float dt = std::chrono::duration<float>(ev.time - prev.time).count();
            v[27] = std::clamp(dt / 10.f, 0.f, 1.f);
        }
        for (int i = 0; i < kFeatures; ++i) {
            v[28 + i]     = rolling_mean_[i];
            v[28 + kFeatures + i] = sqrtf(std::max(0.f, rolling_var_[i]));
        }
        return v;
    }

    float scoreAnomaly(const Event& ev, const LocalState& ls) {
        const auto& p = ev.payload;
        const auto& f = ev.flow;
        float feat[kFeatures] = {
            static_cast<float>(p.bytes_in + p.bytes_out),
            p.rate_hz,
            static_cast<float>(f.packets_total),
            f.packet_size_mean,
            f.iat_mean,
            static_cast<float>(f.syn_count)
        };
        size_t n = buffer_.size();
        for (int i = 0; i < kFeatures; ++i) {
            float delta = feat[i] - rolling_mean_[i];
            rolling_mean_[i] += delta / static_cast<float>(n + 1);
            float delta2 = feat[i] - rolling_mean_[i];
            rolling_var_[i] +=
                (delta * delta2 - rolling_var_[i]) / static_cast<float>(n + 1);
        }
        if (n < 4) return 0.f;
        float sum_sq = 0.f, max_z = 0.f;
        for (int i = 0; i < kFeatures; ++i) {
            float sigma = sqrtf(std::max(1e-6f, rolling_var_[i]));
            float z     = fabsf(feat[i] - rolling_mean_[i]) / sigma;
            sum_sq     += z * z;
            max_z       = std::max(max_z, z);
        }
        // L2-norm across features catches weak-but-consistent anomalies
        float score = sqrtf(sum_sq / static_cast<float>(kFeatures));
        // Keep max_z as a floor to preserve single-spike detection
        score = std::max(score, max_z * 0.5f);
        // Per-feature boosts for known attack indicators
        if (f.syn_count > 5 && f.ack_count < f.syn_count / 2)
            score += 0.4f; // SYN flood / portscan
        if (f.packets_total > 100 && f.packet_size_mean < 100.f)
            score += 0.3f; // many small packets → DoS
        if (f.iat_mean < 0.001f && f.packets_total > 50)
            score += 0.3f; // burst of packets
        if (f.down_up_ratio > 5.f && f.bytes_bwd > f.bytes_fwd * 3)
            score += 0.3f; // asymmetric traffic
        if (f.iat_std > f.iat_mean * 3.f && f.iat_mean > 0.001f)
            score += 0.25f; // irregular timing → scan/probe
        if (f.fin_count > f.syn_count * 2 && f.syn_count > 3)
            score += 0.3f; // FIN scan
        score += ls.entropy > 0.85f ? 0.5f : 0.f;
        score += ls.burst_metric > 0.7f ? 0.3f : 0.f;
        return std::clamp(score / 5.f, 0.f, 1.f);
    }

    float computeEntropy() const {
        if (buffer_.empty()) return 0.f;
        std::array<int, 256> freq{};
        for (const auto& e : buffer_) freq[e.payload.protocol]++;
        float H = 0.f, n = static_cast<float>(buffer_.size());
        for (int c : freq) {
            if (!c) continue;
            float p = c / n;
            H -= p * std::log2f(p);
        }
        return H / 8.f;
    }

    float burstMetric() const {
        if (buffer_.size() < 3) return 0.f;
        std::vector<float> iats;
        iats.reserve(buffer_.size() - 1);
        for (size_t i = 1; i < buffer_.size(); ++i) {
            float dt = std::chrono::duration<float>(
                           buffer_[i].time - buffer_[i-1].time).count();
            iats.push_back(dt);
        }
        float mean = std::accumulate(iats.begin(), iats.end(), 0.f) /
                     static_cast<float>(iats.size());
        if (mean < 1e-9f) return 1.f;
        float var = 0.f;
        for (float d : iats) var += (d - mean) * (d - mean);
        var /= static_cast<float>(iats.size());
        return std::clamp(sqrtf(var) / mean, 0.f, 1.f);
    }

    static float normalize(float v, float lo, float hi) {
        return (v - lo) / (hi - lo + 1e-9f);
    }

    size_t            window_;
    std::deque<Event> buffer_;
    float             rolling_mean_[kFeatures] = {};
    float             rolling_var_[kFeatures]  = {};
};

// § 5.8 Input validation
inline bool validate_event(const Event& ev) {
    if (ev.source.empty())                   return false;
    if (ev.type == EventType::Unknown)       return false;
    if (!std::isfinite(ev.payload.entropy))  return false;
    if (!std::isfinite(ev.payload.rate_hz))  return false;
    return true;
}

}  // namespace ids
