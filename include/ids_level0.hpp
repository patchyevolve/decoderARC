#pragma once
#include "ids_types.hpp"
#include <algorithm>
#include <cmath>
#include <deque>
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
        rolling_mean_[0] = rolling_mean_[1] = 0.f;
        rolling_var_[0]  = rolling_var_[1]  = 0.f;
    }

private:
    Vec embed(const Event& ev) const {
        Vec v{};
        const auto& p = ev.payload;
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
        size_t sh = std::hash<std::string>{}(ev.source);
        size_t dh = std::hash<std::string>{}(ev.destination);
        for (size_t i = 11; i < 16; ++i)
            v[i] = static_cast<float>((sh >> (i * 5)) & 0x1F) / 31.f;
        for (size_t i = 16; i < 21; ++i)
            v[i] = static_cast<float>((dh >> (i * 5)) & 0x1F) / 31.f;
        if (buffer_.size() >= 2) {
            auto& prev = buffer_[buffer_.size() - 2];
            float dt = std::chrono::duration<float>(ev.time - prev.time).count();
            v[21] = std::clamp(dt / 10.f, 0.f, 1.f);
        }
        v[22] = rolling_mean_[0];
        v[23] = rolling_mean_[1];
        v[24] = sqrtf(std::max(0.f, rolling_var_[0]));
        v[25] = sqrtf(std::max(0.f, rolling_var_[1]));
        return v;
    }

    float scoreAnomaly(const Event& ev, const LocalState& ls) {
        const auto& p = ev.payload;
        float feat[2] = { static_cast<float>(p.bytes_in + p.bytes_out), p.rate_hz };
        size_t n = buffer_.size();
        for (int i = 0; i < 2; ++i) {
            float delta = feat[i] - rolling_mean_[i];
            rolling_mean_[i] += delta / static_cast<float>(n + 1);
            float delta2 = feat[i] - rolling_mean_[i];
            rolling_var_[i] +=
                (delta * delta2 - rolling_var_[i]) / static_cast<float>(n + 1);
        }
        if (n < 4) return 0.f;
        float score = 0.f;
        for (int i = 0; i < 2; ++i) {
            float sigma = sqrtf(std::max(1e-6f, rolling_var_[i]));
            float z     = fabsf(feat[i] - rolling_mean_[i]) / sigma;
            score       = std::max(score, z);
        }
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
    float             rolling_mean_[2] = {};
    float             rolling_var_[2]  = {};
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
