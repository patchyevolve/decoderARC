#pragma once
#include "ids_types.hpp"
#include <deque>
#include <mutex>
#include <atomic>
#include <ostream>
#include <chrono>
#include <thread>

namespace ids {

// ─── EMA latency tracker ──────────────────────────────────────
class EMATracker {
public:
    explicit EMATracker(float alpha = 0.01f) : alpha_(alpha) {}

    void record(float val_us) {
        avg_us_ += alpha_ * (val_us - avg_us_);
        if (val_us > p99_us_) p99_us_ = val_us;   // simplified max-tracked p99
    }

    float avg_us() const { return avg_us_; }
    float p99_us() const { return p99_us_; }
    void  reset()        { avg_us_ = 0.f; p99_us_ = 0.f; }

private:
    float alpha_;
    float avg_us_ = 0.f;
    float p99_us_ = 0.f;
};

// ─── Fault log ────────────────────────────────────────────────
struct FaultLog {
    std::deque<FaultRecord> records;
    size_t max_records = 1000;
    mutable std::mutex mu;

    void append(FaultRecord r) {
        std::lock_guard<std::mutex> lk(mu);
        records.push_back(std::move(r));
        if (records.size() > max_records) records.pop_front();
    }

    std::vector<FaultRecord> last_n(size_t n) const {
        std::lock_guard<std::mutex> lk(mu);
        size_t start = records.size() > n ? records.size() - n : 0;
        return std::vector<FaultRecord>(records.begin() + start, records.end());
    }

    std::vector<FaultRecord> by_type(FaultType t) const {
        std::lock_guard<std::mutex> lk(mu);
        std::vector<FaultRecord> out;
        for (const auto& r : records) if (r.type == t) out.push_back(r);
        return out;
    }

    void export_json(std::ostream& out) const {
        std::lock_guard<std::mutex> lk(mu);
        out << "[";
        bool first = true;
        for (const auto& r : records) {
            if (!first) out << ",";
            out << "{\"key\":\"" << r.key << "\",\"detail\":\"" << r.detail << "\"}";
            first = false;
        }
        out << "]";
    }
};

// ─── Drift time series ────────────────────────────────────────
struct DriftTimeSeries {
    std::deque<TimeSeriesSample> samples;
    size_t max_samples = 10000;
    mutable std::mutex mu;

    void record(const GlobalState& gs, float alert_threshold, float gate_threshold) {
        std::lock_guard<std::mutex> lk(mu);
        TimeSeriesSample s;
        s.time             = std::chrono::steady_clock::now();
        s.drift_score      = gs.drift_score;
        s.anomaly_history  = gs.anomaly_history;
        s.alert_threshold  = alert_threshold;
        s.gate_threshold   = gate_threshold;
        s.baseline_energy  = 0.f;
        for (float v : gs.baseline_model) s.baseline_energy += v*v;
        samples.push_back(s);
        if (samples.size() > max_samples) samples.pop_front();
    }

    std::vector<TimeSeriesSample> last_n(size_t n) const {
        std::lock_guard<std::mutex> lk(mu);
        size_t start = samples.size() > n ? samples.size() - n : 0;
        return std::vector<TimeSeriesSample>(samples.begin() + start, samples.end());
    }

    void export_json(std::ostream& out) const {
        std::lock_guard<std::mutex> lk(mu);
        out << "[";
        bool first = true;
        for (const auto& s : samples) {
            if (!first) out << ",";
            out << "{\"drift\":" << s.drift_score
                << ",\"hist\":" << s.anomaly_history << "}";
            first = false;
        }
        out << "]";
    }
};

// ─── Routing debug log ────────────────────────────────────────
struct RoutingDebugLog {
    std::deque<RoutingLogEntry> entries;
    size_t ring_size = 10000;
    bool   enabled   = false;
    mutable std::mutex mu;

    void append(RoutingLogEntry e) {
        if (!enabled) return;
        std::lock_guard<std::mutex> lk(mu);
        entries.push_back(std::move(e));
        if (entries.size() > ring_size) entries.pop_front();
    }

    std::vector<RoutingLogEntry> last_n(size_t n) const {
        std::lock_guard<std::mutex> lk(mu);
        size_t start = entries.size() > n ? entries.size() - n : 0;
        return std::vector<RoutingLogEntry>(entries.begin() + start, entries.end());
    }
};

// ─── Stage latency tracker ────────────────────────────────────
struct StageLatencyTracker {
    EMATracker l0, l1, l2, mem_write, retrieval, reasoning, correlation, decision, total;

    StageLatency snapshot() const {
        StageLatency s;
        s.l0_avg_us           = l0.avg_us();
        s.l1_avg_us           = l1.avg_us();
        s.l2_avg_us           = l2.avg_us();
        s.memory_write_avg_us = mem_write.avg_us();
        s.retrieval_avg_us    = retrieval.avg_us();
        s.reasoning_avg_us    = reasoning.avg_us();
        s.correlation_avg_us  = correlation.avg_us();
        s.decision_avg_us     = decision.avg_us();
        s.total_avg_us        = total.avg_us();
        s.l0_p99_us           = l0.p99_us();
        s.retrieval_p99_us    = retrieval.p99_us();
        s.reasoning_p99_us    = reasoning.p99_us();
        s.total_p99_us        = total.p99_us();
        return s;
    }
};

// ─── Simple timing helper ────────────────────────────────────
struct ScopeTimer {
    using Clock = std::chrono::steady_clock;
    Clock::time_point start_;
    EMATracker&       tracker_;
    ScopeTimer(EMATracker& t) : start_(Clock::now()), tracker_(t) {}
    ~ScopeTimer() {
        float us = std::chrono::duration<float, std::micro>(
            Clock::now() - start_).count();
        tracker_.record(us);
    }
};

// ─── §9.14 Replay config ─────────────────────────────────────
struct ReplayConfig {
    std::string event_log_path;
    bool        compare_to_reference  = false;
    std::string reference_output_path;
    float       speed_multiplier      = 0.f;
};

struct ReplayResult {
    size_t events_replayed  = 0;
    size_t alert_matches    = 0;
    size_t alert_mismatches = 0;
    float  avg_latency_us   = 0.f;
};

// ─── TelemetryExporter ────────────────────────────────────────
class TelemetryExporter {
public:
    TelemetryExporter(const Metrics&             metrics,
                      const HealthStats&          health,
                      const DriftTimeSeries&      drift,
                      const FaultLog&             faults,
                      const StageLatencyTracker&  latency)
        : metrics_(metrics), health_(health),
          drift_(drift), faults_(faults), latency_(latency) {}

    void export_metrics(std::ostream& out) const {
        out << "{\"events_total\":" << metrics_.events_total.load()
            << ",\"alerts_total\":" << metrics_.alerts_total.load()
            << ",\"blocks_total\":" << metrics_.blocks_total.load()
            << ",\"faults_total\":" << metrics_.faults_total.load()
            << "}";
    }

    void export_drift_series(std::ostream& out) const { drift_.export_json(out); }
    void export_fault_log(std::ostream& out)    const { faults_.export_json(out); }

    void export_latency(std::ostream& out) const {
        auto s = latency_.snapshot();
        out << "{\"l0_avg\":" << s.l0_avg_us
            << ",\"reasoning_avg\":" << s.reasoning_avg_us
            << ",\"total_avg\":" << s.total_avg_us << "}";
    }

    // §9.17 MetricsSink — background push at interval_s
    using MetricsSink = std::function<void(const Metrics&)>;

    void set_sink(MetricsSink sink, float interval_s = 1.0f) {
        sink_          = std::move(sink);
        sink_interval_ = interval_s;
        if (sink_ && !sink_thread_running_.load()) {
            sink_thread_running_ = true;
            sink_thread_ = std::thread([this]() {
                while (sink_thread_running_.load()) {
                    std::this_thread::sleep_for(
                        std::chrono::duration<float>(sink_interval_));
                    if (sink_ && sink_thread_running_.load())
                        sink_(metrics_);
                }
            });
        }
    }

    void stop_sink() {
        sink_thread_running_ = false;
        if (sink_thread_.joinable()) sink_thread_.join();
    }

    ~TelemetryExporter() { stop_sink(); }

private:
    const Metrics&            metrics_;
    const HealthStats&        health_;
    const DriftTimeSeries&    drift_;
    const FaultLog&           faults_;
    const StageLatencyTracker&latency_;
    MetricsSink               sink_;
    float                     sink_interval_       = 1.f;
    std::atomic<bool>         sink_thread_running_ {false};
    std::thread               sink_thread_;
};

}  // namespace ids
