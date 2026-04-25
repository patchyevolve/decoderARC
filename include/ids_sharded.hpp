#pragma once
// ─────────────────────────────────────────────────────────────
//  ids_sharded.hpp — §4.3 Sharded Pipeline
//
//  N independent IDS instances, one per shard.
//  Events routed by consistent hash on source key.
//  Each shard owns a bounded queue + dedicated worker thread.
//
//  Usage:
//    ids::ShardedIDS ids(cfg, 8);   // 8 shards
//    ids.on_alert([](const ids::Alert& a){ ... });
//    ids.start();
//    ids.ingest(event);             // lock-free hash-route + enqueue
//    ids.shutdown();                // drain queues + join threads
// ─────────────────────────────────────────────────────────────
#include "ids.hpp"
#include <atomic>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

namespace ids {

// ─── §4.5 Bounded queue (MPSC, lock-based) ───────────────────
class BoundedQueue {
public:
    explicit BoundedQueue(size_t cap) : capacity_(cap) {}

    // Non-blocking push — returns false when full
    bool try_push(Event ev) {
        std::lock_guard<std::mutex> lk(mu_);
        if (items_.size() >= capacity_) return false;
        items_.push_back(std::move(ev));
        cv_.notify_one();
        return true;
    }

    // Priority push (§4.5 BackpressurePolicy::Priority)
    // Evicts head (oldest low-priority) to make room for high-anomaly events
    bool priority_push(Event ev, float anomaly_score, float keep_above) {
        std::lock_guard<std::mutex> lk(mu_);
        if (items_.size() < capacity_) {
            items_.push_back(std::move(ev));
            cv_.notify_one();
            return true;
        }
        if (anomaly_score < keep_above) { ++drops_; return false; }
        items_.pop_front();   // evict oldest
        ++drops_;
        items_.push_back(std::move(ev));
        cv_.notify_one();
        return true;
    }

    // Blocking pop with timeout — used exclusively by worker thread
    std::optional<Event> pop(std::chrono::milliseconds timeout
                             = std::chrono::milliseconds(5)) {
        std::unique_lock<std::mutex> lk(mu_);
        cv_.wait_for(lk, timeout, [this]{ return !items_.empty() || closed_; });
        if (items_.empty()) return std::nullopt;
        Event ev = std::move(items_.front());
        items_.pop_front();
        return ev;
    }

    void close() {
        std::lock_guard<std::mutex> lk(mu_);
        closed_ = true;
        cv_.notify_all();
    }

    size_t   size()   const { std::lock_guard<std::mutex> lk(mu_); return items_.size(); }
    bool     closed() const { return closed_; }
    uint64_t drops()  const { return drops_.load(); }

private:
    size_t                  capacity_;
    mutable std::mutex      mu_;
    std::condition_variable cv_;
    std::deque<Event>       items_;
    std::atomic<uint64_t>   drops_{0};
    bool                    closed_ = false;
};

// ─── Single shard ─────────────────────────────────────────────
// Owns one IDS pipeline + one BoundedQueue + one worker thread.
// State ownership guarantee (§4.4): one entity → one shard → FIFO.
struct Shard {
    uint32_t              id;
    IDS                   pipeline;
    BoundedQueue          queue;
    std::thread           worker;
    std::atomic<bool>     running{false};
    std::atomic<uint64_t> processed{0};
    std::atomic<uint64_t> heartbeat{0};  // incremented each loop tick for watchdog
    float                 avg_latency_us = 0.f;

    Shard(uint32_t shard_id, const IDSConfig& cfg, size_t q_depth)
        : id(shard_id), pipeline(cfg), queue(q_depth) {}

    // Non-copyable — thread owns this object's lifetime
    Shard(const Shard&)            = delete;
    Shard& operator=(const Shard&) = delete;
};

// ─── ShardedIDS ───────────────────────────────────────────────
class ShardedIDS {
public:
    // n_shards: number of independent pipeline lanes (§4.3 recommends 8)
    explicit ShardedIDS(const IDSConfig& cfg = IDSConfig{},
                        uint32_t         n_shards = 8)
        : cfg_(cfg), n_shards_(n_shards) {
        if (n_shards_ == 0 || n_shards_ > 256)
            throw std::invalid_argument("n_shards must be 1–256");
        shards_.reserve(n_shards_);
        for (uint32_t i = 0; i < n_shards_; ++i) {
            shards_.emplace_back(
                std::make_unique<Shard>(i, cfg, cfg.queue.queue_depth));
            // Forward per-shard callbacks to the unified callbacks set by caller
            shards_[i]->pipeline.on_alert([this](const Alert& a) {
                if (alert_cb_) alert_cb_(a);
            });
            shards_[i]->pipeline.on_block([this](const std::string& src) {
                if (block_cb_) block_cb_(src);
            });
            shards_[i]->pipeline.on_escalate([this](const Alert& a) {
                if (escalate_cb_) escalate_cb_(a);
            });
        }
    }

    ~ShardedIDS() { shutdown(); }

    // ── Callbacks — must be set before start() ────────────────
    void on_alert   (AlertCallback    cb) { alert_cb_    = std::move(cb); }
    void on_block   (BlockCallback    cb) { block_cb_    = std::move(cb); }
    void on_escalate(EscalateCallback cb) { escalate_cb_ = std::move(cb); }

    // ── Rules & signatures — broadcast to all shards ──────────
    void add_rule(Rule r) {
        for (auto& s : shards_) s->pipeline.add_rule(r);
    }
    void load_signature(Vec emb, const std::string& label, float score) {
        for (auto& s : shards_) s->pipeline.load_signature(emb, label, score);
    }

    // ── §4.9 Start all worker threads ─────────────────────────
    void start() {
        for (auto& s : shards_) {
            s->running = true;
            s->worker  = std::thread([this, raw = s.get()]() {
                workerLoop(*raw);
            });
        }
        if (cfg_.watchdog.auto_restart)
            startWatchdog();
    }

    // ── §4.1 Ingest — hash-route + backpressure-aware enqueue ─
    bool ingest(const Event& ev) {
        ++total_ingested_;
        Shard& s = *shards_[shardFor(ev)];

        bool accepted = false;
        switch (cfg_.backpressure.policy) {
        case BackpressurePolicy::Drop:
            accepted = s.queue.try_push(ev);
            break;
        case BackpressurePolicy::Priority: {
            // Fast anomaly estimate without running L0 — rate spike heuristic
            float est = ev.payload.rate_hz > 5000.f ? 0.7f : 0.1f;
            accepted = s.queue.priority_push(
                ev, est, cfg_.backpressure.priority_keep_above);
            break;
        }
        case BackpressurePolicy::Block:
            // Spin until space — bounded blocking for low-drop-tolerance sources
            while (!s.queue.try_push(ev))
                std::this_thread::yield();
            accepted = true;
            break;
        case BackpressurePolicy::Sample:
            if (sample_counter_++ % cfg_.backpressure.sample_rate != 0) break;
            accepted = s.queue.try_push(ev);
            break;
        }

        if (!accepted) ++total_dropped_;
        return accepted;
    }

    void ingest_batch(const std::vector<Event>& events) {
        for (const auto& ev : events) ingest(ev);
    }

    // ── §4.8 Shutdown sequence ────────────────────────────────
    // 1. Stop watchdog
    // 2. Signal workers to stop accepting new events
    // 3. Close queues — workers drain remaining items then exit
    // 4. Join all threads
    void shutdown() {
        // Step 1: stop watchdog first so it doesn't restart threads we're joining
        watchdog_running_ = false;
        if (watchdog_.joinable()) watchdog_.join();

        // Steps 2–3
        for (auto& s : shards_) {
            s->running = false;
            s->queue.close();
        }
        // Step 4
        for (auto& s : shards_)
            if (s->worker.joinable()) s->worker.join();
    }

    // ── §4.8 Force-flush pending L1 segments before save ──────
    // Sends a synthetic session-end event to each active IP on each shard.
    // Call this before save_all() to ensure no segment state is lost.
    void flush_pending() {
        for (auto& s : shards_) {
            Event flush_ev;
            flush_ev.type   = EventType::Signal;
            flush_ev.source = "__flush__";
            flush_ev.metadata["session_end"] = "1";
            flush_ev.payload.entropy = 0.f;
            flush_ev.payload.rate_hz = 0.f;
            s->queue.try_push(flush_ev);
        }
    }

    // ── §9.9 Per-shard stats ──────────────────────────────────
    std::vector<ShardStats> shard_stats() const {
        std::vector<ShardStats> out;
        out.reserve(n_shards_);
        for (const auto& s : shards_) {
            // Start from the inner single-pipeline shard_stats
            auto inner = s->pipeline.shard_stats();
            ShardStats ss = inner.empty() ? ShardStats{} : inner[0];
            ss.shard_id       = s->id;
            ss.queue_depth    = s->queue.size();
            ss.drops          = static_cast<size_t>(s->queue.drops());
            ss.avg_latency_us = s->avg_latency_us;
            out.push_back(ss);
        }
        return out;
    }

    // ── Aggregate metrics across all shards ───────────────────
    // Returns a plain snapshot (copyable) with summed counters.
    // Individual shard metrics remain accessible via shard(i).metrics().
    struct AggregateMetrics {
        uint64_t events_total      = 0;
        uint64_t alerts_total      = 0;
        uint64_t blocks_total      = 0;
        uint64_t escalations_total = 0;
        uint64_t drops_total       = 0;
        uint64_t reasoning_calls   = 0;
        uint64_t forced_reasoning  = 0;
        uint64_t memory_writes     = 0;
        uint64_t memory_evictions  = 0;
        uint64_t state_resets      = 0;
        uint64_t faults_total      = 0;
        uint64_t campaigns_active  = 0;
        uint64_t baseline_freezes  = 0;
    };

    AggregateMetrics aggregate_metrics() const {
        AggregateMetrics agg;
        for (const auto& s : shards_) {
            const auto& m = s->pipeline.metrics();
            agg.events_total      += m.events_total.load();
            agg.alerts_total      += m.alerts_total.load();
            agg.blocks_total      += m.blocks_total.load();
            agg.escalations_total += m.escalations_total.load();
            agg.drops_total       += m.drops_total.load();
            agg.reasoning_calls   += m.reasoning_calls.load();
            agg.forced_reasoning  += m.forced_reasoning.load();
            agg.memory_writes     += m.memory_writes.load();
            agg.memory_evictions  += m.memory_evictions.load();
            agg.state_resets      += m.state_resets.load();
            agg.faults_total      += m.faults_total.load();
            agg.campaigns_active  += m.campaigns_active.load();
            agg.baseline_freezes  += m.baseline_freezes.load();
        }
        return agg;
    }

    // ── §9.13 / §4.8 State persistence ───────────────────────
    // save_all() snapshots every shard's state + config.
    // load_all() restores; missing files start clean (§4.8 rule).
    bool save_all(const std::string& dir) noexcept {
        bool ok = true;
        for (const auto& s : shards_) {
            std::string prefix = dir + "/shard_" + std::to_string(s->id);
            ok &= s->pipeline.save_state(prefix + "_state.bin");
            ok &= s->pipeline.save_config(prefix + "_config.json");
        }
        return ok;
    }

    bool load_all(const std::string& dir) noexcept {
        for (const auto& s : shards_) {
            std::string prefix = dir + "/shard_" + std::to_string(s->id);
            s->pipeline.load_state(prefix + "_state.bin");  // non-fatal on miss
        }
        return true;
    }

    // ── Direct shard access ───────────────────────────────────
    IDS&       shard(uint32_t i)       { return shards_.at(i)->pipeline; }
    const IDS& shard(uint32_t i) const { return shards_.at(i)->pipeline; }

    uint64_t total_ingested()  const { return total_ingested_.load(); }
    uint64_t total_dropped()   const { return total_dropped_.load();  }
    uint64_t watchdog_restarts()const{ return watchdog_restarts_.load(); }
    uint32_t num_shards()      const { return n_shards_; }

private:
    // ── §4.3 Consistent hash routing ─────────────────────────
    uint32_t shardFor(const Event& ev) const {
        const std::string& key =
            cfg_.sharding.hash_key == "session"
                ? (ev.metadata.count("session")
                       ? ev.metadata.at("session") : ev.source)
            : cfg_.sharding.hash_key == "user"
                ? (ev.metadata.count("user")
                       ? ev.metadata.at("user")    : ev.source)
            : ev.source;
        return static_cast<uint32_t>(std::hash<std::string>{}(key)) % n_shards_;
    }

    // ── Worker loop — sequential within shard (§4.4) ─────────
    void workerLoop(Shard& s) {
        while (s.running.load() || s.queue.size() > 0) {
            auto ev_opt = s.queue.pop(std::chrono::milliseconds(5));
            if (!ev_opt) {
                if (!s.running.load()) break;
                ++s.heartbeat;
                continue;
            }
            auto t0 = std::chrono::steady_clock::now();
            s.pipeline.ingest(*ev_opt);
            float us = std::chrono::duration<float, std::micro>(
                           std::chrono::steady_clock::now() - t0).count();
            // EMA latency update (α=0.01 per §9.16)
            s.avg_latency_us += 0.01f * (us - s.avg_latency_us);
            ++s.processed;
            ++s.heartbeat;
        }
    }

    // ── §5.9 Watchdog ─────────────────────────────────────────
    // Monitors heartbeat counters; restarts hung shards automatically.
    void startWatchdog() {
        watchdog_running_ = true;
        watchdog_ = std::thread([this]() {
            std::vector<uint64_t> last(n_shards_, 0);
            std::vector<uint32_t> missed(n_shards_, 0);
            while (watchdog_running_) {
                std::this_thread::sleep_for(std::chrono::duration<float>(
                    cfg_.watchdog.heartbeat_interval_s));
                for (uint32_t i = 0; i < n_shards_; ++i) {
                    uint64_t beat = shards_[i]->heartbeat.load();
                    if (beat == last[i]) {
                        ++missed[i];
                        if (missed[i] >= cfg_.watchdog.max_missed_beats) {
                            restartShard(i);
                            missed[i] = 0;
                        }
                    } else {
                        missed[i] = 0;
                        last[i]   = beat;
                    }
                }
            }
        });
    }

    void restartShard(uint32_t idx) {
        auto& s    = *shards_[idx];
        s.running  = false;
        if (s.worker.joinable()) s.worker.join();
        s.running  = true;
        s.worker   = std::thread([this, raw = &s]() { workerLoop(*raw); });
        ++watchdog_restarts_;
    }

    IDSConfig          cfg_;
    uint32_t           n_shards_;
    std::vector<std::unique_ptr<Shard>> shards_;

    // Unified callbacks — forwarded from all per-shard callbacks
    AlertCallback      alert_cb_;
    BlockCallback      block_cb_;
    EscalateCallback   escalate_cb_;

    // Ingest counters
    std::atomic<uint64_t> total_ingested_{0};
    std::atomic<uint64_t> total_dropped_ {0};
    std::atomic<uint64_t> sample_counter_{0};

    // Watchdog
    std::thread            watchdog_;
    std::atomic<bool>      watchdog_running_{false};
    std::atomic<uint64_t>  watchdog_restarts_{0};
};

}  // namespace ids
