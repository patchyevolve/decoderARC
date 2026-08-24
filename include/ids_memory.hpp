#pragma once
#include "ids_types.hpp"
#include <algorithm>
#include <cmath>
#include <mutex>
#include <numeric>
#include <shared_mutex>
#include <unordered_map>
#include <vector>

namespace ids {

class VectorStore {
public:
    void set_max_size(size_t n) { max_size_ = n; }
    void set_record_ttl(float ttl_s) { ttl_s_ = ttl_s; }

    void insert(MemoryRecord rec) {
        std::lock_guard<std::mutex> lk(mu_);
        rec.id = next_id_++;
        if (records_.size() >= records_.capacity() && records_.size() < max_size_)
            records_.reserve(std::min(max_size_, records_.capacity() + 4096));
        records_.push_back(std::move(rec));
        if (records_.size() > max_size_) evict();
    }

    std::vector<MemoryRecord> search(const Vec& query, size_t k,
                                     float max_age_s = 1e9f,
                                     float recency_tau = 600.f,
                                     float w_sim = 0.5f,
                                     float w_anomaly = 0.3f,
                                     float w_time = 0.2f,
                                     float scope_weight = 0.5f) const {
        std::lock_guard<std::mutex> lk(mu_);
        if (records_.empty()) return {};
        float qnorm = l2norm(query);
        std::vector<std::pair<float, size_t>> scores;
        scores.reserve(records_.size());
        for (size_t i = 0; i < records_.size(); ++i) {
            float age = std::chrono::duration<float>(
                std::chrono::steady_clock::now() - records_[i].inserted_at).count();
            if (age > max_age_s) continue;
            float sim      = cosine(query, records_[i].embedding, qnorm);
            float recency  = expf(-age / std::max(recency_tau, 1.f));
            float final_s  = sim * w_sim
                           + records_[i].score * w_anomaly
                           + recency * w_time
                           + scope_weight;
            scores.emplace_back(final_s, i);
        }
        size_t take = std::min(k, scores.size());
        if (!take) return {};
        std::partial_sort(scores.begin(), scores.begin() + take, scores.end(),
                          [](auto& a, auto& b){ return a.first > b.first; });
        std::vector<MemoryRecord> out;
        out.reserve(take);
        for (size_t i = 0; i < take; ++i) {
            auto rec = records_[scores[i].second];
            rec.score = scores[i].first;
            out.push_back(rec);
        }
        return out;
    }

    std::vector<MemoryRecord> all_records() const {
        std::lock_guard<std::mutex> lk(mu_);
        return records_;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lk(mu_); return records_.size();
    }

    void remove_by_ip(const std::string& ip) {
        std::lock_guard<std::mutex> lk(mu_);
        records_.erase(std::remove_if(records_.begin(), records_.end(),
            [&](const MemoryRecord& r){ return r.key.ip == ip; }), records_.end());
    }

    void sweep(float max_age_s) {
        std::lock_guard<std::mutex> lk(mu_);
        auto now = std::chrono::steady_clock::now();
        records_.erase(std::remove_if(records_.begin(), records_.end(),
            [&](const MemoryRecord& r){
                return std::chrono::duration<float>(now - r.inserted_at).count() > max_age_s;
            }), records_.end());
    }

    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        records_.clear();
    }

private:
    static float l2norm(const Vec& v) {
        float s = 0.f; for (float x : v) s += x*x; return sqrtf(s + 1e-9f);
    }
    static float cosine(const Vec& a, const Vec& b, float anorm) {
        float dot = 0.f;
        for (size_t i = 0; i < kEmbeddingDim; ++i) dot += a[i]*b[i];
        return dot / (anorm * l2norm(b));
    }
    void evict() {
        auto now = std::chrono::steady_clock::now();
        records_.erase(
            std::remove_if(records_.begin(), records_.end(),
                [&](const MemoryRecord& r) {
                    float age = std::chrono::duration<float>(
                        now - r.inserted_at).count();
                    return age > ttl_s_;
                }),
            records_.end());
        if (records_.size() > max_size_) {
            size_t drop = records_.size() / 4;
            std::partial_sort(records_.begin(), records_.begin() + drop,
                records_.end(),
                [](const MemoryRecord& a, const MemoryRecord& b) {
                    return a.score < b.score;
                });
            records_.erase(records_.begin(), records_.begin() + drop);
        }
    }

    mutable std::mutex        mu_;
    std::vector<MemoryRecord> records_;
    uint64_t                  next_id_  = 0;
    size_t                    max_size_ = 100000;
    float                     ttl_s_    = 86400.f;
};

struct Rule {
    uint32_t    id;
    std::string name;
    std::string pattern;
    float       threshold;
    Decision    action;
    bool        enabled  = true;
    uint32_t    priority = 0;
};

class RuleTable {
public:
    void add(Rule r) {
        std::lock_guard<std::mutex> lk(mu_);
        rules_.push_back(std::move(r));
    }
    void remove(uint32_t id) {
        std::lock_guard<std::mutex> lk(mu_);
        rules_.erase(std::remove_if(rules_.begin(), rules_.end(),
            [id](const Rule& r){ return r.id == id; }), rules_.end());
    }
    void set_enabled(uint32_t id, bool enabled) {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& r : rules_) if (r.id == id) r.enabled = enabled;
    }
    void replace(std::vector<Rule> new_rules) {
        std::lock_guard<std::mutex> lk(mu_);
        rules_ = std::move(new_rules);
    }
    std::vector<std::string> match(float score, EventType, const std::string& src) const {
        std::lock_guard<std::mutex> lk(mu_);
        std::vector<std::string> out;
        for (const auto& r : rules_) {
            if (!r.enabled) continue;
            if (score >= r.threshold) out.push_back(r.name);
            if (!r.pattern.empty() && src.find(r.pattern) != std::string::npos)
                out.push_back(r.name + ":ip");
        }
        return out;
    }
    std::vector<Rule> all() const {
        std::lock_guard<std::mutex> lk(mu_); return rules_;
    }
private:
    mutable std::mutex  mu_;
    std::vector<Rule>   rules_;
};

struct MemoryStore {
    VectorStore global_store;
    std::unordered_map<std::string, VectorStore> host_store;
    std::unordered_map<std::string, VectorStore> user_store;
    std::unordered_map<std::string, VectorStore> ip_store;
    std::unordered_map<std::string, VectorStore> session_store;
    std::unordered_map<std::string, VectorStore> process_store;
    RuleTable rules;
    mutable std::shared_mutex host_mu;
    mutable std::shared_mutex global_mu;
};

inline bool should_write(float anomaly_score, float drift,
                          const RetrievedContext& ctx,
                          Decision decision,
                          const WritePolicy& pol) {
    if (anomaly_score >= pol.memory_force_gate)                           return true;
    if (anomaly_score >= pol.memory_write_gate)                           return true;
    if (pol.write_on_rule_match && !ctx.matched_rules.empty())            return true;
    if (pol.write_on_block     && decision == Decision::Block)            return true;
    if (pol.write_on_escalate  && decision == Decision::Escalate)         return true;
    if (pol.write_on_high_drift && drift >= pol.drift_write_threshold)    return true;
    return false;
}

inline void write_record(MemoryStore& mem, MemoryRecord rec,
                          const MemoryKey& key, float anomaly_score,
                          const WritePolicy& pol) {
    rec.key = key;
    mem.ip_store[key.ip].insert(rec);
    if (!key.user.empty())
        mem.user_store[key.user].insert(rec);
    if (anomaly_score >= 0.50f && !key.host.empty())
        mem.host_store[key.host].insert(rec);
    if (anomaly_score >= pol.memory_force_gate) {
        std::unique_lock lk(mem.global_mu);
        mem.global_store.insert(rec);
    }
    if (!key.session.empty())
        mem.session_store[key.session].insert(rec);
    if (!key.process.empty())
        mem.process_store[key.process].insert(rec);
}

class Retriever {
public:
    explicit Retriever(MemoryStore&          mem,
                       RetrievalTimeConfig   time_cfg  = {},
                       RetrievalWeights      weights   = {},
                       ForceRetrievalConfig  force_cfg = {})
        : mem_(mem), time_cfg_(time_cfg), weights_(weights), force_cfg_(force_cfg) {}

    RetrievedContext retrieve(const LocalState&   ls,
                              const SegmentState& ss,
                              const GlobalState&  gs,
                              const Event&        ev) const {
        (void)ss;
        RetrievedContext ctx;
        MemoryKey key = key_from_event(ev);

        float max_age  = time_cfg_.retrieval_max_age_s;
        float tau      = time_cfg_.recency_tau;
        float ws = weights_.w_sim, wa = weights_.w_anomaly, wt = weights_.w_time;

        auto merge = [&](const std::vector<MemoryRecord>& hits) {
            for (auto& h : hits) {
                bool dup = false;
                for (auto& e : ctx.records) if (e.id == h.id) { dup = true; break; }
                if (!dup) ctx.records.push_back(h);
                ctx.similarity_max = std::max(ctx.similarity_max, h.score);
            }
        };

        if (mem_.ip_store.count(key.ip))
            merge(mem_.ip_store.at(key.ip).search(ls.embedding, 3, max_age, tau, ws, wa, wt, 1.0f));
        if (!key.user.empty() && mem_.user_store.count(key.user))
            merge(mem_.user_store.at(key.user).search(ls.embedding, 2, max_age, tau, ws, wa, wt, 0.9f));
        if (!key.session.empty() && mem_.session_store.count(key.session))
            merge(mem_.session_store.at(key.session).search(ls.embedding, 2, max_age, tau, ws, wa, wt, 0.85f));
        if (!key.host.empty() && mem_.host_store.count(key.host))
            merge(mem_.host_store.at(key.host).search(ls.embedding, 2, max_age, tau, ws, wa, wt, 0.7f));

        {
            std::shared_lock glk(mem_.global_mu);
            auto ghits = mem_.global_store.search(ls.embedding, 1, max_age, tau, ws, wa, wt, 0.5f);
            merge(ghits);
        }

        // Force retrieval: if anomaly or drift exceeds thresholds, boost global search counts
        bool force = force_cfg_.force_retrieve
            || (force_cfg_.force_on_block)
            || (gs.drift_score > force_cfg_.drift_force_threshold);
        if (force && !ctx.records.empty()) {
            std::shared_lock glk(mem_.global_mu);
            auto ghits = mem_.global_store.search(ls.embedding, 4, max_age, tau, ws, wa, wt, 0.5f);
            merge(ghits);
        }

        std::sort(ctx.records.begin(), ctx.records.end(),
                  [](const MemoryRecord& a, const MemoryRecord& b){ return a.score > b.score; });
        if (ctx.records.size() > kTopKRetrieval)
            ctx.records.resize(kTopKRetrieval);

        ctx.matched_rules = mem_.rules.match(ls.anomaly_score, ev.type, ev.source);
        return ctx;
    }

    void write(const LocalState& ls, const Event& ev,
               float anomaly_score, float drift,
               Decision decision,
               const RetrievedContext& ctx,
               const WritePolicy& pol) {
        if (!should_write(anomaly_score, drift, ctx, decision, pol)) return;
        MemoryRecord rec;
        rec.embedding   = ls.embedding;
        rec.score       = anomaly_score;
        rec.label       = "auto";
        rec.raw_summary = "src=" + ev.source;
        write_record(mem_, rec, key_from_event(ev), anomaly_score, pol);
    }

    void store_anomaly(const LocalState& ls, const std::string& label,
                       float score, const std::string& summary,
                       const MemoryKey& key = {}) {
        MemoryRecord r;
        r.embedding   = ls.embedding;
        r.score       = score;
        r.label       = label;
        r.raw_summary = summary;
        r.key         = key;
        mem_.global_store.insert(r);
        if (!key.ip.empty()) mem_.ip_store[key.ip].insert(r);
    }

    enum class CleanupReason { SessionEnd, StateExpired, HostRemoved, Manual };

    void cleanup(const MemoryKey& key, CleanupReason reason) {
        if (!key.ip.empty())      mem_.ip_store.erase(key.ip);
        if (!key.session.empty()) mem_.session_store.erase(key.session);
        if (reason == CleanupReason::HostRemoved && !key.host.empty())
            mem_.host_store.erase(key.host);
        if (reason == CleanupReason::Manual) {
            if (!key.user.empty())    mem_.user_store.erase(key.user);
            if (!key.process.empty()) mem_.process_store.erase(key.process);
        }
    }

    void sweep(const MemoryCleanupConfig& cfg) {
        mem_.global_store.sweep(cfg.record_ttl_s);
        for (auto& [k, vs] : mem_.ip_store)      vs.sweep(cfg.record_ttl_s);
        for (auto& [k, vs] : mem_.host_store)     vs.sweep(cfg.record_ttl_s);
        for (auto& [k, vs] : mem_.user_store)     vs.sweep(cfg.record_ttl_s);
        for (auto& [k, vs] : mem_.session_store)  vs.sweep(cfg.record_ttl_s);
        for (auto& [k, vs] : mem_.process_store)  vs.sweep(cfg.record_ttl_s);
    }

    void set_record_ttl(float ttl_s) {
        mem_.global_store.set_record_ttl(ttl_s);
    }

    MemoryStore& store() { return mem_; }
    const MemoryStore& store() const { return mem_; }

private:
    MemoryStore&         mem_;
    RetrievalTimeConfig  time_cfg_;
    RetrievalWeights     weights_;
    ForceRetrievalConfig force_cfg_;
};

}  // namespace ids
