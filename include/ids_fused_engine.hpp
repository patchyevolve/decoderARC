#pragma once
#include "ids_specialist.hpp"
#include "ids_thread_pool.hpp"
#include <vector>
#include <future>
#include <algorithm>
#include <map>
#include <chrono>

namespace ids {

/**
 * @brief Strategy for fusing multiple specialist results.
 */
class FusionStrategy {
public:
    virtual ~FusionStrategy() = default;
    virtual SpecialistResult fuse(const std::vector<SpecialistResult>& results) = 0;
};

/**
 * @brief Default Consensus Fusion: Takes the highest confidence result that is validated.
 */
class ConsensusFusion : public FusionStrategy {
public:
    SpecialistResult fuse(const std::vector<SpecialistResult>& results) override {
        if (results.empty()) return {"None", 0.0f, Decision::Ignore, "No results to fuse"};

        SpecialistResult fused;
        fused.confidence = 0.0f;
        fused.suggested_decision = Decision::Ignore;

        std::string class_summary;
        for (const auto& res : results) {
            if (!res.validated) continue;

            if (res.confidence > fused.confidence) {
                fused.confidence = res.confidence;
                fused.attack_class = res.attack_class;
                fused.suggested_decision = res.suggested_decision;
            }
            if (res.suggested_decision != Decision::Ignore) {
                class_summary += "[" + res.attack_class + ":" + std::to_string(res.confidence).substr(0,4) + "] ";
            }
        }
        fused.details = "Consensus Fusion: " + class_summary;
        fused.validated = true;
        return fused;
    }
};

/**
 * @brief Priority Fusion: Some specialists (e.g., ZeroDay) have higher weight if they trigger.
 */
class PriorityFusion : public FusionStrategy {
public:
    SpecialistResult fuse(const std::vector<SpecialistResult>& results) override {
        // Find if any "Critical" attack class triggered
        for (const auto& res : results) {
            if (res.validated && (res.attack_class == "ZeroDay" || res.attack_class == "Ransomware") && res.confidence > 0.6f) {
                SpecialistResult fused = res;
                fused.details = "Priority Trigger (" + res.attack_class + "): " + res.details;
                return fused;
            }
        }
        // Fallback to consensus
        ConsensusFusion fallback;
        return fallback.fuse(results);
    }
};

/**
 * @brief FusedDetectionEngine coordinates multiple specialists with robust handling.
 */
class FusedDetectionEngine {
public:
    explicit FusedDetectionEngine(size_t num_threads = 4)
        : pool_(num_threads), strategy_(std::make_unique<ConsensusFusion>()) {}

    void add_specialist(std::unique_ptr<Specialist> s) {
        specialists_.push_back(std::move(s));
    }

    void set_fusion_strategy(std::unique_ptr<FusionStrategy> strategy) {
        strategy_ = std::move(strategy);
    }

    /**
     * @brief Ingest an event with parallel execution, timeouts, and robust fusion.
     */
    SpecialistResult ingest(const Event& ev, std::chrono::milliseconds timeout = std::chrono::milliseconds(50)) {
        auto start_time = std::chrono::steady_clock::now();

        std::vector<std::future<SpecialistResult>> futures;
        for (auto& s : specialists_) {
            futures.push_back(pool_.enqueue([&s, ev]() {
                return s->analyze(ev);
            }));
        }

        std::vector<SpecialistResult> results;
        for (size_t i = 0; i < futures.size(); ++i) {
            auto status = futures[i].wait_for(timeout);
            if (status == std::future_status::ready) {
                try {
                    results.push_back(futures[i].get());
                } catch (const std::exception& e) {
                    results.push_back({specialists_[i]->attack_class(), 0.0f, Decision::Ignore, std::string("Error: ") + e.what(), false});
                }
            } else {
                // Timeout handling
                results.push_back({specialists_[i]->attack_class(), 0.0f, Decision::Ignore, "Timeout", false});
            }
        }

        auto fused = strategy_->fuse(results);
        
        auto end_time = std::chrono::steady_clock::now();
        fused.details += " | Latency: " + std::to_string(std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count()) + "us";
        
        return fused;
    }

private:
    std::vector<std::unique_ptr<Specialist>> specialists_;
    ThreadPool pool_;
    std::unique_ptr<FusionStrategy> strategy_;
};

} // namespace ids
