#pragma once
// ─────────────────────────────────────────────────────────────
//  ids_parallel.hpp — §4 Parallel batch processing
//
//  Multi-file ingester using ThreadPool.
//  Each file gets its own IDS pipeline and processes in parallel.
//  Results are merged after all files complete.
// ─────────────────────────────────────────────────────────────
#include "ids_ingest.hpp"
#include "ids_thread_pool.hpp"
#include <filesystem>
#include <future>
#include <mutex>

namespace ids {

struct ParallelIngestResult {
    uint64_t tp = 0, tn = 0, fp = 0, fn = 0;
    uint64_t alerts = 0, blocks = 0, escalations = 0;
    uint64_t total_rows = 0;

    ParallelIngestResult& operator+=(const DatasetIngester::IngestResult& r) {
        tp += r.tp; tn += r.tn; fp += r.fp; fn += r.fn;
        alerts += r.alerts; blocks += r.blocks; escalations += r.escalations;
        total_rows += r.rows_ingested;
        return *this;
    }
};

class ParallelIngester {
public:
    explicit ParallelIngester(size_t n_threads = 0)
        : pool_(n_threads > 0 ? n_threads : std::thread::hardware_concurrency()) {}

    // Ingest multiple files in parallel, each with its own pipeline
    ParallelIngestResult ingest_files(const IDSConfig& cfg,
                                       const std::vector<std::string>& paths,
                                       size_t max_rows_per_file = 0,
                                       const DecisionThresholds& thresholds = {0.05f, 0.10f, 0.25f, 0.70f, 0.90f}) {
        std::vector<std::future<DatasetIngester::IngestResult>> futures;
        futures.reserve(paths.size());

        for (const auto& path : paths) {
            futures.push_back(pool_.enqueue([&cfg, path, max_rows_per_file, thresholds]() {
                IDS pipeline(cfg);
                DatasetIngester ingester(pipeline, 4096);
                ingester.set_thresholds(thresholds);
                return ingester.ingest_file(path, false, max_rows_per_file);
            }));
        }

        ParallelIngestResult total;
        for (auto& f : futures) {
            total += f.get();
        }
        return total;
    }

    // Train then evaluate, all in parallel shards
    struct TrainEvalResult {
        ParallelIngestResult train;
        ParallelIngestResult eval;
        float precision = 0.f, recall = 0.f, f1 = 0.f;
    };

    TrainEvalResult train_eval(const IDSConfig& cfg,
                                const std::vector<std::string>& benign_paths,
                                const std::vector<std::string>& attack_paths,
                                size_t train_rows = 5000,
                                size_t eval_rows = 2000,
                                float alert_threshold = 0.70f) {
        // Phase 1: sequential training (builds persistent baseline)
        IDS train_pipeline(cfg);
        DatasetIngester train_ingester(train_pipeline, 4096);
        for (const auto& path : benign_paths)
            train_ingester.ingest_file(path, false, train_rows);
        train_pipeline.train_autoencoder(3);

        // Save trained state so each eval shard starts from same baseline
        auto state_dir = std::string("/tmp/ids_parallel_state_") + std::to_string(reinterpret_cast<uintptr_t>(this));
        train_pipeline.save_all(state_dir);

        // Phase 2: parallel evaluation on attack files
        DecisionThresholds thresholds;
        thresholds.ignore_threshold = 0.05f;
        thresholds.log_threshold    = 0.10f;
        thresholds.alert_threshold  = alert_threshold;
        thresholds.block_threshold  = 0.92f;

        std::vector<std::future<DatasetIngester::IngestResult>> futures;
        futures.reserve(attack_paths.size());
        std::mutex result_mutex;
        TrainEvalResult result;

        for (const auto& path : attack_paths) {
            futures.push_back(pool_.enqueue([&cfg, path, eval_rows, thresholds, state_dir]() {
                IDS pipeline(cfg);
                pipeline.load_all(state_dir);
                DatasetIngester ingester(pipeline, 4096);
                ingester.set_thresholds(thresholds);
                return ingester.ingest_file(path, false, eval_rows);
            }));
        }

        for (auto& f : futures) {
            auto r = f.get();
            result.eval += r;
        }

        uint64_t gtotal = result.eval.tp + result.eval.fn + result.eval.fp + result.eval.tn;
        if (gtotal > 0) {
            result.precision = 100.f * result.eval.tp / (result.eval.tp + result.eval.fp + 1);
            result.recall    = 100.f * result.eval.tp / (result.eval.tp + result.eval.fn + 1);
            result.f1 = (result.precision + result.recall) > 0.f
                ? 2.f * result.precision * result.recall / (result.precision + result.recall)
                : 0.f;
        }

        // Cleanup temp state
        std::error_code ec;
        std::filesystem::remove_all(state_dir);
        return result;
    }

private:
    ThreadPool pool_;
};

} // namespace ids
