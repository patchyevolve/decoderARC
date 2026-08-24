#include "ids_ingest.hpp"
#include <algorithm>
#include <filesystem>
#include <iomanip>

namespace fs = std::filesystem;

struct DatasetInfo {
    std::string path;
    std::string name;
    bool benign;
};

int main() {
    std::cout << "=== IDS Dataset Calibration & Evaluation Demo ===" << std::endl;

    std::vector<DatasetInfo> benign_files, attack_files;
    std::string dir = "real_datasets";
    if (!fs::is_directory(dir)) {
        std::cerr << "Directory not found: " << dir << std::endl;
        return 1;
    }

    for (const auto& entry : fs::directory_iterator(dir)) {
        if (entry.path().extension() != ".csv") continue;
        std::string name = entry.path().stem().string();
        bool is_benign = name.find("benign") != std::string::npos;
        (is_benign ? benign_files : attack_files).push_back({entry.path().string(), name, is_benign});
    }

    std::cout << "\nFound " << benign_files.size() << " benign, "
              << attack_files.size() << " attack datasets.\n";

    // ── Single pipeline: train on benign, then test on attacks ──
    ids::IDSConfig cfg;
    ids::IDS pipeline(cfg);
    ids::DatasetIngester ingester(pipeline, 4096);

    // ── Phase 1: Train baseline on benign traffic ────────────
    std::cout << "\n─── Phase 1: Baseline Training ─────────────────" << std::endl;
    ids::DatasetStats benign_stats;
    uint64_t trained = 0;
    for (const auto& bf : benign_files) {
        size_t limit = 5000;
        std::cout << "  Training on " << bf.name << " (" << limit << ")..." << std::flush;
        auto res = ingester.ingest_file(bf.path, false, limit);
        trained += res.rows_ingested;
        benign_stats.benign_scores.insert(benign_stats.benign_scores.end(),
            res.stats.benign_scores.begin(), res.stats.benign_scores.end());
        std::cout << " " << res.rows_ingested << " rows (total trained: " << trained << ")" << std::endl;
    }

    // Score drift_series from pipeline
    std::vector<float> drift_samples;
    auto gs = pipeline.global_state();
    for (int i = 0; i < 20; ++i) {
        drift_samples.push_back(gs.drift_score);
    }

    benign_stats.finalize();
    auto suggested = benign_stats.suggest_thresholds(0.01f);

    // Train autoencoder on benign embeddings collected during ingest
    std::cout << "\n  Training autoencoder on " << pipeline.embedding_count()
              << " benign embeddings..." << std::flush;
    pipeline.train_autoencoder(3);
    std::cout << " done" << std::endl;

    std::cout << "\n  Baseline trained on " << trained << " benign events." << std::endl;
    std::cout << "  Benign drift 95th: " << benign_stats.benign_score_95th
              << "  99th: " << benign_stats.benign_score_99th << std::endl;
    std::cout << "  Current pipeline drift: " << pipeline.global_state().drift_score
              << " anomaly_hist: " << pipeline.global_state().anomaly_history << std::endl;
    std::cout << "  Suggested gate:   " << suggested.gate_threshold << std::endl;
    std::cout << "  Suggested alert:  " << suggested.alert_threshold << std::endl;
    std::cout << "  Suggested block:  " << suggested.block_threshold << std::endl;

    // ── Phase 2: Evaluate on attack datasets ────────────────
    std::cout << "\n─── Phase 2: Attack Detection ──────────────────" << std::endl;
    std::cout << "  Single global threshold from benign 99th percentile." << std::endl;
    std::cout << "  No per-class calibration — detection is purely anomaly-based.\n" << std::endl;

    uint64_t total_tp = 0, total_tn = 0, total_fp = 0, total_fn = 0;

    for (const auto& af : attack_files) {
        if (af.name.find("friday-working-hours") != std::string::npos) continue;

        ids::IDSConfig test_cfg;
        test_cfg.thresholds.ignore_threshold = 0.05f;
        test_cfg.thresholds.log_threshold    = 0.10f;
        test_cfg.thresholds.alert_threshold  = suggested.alert_threshold;
        test_cfg.thresholds.block_threshold  = suggested.block_threshold;

        ids::IDS test_pipeline(cfg);
        ids::DatasetIngester test_ingester(test_pipeline, 4096);
        test_ingester.set_thresholds(test_cfg.thresholds);

        for (const auto& bf : benign_files)
            test_ingester.ingest_file(bf.path, false, 2000);

        auto res = test_ingester.ingest_file(af.path, false, 2000);

        float prec = (res.tp + res.fp) > 0 ? 100.f * res.tp / float(res.tp + res.fp) : 0.f;
        float rec  = (res.tp + res.fn) > 0 ? 100.f * res.tp / float(res.tp + res.fn) : 0.f;
        float f1   = (prec + rec) > 0.f ? 2.f * prec * rec / (prec + rec) : 0.f;

        std::cout << "  " << std::left << std::setw(35) << af.name
                  << " TP:" << std::setw(4) << res.tp
                  << " FP:" << std::setw(4) << res.fp
                  << " FN:" << std::setw(4) << res.fn
                  << " F1:" << std::fixed << std::setprecision(0) << f1 << "%"
                  << std::endl;

        total_tp   += res.tp;
        total_tn   += res.tn;
        total_fp   += res.fp;
        total_fn   += res.fn;
    }

    uint64_t gtotal = total_tp + total_tn + total_fp + total_fn;
    float gprec = (total_tp + total_fp) > 0 ? 100.f * total_tp / float(total_tp + total_fp) : 0.f;
    float grec  = (total_tp + total_fn) > 0 ? 100.f * total_tp / float(total_tp + total_fn) : 0.f;
    float gf1   = (gprec + grec) > 0.f ? 2.f * gprec * grec / (gprec + grec) : 0.f;

    std::cout << "\n════════════════════════════════════════════════" << std::endl;
    std::cout << "  GLOBAL SUMMARY (" << gtotal << " total rows) — single global threshold" << std::endl;
    std::cout << "  TP:" << total_tp << " FN:" << total_fn
              << " FP:" << total_fp << " TN:" << total_tn << std::endl;
    std::cout << "  Precision: " << std::fixed << std::setprecision(1)
              << gprec << "%  Recall: " << grec << "%  F1: " << gf1 << "%" << std::endl;
    std::cout << "════════════════════════════════════════════════" << std::endl;
    return 0;
}
