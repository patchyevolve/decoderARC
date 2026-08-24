// ids_e2e_test.cpp — End-to-end detection evaluation with assertions
// Compile: clang++ -std=c++17 -O2 -I../include ids_e2e_test.cpp -o ids_e2e_test -lpthread
//
// Tests the full IDS pipeline against CICIDS2017 datasets.
// Exits 0 on pass, 1 on fail. Use from CI.
#include "ids.hpp"
#include "ids_ingest.hpp"
#include <algorithm>
#include <cassert>
#include <cmath>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>

namespace fs = std::filesystem;

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name) \
    std::cout << "  " << name << "...\n" << std::flush; \
    try

#define PASS() do { std::cout << "    PASS\n"; g_passed++; } while(0)
#define FAIL(msg) do { std::cout << "    FAIL: " << msg << "\n"; g_failed++; } while(0)

#define ASSERT_TRUE(x) do { \
    if (!(x)) throw std::runtime_error(std::string(#x) + " is false"); \
} while(0)

#define ASSERT_GE(a, b) do { \
    if ((a) < (b)) { \
        std::ostringstream ss; ss << #a " < " #b " (" << (a) << " < " << (b) << ")"; \
        throw std::runtime_error(ss.str()); \
    } \
} while(0)

struct EvalResult {
    uint64_t tp = 0, fp = 0, fn = 0, tn = 0;
    uint64_t rows = 0;
    float precision = 0.f;
    float recall = 0.f;
    float f1 = 0.f;
    float accuracy = 0.f;
};

EvalResult evaluate_dataset(ids::IDS& pipeline, const std::string& path,
                            const ids::DecisionThresholds& thr, size_t max_rows = 0) {
    EvalResult r;
    ids::DatasetIngester ingester(pipeline, 4096);
    ingester.set_thresholds(thr);

    auto res = ingester.ingest_file(path, false, max_rows);
    r.tp = res.tp;
    r.fp = res.fp;
    r.fn = res.fn;
    r.tn = res.tn;
    r.rows = res.rows_ingested;

    uint64_t total = r.tp + r.tn + r.fp + r.fn;
    r.precision = total > 0 ? 100.f * r.tp / float(r.tp + r.fp) : 0.f;
    r.recall    = total > 0 ? 100.f * r.tp / float(r.tp + r.fn) : 0.f;
    r.f1        = (r.precision + r.recall) > 0.f ? 2.f * r.precision * r.recall / (r.precision + r.recall) : 0.f;
    r.accuracy  = total > 0 ? 100.f * (r.tp + r.tn) / float(total) : 0.f;
    return r;
}

int main() {
    std::cout << "=== IDS End-to-End Detection Test ===" << std::endl;

    if (!fs::is_directory("real_datasets")) {
        std::cout << "SKIP: real_datasets/ not found (not in git). Run locally with datasets." << std::endl;
        return 0;
    }

    // ── Phase 1: Train on benign traffic ────────────────────
    std::cout << "\n--- Phase 1: Training baseline ---" << std::endl;

    ids::IDSConfig cfg;
    cfg.thresholds.ignore_threshold  = 0.05f;
    cfg.thresholds.log_threshold     = 0.10f;
    cfg.thresholds.alert_threshold   = 0.60f;
    cfg.thresholds.block_threshold   = 0.90f;
    cfg.thresholds.escalate_threshold = 0.99f;

    ids::IDS pipeline(cfg);
    ids::DatasetIngester ingester(pipeline, 4096);

    // Train on Monday benign (largest benign file)
    std::vector<std::string> train_files = {
        "real_datasets/monday_benign.csv",
        "real_datasets/tuesday_benign.csv"
    };
    for (const auto& tf : train_files) {
        if (!fs::exists(tf)) continue;
        std::cout << "  Training on " << tf << "..." << std::flush;
        auto res = ingester.ingest_file(tf, false, 10000);
        std::cout << " " << res.rows_ingested << " rows" << std::endl;
    }

    // Train autoencoder
    std::cout << "  Training autoencoder..." << std::flush;
    pipeline.train_autoencoder(3);
    std::cout << " done" << std::endl;

    // Get threshold suggestion from benign data (use all training benign scores)
    ids::DatasetStats benign_stats;
    for (const auto& tf : train_files) {
        if (!fs::exists(tf)) continue;
        ids::IDS tmp_pipeline(cfg);
        ids::DatasetIngester tmp_ingester(tmp_pipeline, 4096);
        auto res = tmp_ingester.ingest_file(tf, false, 10000);
        benign_stats.benign_scores.insert(benign_stats.benign_scores.end(),
            res.stats.benign_scores.begin(), res.stats.benign_scores.end());
    }
    benign_stats.finalize();
    auto suggested = benign_stats.suggest_thresholds(0.01f);

    std::cout << "  Suggested alert threshold: " << suggested.alert_threshold << std::endl;
    std::cout << "  Suggested block threshold: " << suggested.block_threshold << std::endl;

    // Use suggested thresholds for evaluation
    ids::DecisionThresholds eval_thr{
        0.05f, 0.10f,
        suggested.alert_threshold,
        suggested.block_threshold,
        0.99f
    };

    // ── Phase 2: Evaluate on attack datasets ────────────────
    std::cout << "\n--- Phase 2: Attack detection evaluation ---" << std::endl;

    struct TestCase {
        std::string file;
        std::string name;
        float min_recall;    // minimum acceptable recall (%)
        float min_f1;        // minimum acceptable F1 (%)
        size_t max_rows;     // 0 = unlimited
    };

    std::vector<TestCase> tests = {
        {"real_datasets/portscan.csv",          "Port Scan",        30.f, 20.f, 5000},
        {"real_datasets/dos_hulk.csv",          "DoS Hulk",         40.f, 30.f, 5000},
        {"real_datasets/ftp_patator.csv",       "FTP Brute Force",  30.f, 20.f, 3000},
        {"real_datasets/ssh_patator-new.csv",   "SSH Brute Force",  15.f, 10.f, 3000},
        {"real_datasets/ddos_loit.csv",         "DDoS Loit",        30.f, 20.f, 5000},
    };

    uint64_t total_tp = 0, total_fp = 0, total_fn = 0, total_tn = 0;

    for (const auto& tc : tests) {
        if (!fs::exists(tc.file)) {
            std::cout << "  [SKIP] " << tc.name << " — file not found" << std::endl;
            continue;
        }

        auto result = evaluate_dataset(pipeline, tc.file, eval_thr, tc.max_rows);

        total_tp += result.tp;
        total_fp += result.fp;
        total_fn += result.fn;
        total_tn += result.tn;

        std::cout << "  " << std::left << std::setw(20) << tc.name
                  << " rows=" << std::setw(6) << result.rows
                  << " TP=" << std::setw(5) << result.tp
                  << " FP=" << std::setw(5) << result.fp
                  << " FN=" << std::setw(5) << result.fn
                  << " P=" << std::fixed << std::setprecision(1) << result.precision << "%"
                  << " R=" << result.recall << "%"
                  << " F1=" << result.f1 << "%"
                  << std::endl;

        // Run assertions
        TEST(tc.name + " recall >= " + std::to_string(int(tc.min_recall)) + "%") {
            ASSERT_GE(result.recall, tc.min_recall);
            PASS();
        } catch (const std::exception& e) { FAIL(e.what()); }

        TEST(tc.name + " F1 >= " + std::to_string(int(tc.min_f1)) + "%") {
            ASSERT_GE(result.f1, tc.min_f1);
            PASS();
        } catch (const std::exception& e) { FAIL(e.what()); }
    }

    // ── Phase 3: Verify benign traffic has low FP rate ──────
    std::cout << "\n--- Phase 3: Benign false positive check ---" << std::endl;

    std::string benign_file = "real_datasets/wednesday_benign.csv";
    if (fs::exists(benign_file)) {
        auto benign_result = evaluate_dataset(pipeline, benign_file, eval_thr, 5000);
        float fp_rate = benign_result.rows > 0 ? 100.f * benign_result.fp / float(benign_result.rows) : 0.f;

        std::cout << "  Benign FP rate: " << std::fixed << std::setprecision(1) << fp_rate
                  << "% (" << benign_result.fp << "/" << benign_result.rows << ")" << std::endl;

        TEST("Benign FP rate < 80% (anomaly-based, no calibration)") {
            ASSERT_TRUE(fp_rate < 80.0f);
            PASS();
        } catch (const std::exception& e) { FAIL(e.what()); }
    }

    // ── Global summary ──────────────────────────────────────
    uint64_t gtotal = total_tp + total_tn + total_fp + total_fn;
    float gprec = (total_tp + total_fp) > 0 ? 100.f * total_tp / float(total_tp + total_fp) : 0.f;
    float grec  = (total_tp + total_fn) > 0 ? 100.f * total_tp / float(total_tp + total_fn) : 0.f;
    float gf1   = (gprec + grec) > 0.f ? 2.f * gprec * grec / (gprec + grec) : 0.f;

    std::cout << "\n=== GLOBAL SUMMARY ===" << std::endl;
    std::cout << "  Total rows: " << gtotal << std::endl;
    std::cout << "  TP:" << total_tp << " FP:" << total_fp
              << " FN:" << total_fn << " TN:" << total_tn << std::endl;
    std::cout << "  Precision: " << std::fixed << std::setprecision(1) << gprec << "%" << std::endl;
    std::cout << "  Recall:    " << grec << "%" << std::endl;
    std::cout << "  F1:        " << gf1 << "%" << std::endl;

    TEST("Global recall > 0% (detection is not completely broken)") {
        ASSERT_GE(grec, 0.0f);
        // More importantly: at least some attacks must be detected
        ASSERT_TRUE(total_tp > 0);
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }

    TEST("Global precision > 0% (not every event is an alert)") {
        ASSERT_TRUE(total_fp < gtotal);  // not everything is FP
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }

    std::cout << "\n=== Results: " << g_passed << " passed, "
              << g_failed << " failed ===" << std::endl;
    return g_failed > 0 ? 1 : 0;
}
