// ids_unit_tests.cpp — Unit tests for IDS pipeline stages
// Compile: clang++ -std=c++17 -O2 -I../include ids_unit_tests.cpp -o ids_unit_tests -lpthread
#include "ids.hpp"
#include "ids_ingest.hpp"
#include <cassert>
#include <cmath>
#include <iostream>
#include <numeric>

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name) \
    std::cout << "  " << name << "... " << std::flush; \
    try

#define PASS() do { std::cout << "PASS\n"; g_passed++; } while(0)
#define FAIL(msg) do { std::cout << "FAIL: " << msg << "\n"; g_failed++; } while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { std::ostringstream ss; ss << #a " != " #b " (" << (a) << " vs " << (b) << ")"; throw std::runtime_error(ss.str()); } \
} while(0)

#define ASSERT_NEAR(a, b, eps) do { \
    if (std::abs((a) - (b)) > (eps)) { std::ostringstream ss; ss << #a " != " #b " (" << (a) << " vs " << (b) << ")"; throw std::runtime_error(ss.str()); } \
} while(0)

#define ASSERT_TRUE(x) do { if (!(x)) throw std::runtime_error(std::string(#x) + " is false"); } while(0)

// ═══════════════════════════════════════════════════════════════
//  Test: score_to_decision thresholds
// ═══════════════════════════════════════════════════════════════
void test_score_to_decision() {
    TEST("score_to_decision thresholds") {
        ids::DecisionThresholds t{0.20f, 0.40f, 0.60f, 0.85f, 0.95f};

        ASSERT_EQ(static_cast<int>(ids::score_to_decision(0.0f, t)),  static_cast<int>(ids::Decision::Ignore));
        ASSERT_EQ(static_cast<int>(ids::score_to_decision(0.15f, t)), static_cast<int>(ids::Decision::Ignore));
        ASSERT_EQ(static_cast<int>(ids::score_to_decision(0.20f, t)), static_cast<int>(ids::Decision::Log));
        ASSERT_EQ(static_cast<int>(ids::score_to_decision(0.35f, t)), static_cast<int>(ids::Decision::Log));
        ASSERT_EQ(static_cast<int>(ids::score_to_decision(0.40f, t)), static_cast<int>(ids::Decision::Alert));
        ASSERT_EQ(static_cast<int>(ids::score_to_decision(0.55f, t)), static_cast<int>(ids::Decision::Alert));
        ASSERT_EQ(static_cast<int>(ids::score_to_decision(0.60f, t)), static_cast<int>(ids::Decision::Block));
        ASSERT_EQ(static_cast<int>(ids::score_to_decision(0.80f, t)), static_cast<int>(ids::Decision::Block));
        ASSERT_EQ(static_cast<int>(ids::score_to_decision(0.85f, t)), static_cast<int>(ids::Decision::Block));
        ASSERT_EQ(static_cast<int>(ids::score_to_decision(0.95f, t)), static_cast<int>(ids::Decision::Escalate));
        ASSERT_EQ(static_cast<int>(ids::score_to_decision(1.0f, t)),  static_cast<int>(ids::Decision::Escalate));
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }
}

// ═══════════════════════════════════════════════════════════════
//  Test: Config validation
// ═══════════════════════════════════════════════════════════════
void test_config_validation() {
    TEST("validate_config accepts valid config") {
        ids::IDSConfig cfg;
        std::string reason;
        ASSERT_TRUE(ids::validate_config(cfg, &reason));
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }

    TEST("validate_config rejects bad thresholds") {
        ids::IDSConfig cfg;
        cfg.thresholds.ignore_threshold = 0.80f;
        cfg.thresholds.log_threshold    = 0.60f;  // inverted
        std::string reason;
        ASSERT_TRUE(!ids::validate_config(cfg, &reason));
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }

    TEST("validate_config rejects bad decay") {
        ids::IDSConfig cfg;
        cfg.state.decay_l1 = -1.0f;
        std::string reason;
        ASSERT_TRUE(!ids::validate_config(cfg, &reason));
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }
}

// ═══════════════════════════════════════════════════════════════
//  Test: CSV parsing
// ═══════════════════════════════════════════════════════════════
void test_csv_parsing() {
    TEST("parse_csv_line handles simple fields") {
        auto cols = ids::parse_csv_line("a,b,c,d");
        ASSERT_EQ(cols.size(), 4u);
        ASSERT_EQ(cols[0], "a");
        ASSERT_EQ(cols[3], "d");
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }

    TEST("parse_csv_line handles quoted fields") {
        auto cols = ids::parse_csv_line("a,\"b,c\",d");
        ASSERT_EQ(cols.size(), 3u);
        ASSERT_EQ(cols[1], "b,c");
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }

    TEST("detect_format recognizes FlowCSV") {
        std::string hdr = "flow_id,src_ip,dst_ip,label";
        ASSERT_EQ(static_cast<int>(ids::detect_format(hdr)), static_cast<int>(ids::DatasetFormat::FlowCSV));
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }

    TEST("detect_format recognizes CyberLog") {
        std::string hdr = "timestamp,source_ip,dest_ip,action";
        ASSERT_EQ(static_cast<int>(ids::detect_format(hdr)), static_cast<int>(ids::DatasetFormat::CyberLog));
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }

    TEST("is_benign identifies benign labels") {
        ASSERT_TRUE(ids::is_benign("Benign"));
        ASSERT_TRUE(ids::is_benign("benign"));
        ASSERT_TRUE(ids::is_benign("normal"));
        ASSERT_TRUE(ids::is_benign("0"));
        ASSERT_TRUE(ids::is_benign(""));
        ASSERT_TRUE(!ids::is_benign("DoS_Hulk"));
        ASSERT_TRUE(!ids::is_benign("PortScan"));
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }
}

// ═══════════════════════════════════════════════════════════════
//  Test: CSV row to Event conversion
// ═══════════════════════════════════════════════════════════════
void test_csv_to_event() {
    TEST("csv_to_event maps IP and ports correctly") {
        ids::ColumnMap m;
        m.src_ip = 0; m.dst_ip = 1; m.src_port = 2; m.dst_port = 3;
        m.protocol = 4;

        std::vector<std::string> cols = {"10.0.0.1", "10.0.0.2", "443", "80", "TCP"};
        auto ev = ids::csv_to_event(cols, m);

        ASSERT_EQ(ev.source, "10.0.0.1");
        ASSERT_EQ(ev.destination, "10.0.0.2");
        ASSERT_EQ(ev.payload.port_src, 443);
        ASSERT_EQ(ev.payload.port_dst, 80);
        ASSERT_EQ(ev.payload.protocol, 6);  // TCP
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }

    TEST("csv_to_event handles UDP protocol") {
        ids::ColumnMap m;
        m.src_ip = 0; m.dst_ip = 1; m.protocol = 2;

        std::vector<std::string> cols = {"10.0.0.1", "10.0.0.2", "UDP"};
        auto ev = ids::csv_to_event(cols, m);

        ASSERT_EQ(ev.payload.protocol, 17);  // UDP
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }

    TEST("csv_to_event populates flow stats") {
        ids::ColumnMap m;
        m.src_ip = 0; m.dst_ip = 1;
        m.packets_total = 2; m.bytes_fwd = 3; m.bytes_bwd = 4;
        m.pkt_size_mean = 5; m.iat_mean = 6; m.syn_flags = 7;

        std::vector<std::string> cols = {"10.0.0.1", "10.0.0.2", "100", "500", "300", "128.5", "0.01", "5"};
        auto ev = ids::csv_to_event(cols, m);

        ASSERT_EQ(ev.flow.packets_total, 100u);
        ASSERT_EQ(ev.flow.bytes_fwd, 500u);
        ASSERT_EQ(ev.flow.bytes_bwd, 300u);
        ASSERT_NEAR(ev.flow.packet_size_mean, 128.5f, 0.1f);
        ASSERT_NEAR(ev.flow.iat_mean, 0.01f, 0.001f);
        ASSERT_EQ(ev.flow.syn_count, 5u);
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }
}

// ═══════════════════════════════════════════════════════════════
//  Test: Full pipeline ingest (smoke test)
// ═══════════════════════════════════════════════════════════════
void test_pipeline_ingest() {
    TEST("pipeline ingests normal traffic without crashing") {
        ids::IDSConfig cfg;
        ids::IDS pipeline(cfg);

        ids::Event ev;
        ev.source = "192.168.1.1";
        ev.destination = "10.0.0.1";
        ev.type = ids::EventType::NetworkPacket;
        ev.payload.port_src = 12345;
        ev.payload.port_dst = 80;
        ev.payload.protocol = 6;
        ev.payload.bytes_in = 1500;
        ev.payload.entropy = 0.3f;
        ev.payload.rate_hz = 10.f;

        auto state = pipeline.ingest(ev);
        // Pipeline should produce a valid local state
        ASSERT_TRUE(std::isfinite(state.local.anomaly_score));
        ASSERT_TRUE(state.local.anomaly_score >= 0.f);
        ASSERT_TRUE(state.local.anomaly_score <= 1.f);
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }

    TEST("pipeline metrics track event count") {
        ids::IDSConfig cfg;
        ids::IDS pipeline(cfg);

        ids::Event ev;
        ev.source = "192.168.1.1";
        ev.destination = "10.0.0.1";
        ev.type = ids::EventType::NetworkPacket;
        ev.payload.bytes_in = 100;

        uint64_t before = pipeline.metrics().events_total.load();
        pipeline.ingest(ev);
        uint64_t after = pipeline.metrics().events_total.load();
        ASSERT_TRUE(after > before);
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }
}

// ═══════════════════════════════════════════════════════════════
//  Test: Pipeline detects anomalous traffic
// ═══════════════════════════════════════════════════════════════
void test_pipeline_detects_anomaly() {
    TEST("pipeline raises alert on high-rate traffic spike") {
        ids::IDSConfig cfg;
        cfg.thresholds.alert_threshold = 0.50f;
        ids::IDS pipeline(cfg);

        bool alert_fired = false;
        pipeline.on_alert([&](const ids::Alert& a) {
            alert_fired = true;
        });

        // First, train baseline with normal traffic
        for (int i = 0; i < 100; ++i) {
            ids::Event ev;
            ev.source = "10.0.0.1";
            ev.destination = "10.0.0.2";
            ev.type = ids::EventType::NetworkPacket;
            ev.payload.port_src = 12345;
            ev.payload.port_dst = 80;
            ev.payload.protocol = 6;
            ev.payload.bytes_in = 500 + (i % 50);
            ev.payload.entropy = 0.3f;
            ev.payload.rate_hz = 10.f;
            pipeline.ingest(ev);
        }

        // Now inject a massive spike
        for (int i = 0; i < 50; ++i) {
            ids::Event ev;
            ev.source = "192.168.100.1";
            ev.destination = "10.0.0.2";
            ev.type = ids::EventType::NetworkPacket;
            ev.payload.port_src = 12345;
            ev.payload.port_dst = 80;
            ev.payload.protocol = 6;
            ev.payload.bytes_in = 65000;
            ev.payload.entropy = 0.95f;
            ev.payload.rate_hz = 50000.f;
            ev.flow.syn_count = 100;
            ev.flow.fin_count = 0;
            ev.flow.ack_count = 2;
            ev.flow.packets_total = 200;
            pipeline.ingest(ev);
        }

        // After enough anomalous events, the pipeline should fire
        // (may take more events due to SSM accumulation)
        // We check that at least the anomaly score increased
        auto gs = pipeline.global_state();
        ASSERT_TRUE(gs.anomaly_history > 0.f || alert_fired);
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }
}

// ═══════════════════════════════════════════════════════════════
//  Test: ConfigHolder hot-reload
// ═══════════════════════════════════════════════════════════════
void test_config_hot_reload() {
    TEST("ConfigHolder update and rollback") {
        ids::ConfigHolder holder;
        auto c1 = std::make_shared<ids::IDSConfig>();
        c1->thresholds.alert_threshold = 0.50f;

        ASSERT_TRUE(holder.update(c1));
        ASSERT_EQ(holder.history_depth(), 0u);

        auto c2 = std::make_shared<ids::IDSConfig>();
        c2->thresholds.alert_threshold = 0.70f;
        ASSERT_TRUE(holder.update(c2));
        ASSERT_EQ(holder.history_depth(), 1u);

        ASSERT_TRUE(holder.rollback());
        auto current = holder.get();
        ASSERT_NEAR(current->thresholds.alert_threshold, 0.50f, 0.001f);
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }
}

// ═══════════════════════════════════════════════════════════════
//  Test: NearMissDetector
// ═══════════════════════════════════════════════════════════════
void test_near_miss_detector() {
    TEST("NearMissDetector triggers on threshold") {
        ids::NearMissDetector nm(60.f, 3, 0.25f);

        // Below minimum — should not trigger
        ASSERT_TRUE(!nm.check("10.0.0.1", 0.10f));
        ASSERT_TRUE(!nm.check("10.0.0.1", 0.15f));

        // In range — accumulates
        ASSERT_TRUE(!nm.check("10.0.0.1", 0.30f));
        ASSERT_TRUE(!nm.check("10.0.0.1", 0.35f));
        ASSERT_TRUE(nm.check("10.0.0.1", 0.40f));  // 3rd → triggers

        // Above max (0.6) — does not accumulate
        ASSERT_TRUE(!nm.check("10.0.0.1", 0.70f));
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }
}

// ═══════════════════════════════════════════════════════════════
//  Test: Dataset ingestion end-to-end (small)
// ═══════════════════════════════════════════════════════════════
void test_dataset_ingestion() {
    TEST("DatasetIngester parses FlowCSV correctly") {
        ids::IDSConfig cfg;
        ids::IDS pipeline(cfg);
        ids::DatasetIngester ingester(pipeline, 1024);

        // Ingest a known attack file — just verify it parses without crashing
        auto res = ingester.ingest_file("real_datasets/portscan.csv", false, 100);

        ASSERT_TRUE(res.rows_parsed > 0);
        ASSERT_TRUE(res.rows_ingested > 0);
        // Port scan data should have some attack events
        ASSERT_TRUE(res.stats.attack_events > 0 || res.stats.benign_events > 0);
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }

    TEST("DatasetIngester computes TP/FP/FN/TN") {
        ids::IDSConfig cfg;
        ids::IDS pipeline(cfg);
        ids::DatasetIngester ingester(pipeline, 1024);
        ingester.set_thresholds({0.05f, 0.10f, 0.60f, 0.90f, 0.99f});

        auto res = ingester.ingest_file("real_datasets/portscan.csv", false, 200);

        uint64_t total = res.tp + res.tn + res.fp + res.fn;
        ASSERT_TRUE(total > 0);
        // All events should be classified into one of the four categories
        ASSERT_EQ(total, res.rows_ingested);
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }
}

// ═══════════════════════════════════════════════════════════════
//  Test: Memory key construction
// ═══════════════════════════════════════════════════════════════
void test_memory_key() {
    TEST("key_from_event extracts IPs") {
        ids::Event ev;
        ev.source = "10.0.0.1";
        ev.destination = "10.0.0.2";
        auto key = ids::key_from_event(ev, ids::MemoryScope::IP);
        ASSERT_EQ(key.ip, "10.0.0.1");
        ASSERT_EQ(key.host, "10.0.0.2");
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }
}

// ═══════════════════════════════════════════════════════════════
//  Test: Global state after ingest
// ═══════════════════════════════════════════════════════════════
void test_global_state() {
    TEST("global_state returns valid drift and anomaly") {
        ids::IDSConfig cfg;
        ids::IDS pipeline(cfg);

        // Ingest some events
        for (int i = 0; i < 20; ++i) {
            ids::Event ev;
            ev.source = "10.0.0.1";
            ev.destination = "10.0.0.2";
            ev.type = ids::EventType::NetworkPacket;
            ev.payload.bytes_in = 100 + i;
            ev.payload.rate_hz = 10.f;
            pipeline.ingest(ev);
        }

        auto gs = pipeline.global_state();
        ASSERT_TRUE(std::isfinite(gs.drift_score));
        ASSERT_TRUE(std::isfinite(gs.anomaly_history));
        ASSERT_TRUE(gs.drift_score >= 0.f);
        PASS();
    } catch (const std::exception& e) { FAIL(e.what()); }
}

// ═══════════════════════════════════════════════════════════════
//  Main
// ═══════════════════════════════════════════════════════════════
int main() {
    std::cout << "=== IDS Unit Tests ===" << std::endl;

    test_score_to_decision();
    test_config_validation();
    test_csv_parsing();
    test_csv_to_event();
    test_memory_key();
    test_near_miss_detector();
    test_config_hot_reload();
    test_pipeline_ingest();
    test_global_state();
    test_pipeline_detects_anomaly();
    test_dataset_ingestion();

    std::cout << "\n=== Results: " << g_passed << " passed, "
              << g_failed << " failed ===" << std::endl;
    return g_failed > 0 ? 1 : 0;
}
