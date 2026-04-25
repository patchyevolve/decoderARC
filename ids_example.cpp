// ─────────────────────────────────────────────────────────────
//  ids_example.cpp  —  IDS v2 integration demo
//  Compile: g++ -std=c++17 -O2 -Iinclude ids_example.cpp -o ids_demo_v2
// ─────────────────────────────────────────────────────────────
#include "ids.hpp"
#include <iostream>
#include <random>
#include <thread>
#include <chrono>

// ── Event adapters ───────────────────────────────────────────
ids::Event make_packet(const std::string& src, const std::string& dst,
                       uint16_t sport, uint16_t dport,
                       uint8_t proto, uint32_t bytes)
{
    ids::Event ev;
    ev.source           = src;
    ev.destination      = dst;
    ev.type             = ids::EventType::NetworkPacket;
    ev.payload.port_src = sport;
    ev.payload.port_dst = dport;
    ev.payload.protocol = proto;
    ev.payload.bytes_in = bytes;
    ev.payload.rate_hz  = static_cast<float>(bytes) * 1000.f;
    ev.payload.entropy  = 0.2f;
    return ev;
}

ids::Event make_auth(const std::string& user, const std::string& host, bool failed)
{
    ids::Event ev;
    ev.source          = user;
    ev.destination     = host;
    ev.type            = ids::EventType::AuthEvent;
    ev.payload.flags   = failed ? 0x01 : 0x00;
    ev.payload.rate_hz = failed ? 200.f : 1.f;
    ev.payload.entropy = 0.1f;
    return ev;
}

ids::Event make_syslog(const std::string& host, bool is_error)
{
    ids::Event ev;
    ev.source          = host;
    ev.destination     = "syslog";
    ev.type            = ids::EventType::SysLog;
    ev.payload.flags   = is_error ? 0xFF : 0x00;
    ev.payload.entropy = is_error ? 0.92f : 0.1f;
    ev.payload.rate_hz = 10.f;
    return ev;
}

// ── Integration wrapper ───────────────────────────────────────
class NetworkMonitor {
public:
    NetworkMonitor() {
        ids::IDSConfig cfg;

        // § 3 — Gate & decision thresholds
        cfg.gate.gate_threshold        = 0.35f;
        cfg.thresholds.alert_threshold = 0.55f;
        cfg.thresholds.block_threshold = 0.80f;
        cfg.thresholds.log_threshold   = 0.35f;
        cfg.thresholds.ignore_threshold= 0.15f;

        // § 2 — Memory write gate
        cfg.write_policy.memory_write_gate  = 0.50f;
        cfg.write_policy.memory_force_gate  = 0.85f;
        cfg.write_policy.write_on_rule_match= true;
        cfg.write_policy.write_on_block     = true;

        // § 3 — Force reasoning
        cfg.force_gate.force_local      = 0.90f;
        cfg.force_gate.force_on_rule_match = true;

        // § 3 — Escalation
        cfg.escalation.escalate_hist    = 0.75f;
        cfg.escalation.repeat_escalate_n= 3;

        // § 5 — Panic
        cfg.panic.panic_threshold       = 200;

        // § 9 — Telemetry
        cfg.telemetry.routing_debug     = true;
        cfg.telemetry.latency_tracking  = true;

        // Block list
        cfg.policy.block_list = {"10.0.0.99"};

        pipeline_ = std::make_unique<ids::IDS>(cfg);

        pipeline_->on_alert([](const ids::Alert& a) {
            std::cout << "[ALERT] conf=" << a.confidence
                      << " class=" << a.attack_class
                      << " src=" << a.source
                      << " corr=" << a.trace.corr_score
                      << "\n";
        });
        pipeline_->on_block([](const std::string& src) {
            std::cout << "[BLOCK] " << src << "\n";
        });
        pipeline_->on_escalate([](const ids::Alert& a) {
            std::cerr << "[ESCALATE] " << a.source
                      << " campaign=" << a.trace.campaign_id
                      << "\n";
        });

        // Known signatures
        ids::Vec dos_sig{};
        dos_sig[0] = 1.f; dos_sig[9] = 1.f;
        pipeline_->load_signature(dos_sig, "DoS-signature", 1.0f);

        // Rules
        pipeline_->add_rule({1, "PortScan",   "",          0.60f, ids::Decision::Alert});
        pipeline_->add_rule({2, "KnownBadIP", "10.0.0.99", 0.00f, ids::Decision::Block});
    }

    void ingest(const ids::Event& ev) { pipeline_->ingest(ev); }

    void print_summary() const {
        const auto& m = pipeline_->metrics();
        auto lat = pipeline_->latency_stats();
        std::cout << "\n=== v2 Pipeline Summary ===\n"
                  << "  events_total   : " << m.events_total.load()     << "\n"
                  << "  alerts_total   : " << m.alerts_total.load()      << "\n"
                  << "  blocks_total   : " << m.blocks_total.load()      << "\n"
                  << "  escalations    : " << m.escalations_total.load() << "\n"
                  << "  reasoning_calls: " << m.reasoning_calls.load()   << "\n"
                  << "  faults_total   : " << m.faults_total.load()      << "\n"
                  << "  l0_avg_us      : " << lat.l0_avg_us              << "\n"
                  << "  reasoning_avg  : " << lat.reasoning_avg_us       << "\n"
                  << "  total_avg_us   : " << lat.total_avg_us           << "\n";

        auto gs = pipeline_->global_state();
        std::cout << "  anomaly_history: " << gs.anomaly_history << "\n"
                  << "  drift_score    : " << gs.drift_score     << "\n";

        auto campaigns = pipeline_->active_campaigns();
        if (!campaigns.empty()) {
            std::cout << "  active_campaigns:\n";
            for (const auto& c : campaigns)
                std::cout << "    [" << c.id << "] " << c.attack_class
                          << " events=" << c.event_count << "\n";
        }

        auto faults = pipeline_->fault_log_entries(5);
        if (!faults.empty()) {
            std::cout << "  recent_faults:\n";
            for (const auto& f : faults)
                std::cout << "    " << f.key << ": " << f.detail << "\n";
        }
    }

private:
    std::unique_ptr<ids::IDS> pipeline_;
};

// ── Demo ─────────────────────────────────────────────────────
int main() {
    std::cout << "=== IDS v2 Pipeline Demo ===\n\n";
    NetworkMonitor mon;
    std::mt19937 rng(42);
    std::uniform_int_distribution<int> ports(1024, 65535);
    std::uniform_int_distribution<int> bsz(100, 1500);

    // Phase 1 — normal traffic
    std::cout << "--- Phase 1: Normal traffic (50 packets) ---\n";
    for (int i = 0; i < 50; ++i) {
        mon.ingest(make_packet("192.168.1." + std::to_string(i % 10),
                               "10.0.0.1", ports(rng), 80, 6, bsz(rng)));
        std::this_thread::sleep_for(std::chrono::microseconds(200));
    }

    // Phase 2 — brute-force auth
    std::cout << "\n--- Phase 2: Auth brute-force (40 attempts) ---\n";
    for (int i = 0; i < 40; ++i)
        mon.ingest(make_auth("attacker", "server01", true));

    // Phase 3 — DoS burst from blocked IP
    std::cout << "\n--- Phase 3: DoS burst from blocked IP ---\n";
    for (int i = 0; i < 60; ++i)
        mon.ingest(make_packet("10.0.0.99", "10.0.0.1",
                               ports(rng), 80, 6, 65000));

    // Phase 4 — error log flood
    std::cout << "\n--- Phase 4: Error log flood ---\n";
    for (int i = 0; i < 20; ++i)
        mon.ingest(make_syslog("webserver", true));

    // Phase 5 — multi-stage simulation (port scan → brute force → lateral)
    std::cout << "\n--- Phase 5: Multi-stage attack simulation ---\n";
    for (int i = 0; i < 10; ++i)
        mon.ingest(make_packet("172.16.0.1", "10.0.0.2",
                               ports(rng), ports(rng), 6, 64));   // port scan
    for (int i = 0; i < 15; ++i)
        mon.ingest(make_auth("172.16.0.1", "server02", true));     // brute force

    mon.print_summary();
    return 0;
}
