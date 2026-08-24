// ─────────────────────────────────────────────────────────────
//  ids_benchmark — throughput & latency benchmark
//
//  Measures events/sec and per-stage latency for the full
//  ingestion pipeline under synthetic load.
//
//  Build:
//    clang++ -std=c++17 -O2 -Iinclude ids_benchmark.cpp -o build/ids_benchmark -lpthread
//    ./build/ids_benchmark [events]
// ─────────────────────────────────────────────────────────────
#include "ids.hpp"
#include <chrono>
#include <iomanip>
#include <iostream>
#include <random>
#include <thread>

int main(int argc, char** argv) {
    uint64_t num_events = 100000;
    if (argc > 1) num_events = std::stoull(argv[1]);

    ids::IDSConfig cfg;
    cfg.thresholds.alert_threshold = 0.85f; // reduce noise in benchmark

    ids::IDS pipeline(cfg);

    // Generate synthetic events
    std::minstd_rand rng(42);
    std::uniform_int_distribution<int> ip_dist(0, 255);
    std::uniform_int_distribution<int> port_dist(1, 65535);
    std::uniform_int_distribution<int> proto_dist(0, 5);
    std::uniform_real_distribution<float> rate_dist(0.1f, 100.f);
    std::uniform_real_distribution<float> bytes_dist(40, 1500);

    auto make_event = [&](uint64_t i) {
        ids::Event ev;
        ev.source = "10.0." + std::to_string(ip_dist(rng)) + "." + std::to_string(ip_dist(rng));
        ev.destination = "192.168." + std::to_string(ip_dist(rng)) + "." + std::to_string(ip_dist(rng));
        ev.type = ids::EventType::NetworkPacket;
        ev.payload.bytes_in = static_cast<uint64_t>(bytes_dist(rng));
        ev.payload.bytes_out = static_cast<uint64_t>(bytes_dist(rng) * 0.5f);
        ev.payload.port_src = port_dist(rng);
        ev.payload.port_dst = port_dist(rng);
        ev.payload.protocol = static_cast<uint8_t>(proto_dist(rng));
        ev.payload.flags = static_cast<uint8_t>(rng() & 0xFF);
        ev.payload.entropy = rate_dist(rng) / 100.f;
        ev.payload.rate_hz = rate_dist(rng);
        ev.flow.packets_total = 1 + (rng() % 10);
        ev.flow.packet_size_mean = bytes_dist(rng);
        ev.flow.iat_mean = rate_dist(rng) * 0.01f;
        ev.flow.syn_count = rng() % 3;
        ev.flow.down_up_ratio = rate_dist(rng) * 0.1f;
        ev.time = std::chrono::steady_clock::now();
        return ev;
    };

    // Warmup: 1000 events to stabilize adaptive state
    for (uint64_t i = 0; i < 1000; ++i)
        pipeline.ingest(make_event(i));

    // Benchmark
    uint64_t alert_count = 0;
    pipeline.on_alert([&](const ids::Alert&) { alert_count++; });

    auto bench_start = std::chrono::steady_clock::now();

    for (uint64_t i = 0; i < num_events; ++i) {
        auto ev = make_event(i);
        ev.time = std::chrono::steady_clock::now();
        pipeline.ingest(ev);
    }

    auto bench_end = std::chrono::steady_clock::now();
    float elapsed_s = std::chrono::duration<float>(bench_end - bench_start).count();
    float events_per_sec = static_cast<float>(num_events) / elapsed_s;

    auto lat = pipeline.latency_stats();

    std::cout << "\n═══════════════════════════════════════════════════" << std::endl;
    std::cout << "  IDS Throughput Benchmark — " << num_events << " events" << std::endl;
    std::cout << "═══════════════════════════════════════════════════" << std::endl;
    std::cout << "  Throughput:  " << std::fixed << std::setprecision(0)
              << events_per_sec << " events/sec" << std::endl;
    std::cout << "  Total time:  " << std::setprecision(3) << elapsed_s << " s" << std::endl;
    std::cout << "  Alerts:      " << alert_count << std::endl;
    std::cout << "\n  Per-Stage Latency:" << std::endl;
    std::cout << "    L0 (Z-score)          avg " << std::setw(7) << std::setprecision(1)
              << lat.l0_avg_us << " us   p99 " << lat.l0_p99_us << " us" << std::endl;
    std::cout << "    Autoencoder           avg " << std::setw(7) << std::setprecision(1)
              << lat.ae_avg_us << " us   p99 " << lat.ae_p99_us << " us" << std::endl;
    std::cout << "    L1 (SSM)              avg " << std::setw(7) << std::setprecision(1)
              << lat.l1_avg_us << " us" << std::endl;
    std::cout << "    L2 (HSSM)             avg " << std::setw(7) << std::setprecision(1)
              << lat.l2_avg_us << " us" << std::endl;
    std::cout << "    Retrieval             avg " << std::setw(7) << std::setprecision(1)
              << lat.retrieval_avg_us << " us   p99 " << lat.retrieval_p99_us << " us" << std::endl;
    std::cout << "    Specialist            avg " << std::setw(7) << std::setprecision(1)
              << lat.specialist_avg_us << " us" << std::endl;
    std::cout << "    NearMiss/Aggregate    avg " << std::setw(7) << std::setprecision(1)
              << lat.near_miss_avg_us << " us" << std::endl;
    std::cout << "    Online Learning       avg " << std::setw(7) << std::setprecision(1)
              << lat.online_avg_us << " us   p99 " << lat.online_p99_us << " us" << std::endl;
    std::cout << "    Reasoning             avg " << std::setw(7) << std::setprecision(1)
              << lat.reasoning_avg_us << " us   p99 " << lat.reasoning_p99_us << " us" << std::endl;
    std::cout << "    Correlation           avg " << std::setw(7) << std::setprecision(1)
              << lat.correlation_avg_us << " us" << std::endl;
    std::cout << "    Decision              avg " << std::setw(7) << std::setprecision(1)
              << lat.decision_avg_us << " us" << std::endl;
    std::cout << "    ─────────────────────────────────────────" << std::endl;
    std::cout << "    Total (end-to-end)    avg " << std::setw(7) << std::setprecision(1)
              << lat.total_avg_us << " us   p99 " << lat.total_p99_us << " us" << std::endl;
    std::cout << "═══════════════════════════════════════════════════" << std::endl;

    if (lat.total_p99_us > 1000)
        std::cout << "\n  ⚠ p99 exceeds 1ms — may not sustain 10K+ ev/s" << std::endl;
    else
        std::cout << "\n  ✓ p99 under 1ms — suitable for real-time use" << std::endl;
    std::cout << std::endl;

    return 0;
}
