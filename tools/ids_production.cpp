// ═════════════════════════════════════════════════════════════
//  ids_production — Production-grade IDS daemon
//
//  Lifecycle:
//    1. Load config from JSON file (or use defaults)
//    2. Load saved state (memory, autoencoder, L0 stats) from disk
//    3. If no saved state, train on benign CSV data
//    4. Start capture loop (AF_PACKET or pipe from CSV replay)
//    5. Graceful shutdown on SIGINT/SIGTERM with state save
//
//  Build:
//    clang++ -std=c++17 -O2 -I../include ids_production.cpp \
//      -o ids_production -lpthread
//
//  Run:
//    sudo ./ids_production eth0                     # live capture
//    ./ids_production --replay attack.csv            # offline replay
//    ./ids_production --train monday_benign.csv      # train only
//
//  Signals:
//    SIGINT/SIGTERM — graceful stop + state save
//    SIGHUP        — hot-reload config
// ═════════════════════════════════════════════════════════════
#include "ids.hpp"
#include "ids_ingest.hpp"
#include "ids_parallel.hpp"
#include "ids_cloud.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

// POSIX networking for live capture + metrics server
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

// ─── Signal handling ────────────────────────────────────────
static std::atomic<bool> g_running{true};
static std::atomic<bool> g_reload{false};
static std::chrono::steady_clock::time_point g_start_time;

extern "C" void handle_signal(int sig) {
    if (sig == SIGHUP) { g_reload = true; return; }
    g_running = false;
}

// ─── Production config (loaded from JSON) ─────────────────────
struct ProductionConfig {
    std::string state_dir         = "/var/lib/ids";
    std::string benign_csv_dir    = "";
    size_t      train_rows        = 25000;
    float       alert_threshold   = 0.70f;
    float       block_threshold   = 0.92f;
    float       escalate_threshold = 0.995f;
    int         shards            = 0;          // 0 = single pipeline
    int         capture_threads   = 2;
    bool        verbose           = false;
    bool        prometheus        = false;
    int         prometheus_port   = 9102;
    // Cloud uploader
    std::string cloud_url         = "";
    std::string device_id         = "";
    std::string api_key           = "";
    bool        forwarder_only   = true; // default: only forward events, no edge detection
};

ProductionConfig load_config(const std::string& path) {
    ProductionConfig cfg;
    std::ifstream f(path);
    if (!f) return cfg;
    
    auto trim = [](std::string s) {
        auto notspace = [](char c) { return !std::isspace(static_cast<unsigned char>(c)); };
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), notspace));
        s.erase(std::find_if(s.rbegin(), s.rend(), notspace).base(), s.end());
        return s;
    };
    std::string line;
    while (std::getline(f, line)) {
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));
        if (key == "state_dir")         cfg.state_dir = val;
        else if (key == "benign_csv_dir")  cfg.benign_csv_dir = val;
        else if (key == "train_rows")   cfg.train_rows = std::stoul(val);
        else if (key == "alert_threshold") cfg.alert_threshold = std::stof(val);
        else if (key == "block_threshold") cfg.block_threshold = std::stof(val);
        else if (key == "escalate_threshold") cfg.escalate_threshold = std::stof(val);
        else if (key == "shards")       cfg.shards = std::stoi(val);
        else if (key == "verbose")      cfg.verbose = (val == "true" || val == "1");
        else if (key == "prometheus")   cfg.prometheus = (val == "true" || val == "1");
        else if (key == "prometheus_port") cfg.prometheus_port = std::stoi(val);
        else if (key == "cloud_url")    cfg.cloud_url = val;
        else if (key == "device_id")    cfg.device_id = val;
        else if (key == "api_key")      cfg.api_key = val;
        else if (key == "forwarder_only") cfg.forwarder_only = (val == "true" || val == "1");
    }
    return cfg;
}

// ─── Prometheus metrics (text format, served via simple TCP) ─
class MetricsServer {
public:
    MetricsServer(int port) : port_(port), sock_(-1) {
        sock_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (sock_ < 0) return;
        int opt = 1;
        ::setsockopt(sock_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port_);
        addr.sin_addr.s_addr = INADDR_ANY;
        if (::bind(sock_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            ::close(sock_); sock_ = -1; return;
        }
        ::listen(sock_, 5);
    }

    void serve_async(ids::IDS* pipeline) {
        if (sock_ < 0) return;
        thread_ = std::thread([this, pipeline]() {
            while (g_running) {
                struct sockaddr_in client;
                socklen_t len = sizeof(client);
                int fd = ::accept(sock_, (struct sockaddr*)&client, &len);
                if (fd < 0) break;
                // Read request
                char buf[256];
                ::recv(fd, buf, sizeof(buf), 0);
                
                // Check if this is a health check
                bool is_health = (std::strstr(buf, "GET /health") != nullptr);
                
                if (is_health) {
                    auto uptime_s = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::steady_clock::now() - g_start_time).count();
                    std::ostringstream hbody;
                    hbody << "{\"status\":\"ok\",\"uptime\":" << uptime_s << "}";
                    std::ostringstream hresp;
                    hresp << "HTTP/1.1 200 OK\r\n"
                          << "Content-Type: application/json\r\n"
                          << "Connection: close\r\n\r\n"
                          << hbody.str();
                    std::string hstr = hresp.str();
                    ::send(fd, hstr.data(), hstr.size(), 0);
                    ::close(fd);
                    continue;
                }
                
                // Build Prometheus response
                auto lat = pipeline->latency_stats();
                auto gs = pipeline->global_state();
                auto& m = pipeline->metrics();

                std::ostringstream resp;
                resp << "HTTP/1.1 200 OK\r\n"
                     << "Content-Type: text/plain; charset=utf-8\r\n"
                     << "Connection: close\r\n\r\n"
                     << "# HELP ids_events_total Total events processed\n"
                     << "# TYPE ids_events_total counter\n"
                     << "ids_events_total " << m.events_total.load() << "\n"
                     << "# HELP ids_alerts_total Total alerts raised\n"
                     << "# TYPE ids_alerts_total counter\n"
                     << "ids_alerts_total " << m.alerts_total.load() << "\n"
                     << "# HELP ids_blocks_total Total blocks\n"
                     << "# TYPE ids_blocks_total counter\n"
                     << "ids_blocks_total " << m.blocks_total.load() << "\n"
                     << "# HELP ids_faults_total Total faults\n"
                     << "# TYPE ids_faults_total counter\n"
                     << "ids_faults_total " << m.faults_total.load() << "\n"
                     << "# HELP ids_latency_us Event processing latency\n"
                     << "# TYPE ids_latency_us gauge\n"
                     << "ids_latency_avg_us " << lat.total_avg_us << "\n"
                     << "ids_latency_p99_us " << lat.total_p99_us << "\n"
                     << "# HELP ids_drift_score Current drift score\n"
                     << "# TYPE ids_drift_score gauge\n"
                     << "ids_drift_score " << gs.drift_score << "\n"
                     << "# HELP ids_anomaly_history Current anomaly history\n"
                     << "# TYPE ids_anomaly_history gauge\n"
                     << "ids_anomaly_history " << gs.anomaly_history << "\n";

                std::string body = resp.str();
                ::send(fd, body.data(), body.size(), 0);
                ::close(fd);
            }
        });
    }

    ~MetricsServer() { if (sock_ >= 0) ::close(sock_); if (thread_.joinable()) thread_.join(); }

private:
    int port_;
    int sock_;
    std::thread thread_;
};

// ─── Production daemon ───────────────────────────────────────
int main(int argc, char** argv) {
    g_start_time = std::chrono::steady_clock::now();
    std::signal(SIGINT,  handle_signal);
    std::signal(SIGTERM, handle_signal);
    std::signal(SIGHUP,  handle_signal);

    // Parse args
    std::string iface, replay_path, train_path, config_path = "/etc/ids/config.conf";
    bool train_only = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--replay" && i + 1 < argc) replay_path = argv[++i];
        else if (arg == "--train" && i + 1 < argc) train_path = argv[++i];
        else if (arg == "--config" && i + 1 < argc) config_path = argv[++i];
        else if (arg == "--train-only") train_only = true;
        else if (iface.empty()) iface = arg;
    }

    auto cfg = load_config(config_path);
    std::cout << "═══════════════════════════════════════════════" << std::endl;
    std::cout << "  IDS Production Daemon" << std::endl;
    std::cout << "═══════════════════════════════════════════════" << std::endl;
    std::cout << "  State:     " << cfg.state_dir << std::endl;
    std::cout << "  Interface: " << (iface.empty() ? "(none)" : iface) << std::endl;
    std::cout << "  Shards:    " << (cfg.shards > 0 ? std::to_string(cfg.shards) : "single")
              << std::endl;
    std::cout << "  Threshold: alert=" << cfg.alert_threshold
              << " block=" << cfg.block_threshold
              << " escalate=" << cfg.escalate_threshold << std::endl;
    std::cout << "  Mode:      " << (cfg.forwarder_only ? "forwarder-only" : "edge inference")
              << std::endl;

    // ── IDS pipeline ────────────────────────────────────────
    ids::IDSConfig ids_cfg;
    ids_cfg.thresholds.alert_threshold  = cfg.alert_threshold;
    ids_cfg.thresholds.block_threshold  = cfg.block_threshold;
    ids_cfg.thresholds.escalate_threshold = cfg.escalate_threshold;

    ids::IDS pipeline(ids_cfg);

    // ── Load or train baseline ──────────────────────────────
    bool state_loaded = pipeline.load_all(cfg.state_dir);

    if (!state_loaded && !train_path.empty()) {
        std::cout << "\n── Training from: " << train_path << std::endl;
        ids::DatasetIngester ingester(pipeline, 4096);
        auto res = ingester.ingest_file(train_path, false, cfg.train_rows);
        pipeline.train_autoencoder(3);
        pipeline.save_all(cfg.state_dir);
        std::cout << "  Trained on " << res.rows_ingested << " rows, state saved."
                  << std::endl;
    }

    if (state_loaded)
        std::cout << "  State loaded from " << cfg.state_dir << std::endl;
    else
        std::cout << "  No saved state — running with defaults" << std::endl;

    if (train_only) {
        std::cout << "\n  Train-only mode complete. Exiting." << std::endl;
        return 0;
    }

    // ── Cloud uploader ───────────────────────────────────────
    std::unique_ptr<ids::CloudUploader> cloud;
    if (!cfg.cloud_url.empty() && !cfg.device_id.empty() && !cfg.api_key.empty()) {
        std::cout << "\n── Cloud uploader: " << cfg.cloud_url << std::endl;
        cloud = std::make_unique<ids::CloudUploader>(
            cfg.cloud_url, cfg.device_id, cfg.api_key, 5, 30
        );
        cloud->set_metrics_fn([&]() -> ids::CloudMetrics {
            auto& m = pipeline.metrics();
            static auto last_ts = std::chrono::steady_clock::now();
            static uint64_t prev_events = 0;
            static uint64_t prev_alerts = 0;
            static uint64_t prev_blocks = 0;

            auto now = std::chrono::steady_clock::now();
            double elapsed_s = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_ts).count() / 1000.0;
            if (elapsed_s <= 0.0) elapsed_s = 1.0;

            uint64_t events_total = m.events_total.load();
            uint64_t alerts_total = m.alerts_total.load();
            uint64_t blocks_total = m.blocks_total.load();

            float events_per_sec = static_cast<float>(
                (events_total >= prev_events ? events_total - prev_events : events_total) / elapsed_s
            );
            float alerts_per_sec = static_cast<float>(
                (alerts_total >= prev_alerts ? alerts_total - prev_alerts : alerts_total) / elapsed_s
            );
            float blocks_per_sec = static_cast<float>(
                (blocks_total >= prev_blocks ? blocks_total - prev_blocks : blocks_total) / elapsed_s
            );

            last_ts = now;
            prev_events = events_total;
            prev_alerts = alerts_total;
            prev_blocks = blocks_total;

            return ids::CloudMetrics{
                "",  // time — filled by uploader
                events_per_sec,
                alerts_per_sec,
                blocks_per_sec,
                0, 0, 0, 0, 0, 0
            };
        });
        cloud->start();
        std::cout << "  Cloud uploader started" << std::endl;
    }

    // ── Alert callback (skipped in forwarder-only mode) ─────
    uint64_t alert_id = 0;
    if (!cfg.forwarder_only) {
    pipeline.on_alert([&](const ids::Alert& a) {
        auto event_type_name = [](ids::EventType t) -> std::string {
            switch (t) {
                case ids::EventType::NetworkPacket: return "Network";
                case ids::EventType::SysLog: return "System";
                case ids::EventType::ProcessEvent: return "Process";
                case ids::EventType::AuthEvent: return "Auth";
                case ids::EventType::FileAccess: return "File";
                case ids::EventType::ApiCall: return "API";
                case ids::EventType::Signal: return "Signal";
                default: return "System";
            }
        };
        auto protocol_name = [](const std::string& p) -> std::string {
            if (p == "6") return "TCP";
            if (p == "17") return "UDP";
            if (p == "1" || p == "58") return "ICMP";
            if (p == "") return "";
            return p;
        };

        std::string decision_str = "alert";
        switch (a.decision) {
            case ids::Decision::Ignore:   decision_str = "ignore"; break;
            case ids::Decision::Log:      decision_str = "log"; break;
            case ids::Decision::Alert:    decision_str = "alert"; break;
            case ids::Decision::Block:    decision_str = "block"; break;
            case ids::Decision::Escalate: decision_str = "escalate"; break;
            default: break;
        }

        auto now = std::chrono::system_clock::now();
        auto tt  = std::chrono::system_clock::to_time_t(now);
        alert_id++;
        // JSON to stdout (pipe to file/logstash)
        char timebuf[64];
        std::strftime(timebuf, sizeof(timebuf), "%FT%TZ", std::gmtime(&tt));
        std::cout << "{\"timestamp\":\"" << timebuf
                  << "\",\"alert_id\":" << alert_id
                  << ",\"severity\":\"" << decision_str
                  << "\",\"src\":\"" << a.source
                  << "\",\"dst\":\"" << a.destination
                  << "\",\"class\":\"" << a.attack_class
                  << "\",\"confidence\":" << std::fixed << std::setprecision(3) << a.confidence
                  << ",\"explanation\":\"" << a.explanation << "\"}" << std::endl;

        // Push to cloud if uploader is active
        if (cloud) {
            if (decision_str == "log") {
                ids::CloudLog lg;
                lg.time = timebuf;
                lg.type = event_type_name(a.event_type);
                lg.protocol = protocol_name(a.protocol);
                lg.src_ip = a.source;
                lg.src_port = a.source_port;
                lg.dst_ip = a.destination;
                lg.dst_port = a.dest_port;
                lg.severity = "info";
                lg.message = a.explanation;
                cloud->push_log(lg);
            } else if (decision_str != "ignore") {
                ids::CloudAlert ca;
                ca.time = timebuf;
                ca.decision = decision_str;
                ca.severity = (a.confidence > 0.9f ? "critical" :
                               a.confidence > 0.7f ? "high" :
                               a.confidence > 0.5f ? "medium" : "low");
                ca.confidence = a.confidence;
                ca.source_ip = a.source;
                ca.dest_ip = a.destination;
                ca.source_port = a.source_port;
                ca.dest_port = a.dest_port;
                ca.protocol = protocol_name(a.protocol);
                ca.attack_class = a.attack_class;
                ca.anomaly_score = a.confidence;
                ca.ae_score = 0;
                ca.explanation = a.explanation;
                cloud->push_alert(ca);
            }
        }
    }); // end on_alert callback
    } // end if (!cfg.forwarder_only)

    // ── Prometheus metrics ─────────────────────────────────
    MetricsServer metrics_srv(cfg.prometheus_port);
    if (cfg.prometheus)
        metrics_srv.serve_async(&pipeline);

    // ── Capture loop ─────────────────────────────────────────
    if (!replay_path.empty()) {
        std::cout << "\n── Replay mode: " << replay_path << std::endl;
        std::cout << "  Press Ctrl+C to stop.\n" << std::endl;

        ids::DatasetIngester ingester(pipeline, 4096);
        ingester.set_thresholds({
            0.05f, 0.10f, cfg.alert_threshold, cfg.block_threshold, cfg.escalate_threshold
        });

        uint64_t count = 0;
        auto start = std::chrono::steady_clock::now();

        // Stream in chunks — check g_running between batches
        std::ifstream file(replay_path);
        if (file.is_open()) {
            // Parse header and build column map for real CSV parsing
            std::string header_line;
            if (!std::getline(file, header_line)) {
                std::cerr << "  Empty CSV file" << std::endl;
            } else {
                while (!header_line.empty() && (header_line.back() == '\r' || header_line.back() == '\n'))
                    header_line.pop_back();
                auto header_cols = ids::parse_csv_line(header_line);
                auto cmap = ids::build_column_map(header_cols);
                auto fmt = ids::detect_format(header_line);

                if (fmt == ids::DatasetFormat::Unknown) {
                    std::cerr << "  Unknown CSV format, falling back to raw ingest" << std::endl;
                }

                std::vector<ids::Event> batch;
                batch.reserve(4096);
                std::string line;

                while (g_running && std::getline(file, line)) {
                    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                        line.pop_back();
                    if (line.empty()) continue;

                    auto cols = ids::parse_csv_line(line);
                    if (cols.size() < 5) continue;

                    ids::Event ev;
                    if (fmt != ids::DatasetFormat::Unknown) {
                        ev = ids::csv_to_event(cols, cmap);
                    } else {
                        ev.type = ids::EventType::NetworkPacket;
                        ev.source = "replay";
                        ev.destination = "target";
                        ev.payload.bytes_in = 100;
                        ev.payload.entropy = 0.3f;
                        ev.payload.rate_hz = 1.f;
                    }
                    ev.time = std::chrono::steady_clock::now();
                    batch.push_back(std::move(ev));

                    if (batch.size() >= 4096) {
                        for (auto& e : batch) pipeline.ingest(e);
                        count += batch.size();
                        batch.clear();
                    }
                }
                for (auto& e : batch) pipeline.ingest(e);
                count += batch.size();
            }
        }

        auto elapsed = std::chrono::duration<float>(
            std::chrono::steady_clock::now() - start).count();
        auto lat = pipeline.latency_stats();
        std::cout << "\n── Replay complete: " << count << " events in "
                  << std::fixed << std::setprecision(1) << elapsed << "s"
                  << " (" << (count / elapsed) << " ev/s)" << std::endl;
        std::cout << "  Avg latency: " << lat.total_avg_us << " us"
                  << "  p99: " << lat.total_p99_us << " us" << std::endl;

    } else if (!iface.empty()) {
        std::cout << "\n── Live capture on " << iface << std::endl;
        std::cout << "  Press Ctrl+C to stop.\n" << std::endl;

        // AF_PACKET capture (needs CAP_NET_RAW / sudo)
        // (code from ids_collector, kept simple here)
        int sock = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sock < 0) {
            std::cerr << "  Cannot open raw socket. Try: sudo " << argv[0] << " " << iface
                      << std::endl;
            return 1;
        }

        struct ifreq ifr{};
        std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
        if (::ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
            std::cerr << "  Interface not found: " << iface << std::endl;
            ::close(sock);
            return 1;
        }

        struct sockaddr_ll sll{};
        sll.sll_family   = AF_PACKET;
        sll.sll_ifindex  = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);
        if (::bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
            ::close(sock);
            return 1;
        }

        // Set receive timeout so we can check g_running periodically
        struct timeval tv{};
        tv.tv_sec = 1;
        ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        uint8_t pkt_buf[65536];
        uint64_t pkt_count = 0;
        auto start = std::chrono::steady_clock::now();

        while (g_running) {
            struct sockaddr_ll src{};
            socklen_t src_len = sizeof(src);
            ssize_t n = ::recvfrom(sock, pkt_buf, sizeof(pkt_buf), 0,
                                   (struct sockaddr*)&src, &src_len);
            if (n < 0) continue; // timeout → recheck g_running

            // Packet -> event (best-effort L2/L3/L4 parse)
            ids::Event ev;
            ev.type = ids::EventType::NetworkPacket;
            ev.payload.bytes_in = static_cast<uint64_t>(n);
            ev.payload.entropy = 0.3f;
            ev.payload.rate_hz = 10.f;
            ev.time = std::chrono::steady_clock::now();

            std::string src_ip = "pkt:" + std::to_string(pkt_count);
            std::string dst_ip = "net";
            uint16_t src_port = 0;
            uint16_t dst_port = 0;
            uint8_t protocol = 0;

            if (n >= static_cast<ssize_t>(sizeof(ether_header))) {
                const auto* eth = reinterpret_cast<const ether_header*>(pkt_buf);
                uint16_t ether_type = ntohs(eth->ether_type);
                size_t l3 = sizeof(ether_header);

                if (ether_type == ETHERTYPE_IP && n >= static_cast<ssize_t>(l3 + sizeof(iphdr))) {
                    const auto* ip4 = reinterpret_cast<const iphdr*>(pkt_buf + l3);
                    size_t ip4_hlen = static_cast<size_t>(ip4->ihl) * 4;
                    if (n >= static_cast<ssize_t>(l3 + ip4_hlen)) {
                        char sip[INET_ADDRSTRLEN] = {0};
                        char dip[INET_ADDRSTRLEN] = {0};
                        inet_ntop(AF_INET, &ip4->saddr, sip, sizeof(sip));
                        inet_ntop(AF_INET, &ip4->daddr, dip, sizeof(dip));
                        src_ip = sip;
                        dst_ip = dip;
                        protocol = ip4->protocol;

                        const uint8_t* l4 = pkt_buf + l3 + ip4_hlen;
                        size_t l4_len = static_cast<size_t>(n) - (l3 + ip4_hlen);
                        if (protocol == IPPROTO_TCP && l4_len >= sizeof(tcphdr)) {
                            const auto* tcp = reinterpret_cast<const tcphdr*>(l4);
                            src_port = ntohs(tcp->source);
                            dst_port = ntohs(tcp->dest);
                        } else if (protocol == IPPROTO_UDP && l4_len >= sizeof(udphdr)) {
                            const auto* udp = reinterpret_cast<const udphdr*>(l4);
                            src_port = ntohs(udp->source);
                            dst_port = ntohs(udp->dest);
                        }
                    }
                } else if (ether_type == ETHERTYPE_IPV6 && n >= static_cast<ssize_t>(l3 + sizeof(ip6_hdr))) {
                    const auto* ip6 = reinterpret_cast<const ip6_hdr*>(pkt_buf + l3);
                    char sip[INET6_ADDRSTRLEN] = {0};
                    char dip[INET6_ADDRSTRLEN] = {0};
                    inet_ntop(AF_INET6, &ip6->ip6_src, sip, sizeof(sip));
                    inet_ntop(AF_INET6, &ip6->ip6_dst, dip, sizeof(dip));
                    src_ip = sip;
                    dst_ip = dip;
                    protocol = ip6->ip6_nxt;

                    const uint8_t* l4 = pkt_buf + l3 + sizeof(ip6_hdr);
                    size_t l4_len = static_cast<size_t>(n) - (l3 + sizeof(ip6_hdr));
                    if (protocol == IPPROTO_TCP && l4_len >= sizeof(tcphdr)) {
                        const auto* tcp = reinterpret_cast<const tcphdr*>(l4);
                        src_port = ntohs(tcp->source);
                        dst_port = ntohs(tcp->dest);
                    } else if (protocol == IPPROTO_UDP && l4_len >= sizeof(udphdr)) {
                        const auto* udp = reinterpret_cast<const udphdr*>(l4);
                        src_port = ntohs(udp->source);
                        dst_port = ntohs(udp->dest);
                    }
                }
            }

            ev.source = src_ip;
            ev.destination = dst_ip;
            ev.payload.port_src = src_port;
            ev.payload.port_dst = dst_port;
            ev.payload.protocol = protocol;

            if (cloud) {
                std::string proto = "";
                if (protocol == IPPROTO_TCP) proto = "TCP";
                else if (protocol == IPPROTO_UDP) proto = "UDP";
                else if (protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6) proto = "ICMP";
                else if (protocol != 0) proto = std::to_string(protocol);

                auto sys_now = std::chrono::system_clock::now();
                auto sys_tt = std::chrono::system_clock::to_time_t(sys_now);
                char event_time[64];
                std::strftime(event_time, sizeof(event_time), "%FT%TZ", std::gmtime(&sys_tt));

                ids::CloudEvent ce;
                ce.time = event_time;
                ce.src_ip = src_ip;
                ce.src_port = src_port;
                ce.dst_ip = dst_ip;
                ce.dst_port = dst_port;
                ce.protocol = proto;
                ce.bytes = static_cast<int>(n);
                ce.event_type = "network";
                cloud->push_event(ce);
            }

            if (!cfg.forwarder_only) {
                pipeline.ingest(ev);
            }
            pkt_count++;

            if (pkt_count % 10000 == 0 && cfg.verbose) {
                auto elapsed = std::chrono::duration<float>(
                    std::chrono::steady_clock::now() - start).count();
                auto lat = pipeline.latency_stats();
                auto& m = pipeline.metrics();
                std::cout << "\r  " << pkt_count << " pkts, "
                          << m.alerts_total.load() << " alerts, "
                          << (pkt_count / elapsed) << " ev/s, lat="
                          << lat.total_avg_us << " us" << std::flush;
            }

            // Hot-reload check
            if (g_reload.exchange(false)) {
                auto new_cfg = load_config(config_path);
                ids::IDSConfig ids_new;
                ids_new.thresholds.alert_threshold = new_cfg.alert_threshold;
                ids_new.thresholds.block_threshold = new_cfg.block_threshold;
                ids_new.thresholds.escalate_threshold = new_cfg.escalate_threshold;
                pipeline.hot_reload_config(ids_new);
                std::cout << "\n  Config reloaded: alert=" << new_cfg.alert_threshold
                          << " block=" << new_cfg.block_threshold
                          << " escalate=" << new_cfg.escalate_threshold << std::endl;
            }
        }

        ::close(sock);
        auto elapsed = std::chrono::duration<float>(
            std::chrono::steady_clock::now() - start).count();
        std::cout << "\n\n── Capture stopped: " << pkt_count << " pkts in "
                  << std::fixed << std::setprecision(1) << elapsed << "s"
                  << " (" << (pkt_count / elapsed) << " ev/s)" << std::endl;
    }

    // ── Graceful shutdown ─────────────────────────────────────
    std::cout << "\n── Shutting down..." << std::endl;
    if (cloud) { cloud->stop(); std::cout << "  Cloud uploader stopped" << std::endl; }
    pipeline.save_all(cfg.state_dir);
    std::cout << "  State saved to " << cfg.state_dir << std::endl;

    auto& final_metrics = pipeline.metrics();
    auto final_lat     = pipeline.latency_stats();
    std::cout << "\n═══════════════════════════════════════════════" << std::endl;
    std::cout << "  Final Statistics" << std::endl;
    std::cout << "═══════════════════════════════════════════════" << std::endl;
    std::cout << "  Events:    " << final_metrics.events_total.load() << std::endl;
    std::cout << "  Alerts:    " << final_metrics.alerts_total.load() << std::endl;
    std::cout << "  Blocks:    " << final_metrics.blocks_total.load() << std::endl;
    std::cout << "  Online updates: " << final_metrics.online_updates.load() << std::endl;
    std::cout << "  Faults:    " << final_metrics.faults_total.load() << std::endl;
    std::cout << "  Avg lat:   " << final_lat.total_avg_us << " us" << std::endl;
    std::cout << "  P99 lat:   " << final_lat.total_p99_us << " us" << std::endl;
    std::cout << "═══════════════════════════════════════════════" << std::endl;
    return 0;
}
