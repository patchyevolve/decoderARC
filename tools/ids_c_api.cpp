#include "ids_c_api.h"
#include "ids_sharded.hpp"
#include "ids_types.hpp"

#include <cstdlib>
#include <cstring>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

// ─── Per-handle state ─────────────────────────────────────────
struct CentralState {
    std::mutex mu;
    std::unordered_map<std::string, ids::ShardedIDS*> per_user;

    // Alert collector — populated by on_alert callback, drained after ingest
    std::queue<ids::Alert> pending_alerts;

    // Default config for per-user sharded pipelines
    ids::IDSConfig base_cfg;
};

// ─── Helpers ──────────────────────────────────────────────────
static std::string protocol_name(int proto) {
    switch (proto) {
        case 6:  return "TCP";
        case 17: return "UDP";
        case 1:  return "ICMP";
        case 58: return "ICMPv6";
        default: return std::to_string(proto);
    }
}

static std::string escape_json(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;
        }
    }
    return out;
}

static std::string alert_to_json(const ids::Alert& a) {
    std::ostringstream os;
    os << "{"
       << "\"decision\":\"" << escape_json(a.decision == ids::Decision::Alert ? "alert" : "block") << "\","
       << "\"severity\":\"" << (a.confidence > 0.9f ? "critical" : a.confidence > 0.7f ? "high" : "medium") << "\","
       << "\"confidence\":" << a.confidence << ","
       << "\"source_ip\":\"" << escape_json(a.source) << "\","
       << "\"dest_ip\":\"" << escape_json(a.destination) << "\","
       << "\"source_port\":" << a.source_port << ","
       << "\"dest_port\":" << a.dest_port << ","
       << "\"protocol\":\"" << escape_json(a.protocol) << "\","
       << "\"attack_class\":\"" << escape_json(a.attack_class) << "\","
       << "\"explanation\":\"" << escape_json(a.explanation) << "\""
       << "}";
    return os.str();
}

// ─── API implementation ───────────────────────────────────────
extern "C" {

void* ids_central_create() {
    auto* state = new CentralState();
    return state;
}

void ids_central_destroy(void* handle) {
    if (!handle) return;
    auto* state = static_cast<CentralState*>(handle);
    for (auto& [uid, shard] : state->per_user) {
        shard->shutdown();
        delete shard;
    }
    delete state;
}

int ids_central_ingest(
    void* handle,
    const char* user_id,
    const char* src_ip, int src_port,
    const char* dst_ip, int dst_port,
    int protocol,
    long bytes,
    const char* event_type,
    double unix_ts,
    char** alert_json_out
) {
    if (!handle || !user_id || !src_ip || !dst_ip) return 0;

    auto* state = static_cast<CentralState*>(handle);
    std::lock_guard<std::mutex> lk(state->mu);

    // Get or create per-user ShardedIDS
    std::string uid(user_id);
    auto it = state->per_user.find(uid);
    if (it == state->per_user.end()) {
        // Config with defaults
        ids::IDSConfig cfg = state->base_cfg;
        cfg.queue.queue_depth = 10000;
        cfg.thresholds.ignore_threshold = 0.10f;
        cfg.thresholds.log_threshold = 0.30f;
        cfg.thresholds.alert_threshold = 0.70f;
        cfg.thresholds.block_threshold = 0.92f;
        cfg.thresholds.escalate_threshold = 0.995f;
        cfg.sharding.hash_key = "source";

        auto* shard = new ids::ShardedIDS(cfg, 4); // 4 shards for parallelism
        // Wire alert callback to collector
        shard->on_alert([state](const ids::Alert& a) {
            std::lock_guard<std::mutex> lk(state->mu);
            state->pending_alerts.push(a);
        });

        // Start workers
        shard->start();
        state->per_user[uid] = shard;
        it = state->per_user.find(uid);
    }

    auto* shard = it->second;

    // Build Event
    ids::Event ev;
    ev.type = ids::EventType::NetworkPacket;
    ev.source = src_ip ? src_ip : "";
    ev.destination = dst_ip ? dst_ip : "";
    ev.payload.bytes_in = static_cast<uint64_t>(bytes > 0 ? bytes : 0);
    ev.payload.port_src = static_cast<uint16_t>(src_port);
    ev.payload.port_dst = static_cast<uint16_t>(dst_port);
    ev.payload.protocol = static_cast<uint8_t>(protocol);
    ev.payload.entropy = 0.3f;
    ev.payload.rate_hz = 1.f;
    ev.time = std::chrono::steady_clock::now();

    // Optional: store event_type in metadata
    if (event_type) {
        ev.metadata["event_type"] = std::string(event_type);
    }

    // Ingest
    shard->ingest(ev);

    // Drain pending alerts
    if (state->pending_alerts.empty())
        return 0;

    ids::Alert alert = state->pending_alerts.front();
    state->pending_alerts.pop();

    // Fill protocol string from our mapping
    alert.protocol = protocol_name(protocol);

    // Also fill ports
    alert.source_port = src_port;
    alert.dest_port = dst_port;
    alert.source = src_ip ? src_ip : "";
    alert.destination = dst_ip ? dst_ip : "";

    std::string json = alert_to_json(alert);
    if (alert_json_out) {
        *alert_json_out = static_cast<char*>(std::malloc(json.size() + 1));
        if (*alert_json_out) {
            std::memcpy(*alert_json_out, json.data(), json.size() + 1);
        }
    }
    return 1;
}

void ids_central_free_string(char* s) {
    std::free(s);
}

void ids_central_free_alerts(char** alerts, int num) {
    if (!alerts) return;
    for (int i = 0; i < num; ++i) {
        if (alerts[i]) std::free(alerts[i]);
    }
    std::free(alerts);
}

int ids_central_ingest_batch(
    void* handle,
    const char* user_id,
    const char** src_ips, const int* src_ports,
    const char** dst_ips, const int* dst_ports,
    const int* protocols,
    const long* bytes,
    const char** event_types,
    const double* unix_ts,
    int batch_size,
    char*** alerts_json_out,
    int* num_alerts_out
) {
    if (!handle || !user_id || batch_size <= 0) {
        if (num_alerts_out) *num_alerts_out = 0;
        if (alerts_json_out) *alerts_json_out = nullptr;
        return 0;
    }

    auto* state = static_cast<CentralState*>(handle);
    std::lock_guard<std::mutex> lk(state->mu);

    // Get or create per-user ShardedIDS (same as single ingest)
    std::string uid(user_id);
    auto it = state->per_user.find(uid);
    if (it == state->per_user.end()) {
        ids::IDSConfig cfg = state->base_cfg;
        cfg.queue.queue_depth = 10000;
        cfg.thresholds.ignore_threshold = 0.10f;
        cfg.thresholds.log_threshold = 0.30f;
        cfg.thresholds.alert_threshold = 0.70f;
        cfg.thresholds.block_threshold = 0.92f;
        cfg.thresholds.escalate_threshold = 0.995f;
        cfg.sharding.hash_key = "source";

        auto* shard = new ids::ShardedIDS(cfg, 4);
        shard->on_alert([state](const ids::Alert& a) {
            std::lock_guard<std::mutex> lk(state->mu);
            state->pending_alerts.push(a);
        });
        shard->start();
        state->per_user[uid] = shard;
        it = state->per_user.find(uid);
    }

    auto* shard = it->second;

    // Ingest all events in batch
    for (int i = 0; i < batch_size; ++i) {
        ids::Event ev;
        ev.type = ids::EventType::NetworkPacket;
        ev.source = src_ips && src_ips[i] ? src_ips[i] : "";
        ev.destination = dst_ips && dst_ips[i] ? dst_ips[i] : "";
        ev.payload.bytes_in = static_cast<uint64_t>(bytes && bytes[i] > 0 ? bytes[i] : 0);
        ev.payload.port_src = src_ports ? static_cast<uint16_t>(src_ports[i]) : 0;
        ev.payload.port_dst = dst_ports ? static_cast<uint16_t>(dst_ports[i]) : 0;
        ev.payload.protocol = protocols ? static_cast<uint8_t>(protocols[i]) : 0;
        ev.payload.entropy = 0.3f;
        ev.payload.rate_hz = 1.f;
        ev.time = std::chrono::steady_clock::now();
        if (event_types && event_types[i]) {
            ev.metadata["event_type"] = std::string(event_types[i]);
        }
        shard->ingest(ev);
    }

    // Drain pending alerts
    if (state->pending_alerts.empty()) {
        if (num_alerts_out) *num_alerts_out = 0;
        if (alerts_json_out) *alerts_json_out = nullptr;
        return 0;
    }

    // Collect all alerts — preserve source/destination from the IDS engine
    // (the alert already contains the correct IPs from the pipeline)
    std::vector<std::string> alert_jsons;
    while (!state->pending_alerts.empty()) {
        ids::Alert alert = state->pending_alerts.front();
        state->pending_alerts.pop();
        // Only fill protocol if the engine left it empty
        if (alert.protocol.empty())
            alert.protocol = protocol_name(protocols ? protocols[0] : 0);
        // Only fill ports if the engine left them at default (0)
        if (alert.source_port == 0)
            alert.source_port = src_ports ? src_ports[0] : 0;
        if (alert.dest_port == 0)
            alert.dest_port = dst_ports ? dst_ports[0] : 0;
        // Only fill IPs if the engine left them empty
        if (alert.source.empty())
            alert.source = src_ips && src_ips[0] ? src_ips[0] : "";
        if (alert.destination.empty())
            alert.destination = dst_ips && dst_ips[0] ? dst_ips[0] : "";
        alert_jsons.push_back(alert_to_json(alert));
    }

    int n = static_cast<int>(alert_jsons.size());
    if (alerts_json_out) {
        *alerts_json_out = static_cast<char**>(std::malloc(n * sizeof(char*)));
        if (*alerts_json_out) {
            for (int i = 0; i < n; ++i) {
                (*alerts_json_out)[i] = static_cast<char*>(std::malloc(alert_jsons[i].size() + 1));
                if ((*alerts_json_out)[i]) {
                    std::memcpy((*alerts_json_out)[i], alert_jsons[i].data(), alert_jsons[i].size() + 1);
                }
            }
        }
    }
    if (num_alerts_out) *num_alerts_out = n;
    return n;
}

} // extern "C"
