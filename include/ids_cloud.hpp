#pragma once
// ─────────────────────────────────────────────────────────────
//  ids_cloud.hpp — Cloud uploader module for CoreIDS daemon
//
//  Connects the IDS pipeline to the cloud backend.
//  Batches alerts, sends metrics, reports heartbeat.
//
//  Usage:
//    ids::CloudUploader uploader("https://api.coreids.dev",
//                                "<device-id>", "<api-key>");
//    uploader.start();         // launches background thread
//    ...
//    uploader.push_alert(...); // thread-safe, batched
//    ...
//    uploader.stop();          // flush + join
//
//  Requires: libcurl (apt: libcurl4-openssl-dev)
//  Link: -lcurl
// ─────────────────────────────────────────────────────────────

#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <curl/curl.h>

namespace ids {

struct CloudAlert {
    std::string time;
    std::string decision;
    std::string severity;
    float       confidence;
    std::string source_ip;
    std::string dest_ip;
    int         source_port;
    int         dest_port;
    std::string protocol;
    std::string attack_class;
    float       anomaly_score;
    float       ae_score;
    std::string explanation;
};

struct CloudMetrics {
    std::string time;
    float       events_per_sec;
    float       alerts_per_sec;
    float       blocks_per_sec;
    float       avg_latency_us;
    float       p99_latency_us;
    float       drift_score;
    float       memory_usage_pct;
    float       cpu_usage_pct;
    int         online_updates;
};

struct CloudLog {
    std::string time;
    std::string type;
    std::string protocol;
    std::string src_ip;
    int         src_port;
    std::string dst_ip;
    int         dst_port;
    std::string severity;
    std::string message;
};

struct CloudEvent {
    std::string time;
    std::string src_ip;
    int         src_port;
    std::string dst_ip;
    int         dst_port;
    std::string protocol;
    int         bytes;
    std::string event_type;
};

// ─── Global curl init/cleanup via reference counting ─────────
// curl_global_init/cleanup must be called exactly once per program.
class CurlGlobalInit {
public:
    CurlGlobalInit() {
        std::call_once(flag_, [] { curl_global_init(CURL_GLOBAL_ALL); });
    }
    ~CurlGlobalInit() {
        // No cleanup — let the OS handle it at exit to avoid ordering issues
    }
private:
    inline static std::once_flag flag_;
};

// ─── Callback for libcurl write ─────────────────────────────
inline size_t cloud_write_cb(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    auto* s = static_cast<std::string*>(userp);
    s->append(static_cast<char*>(contents), total);
    return total;
}

class CloudUploader {
public:
    CloudUploader(std::string base_url, std::string device_id, std::string api_key,
                  int batch_interval_s = 5, int heartbeat_interval_s = 30,
                  bool verify_ssl = true)
        : base_url_(std::move(base_url))
        , device_id_(std::move(device_id))
        , api_key_(std::move(api_key))
        , batch_interval_s_(batch_interval_s)
        , heartbeat_interval_s_(heartbeat_interval_s)
        , verify_ssl_(verify_ssl)
    {
        static CurlGlobalInit curl_init;
    }

    ~CloudUploader() { stop(); }

    // ── Lifecycle ──────────────────────────────────────────
    void start() {
        if (running_) return;
        running_ = true;
        thread_ = std::thread([this] { run(); });
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lk(stop_mu_);
            if (!running_) return;
            running_ = false;
        }
        cv_.notify_one();
        if (thread_.joinable()) thread_.join();
        flush(); // send remaining alerts
        flush_logs(); // send remaining logs
        flush_events(); // send remaining traffic events
    }

    // ── Thread-safe alert push ────────────────────────────
    void push_alert(CloudAlert a) {
        std::lock_guard<std::mutex> lk(mu_);
        alert_queue_.push_back(std::move(a));
    }

    void push_log(CloudLog l) {
        std::lock_guard<std::mutex> lk(mu_);
        log_queue_.push_back(std::move(l));
    }

    void push_event(CloudEvent e) {
        std::lock_guard<std::mutex> lk(mu_);
        event_queue_.push_back(std::move(e));
    }

    void push_metrics(CloudMetrics m) {
        std::lock_guard<std::mutex> lk(mu_);
        last_metrics_ = std::move(m);
    }

    // ── Config ────────────────────────────────────────────
    void set_metrics_fn(std::function<CloudMetrics()> fn) {
        std::lock_guard<std::mutex> lk(mu_);
        metrics_fn_ = std::move(fn);
    }

private:
    void run() {
        auto last_heartbeat = std::chrono::steady_clock::now();
        auto last_metrics   = std::chrono::steady_clock::now();

        while (running_) {
            // Wait for batch interval or shutdown signal
            {
                std::unique_lock<std::mutex> lk(mu_);
                cv_.wait_for(lk, std::chrono::seconds(batch_interval_s_),
                             [this] { return !running_; });
            }
            if (!running_) break;

            flush();
            flush_logs();
            flush_events();

            // Heartbeat
            auto now = std::chrono::steady_clock::now();
            if (now - last_heartbeat > std::chrono::seconds(heartbeat_interval_s_)) {
                send_heartbeat();
                last_heartbeat = now;
            }

            // Metrics
            if (now - last_metrics > std::chrono::seconds(60)) {
                send_metrics();
                last_metrics = now;
            }
        }
    }

    void flush() {
        std::vector<CloudAlert> batch;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (alert_queue_.empty()) return;
            batch.assign(alert_queue_.begin(), alert_queue_.end());
            alert_queue_.clear();
        }
        if (!batch.empty())
            post_alerts(batch);
    }

    void flush_logs() {
        std::vector<CloudLog> batch;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (log_queue_.empty()) return;
            batch.assign(log_queue_.begin(), log_queue_.end());
            log_queue_.clear();
        }
        if (!batch.empty())
            post_logs(batch);
    }

    void flush_events() {
        std::vector<CloudEvent> batch;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (event_queue_.empty()) return;
            batch.assign(event_queue_.begin(), event_queue_.end());
            event_queue_.clear();
        }
        if (!batch.empty())
            post_events(batch);
    }

    // ── HTTP helpers ──────────────────────────────────────
    std::string post(const std::string& path, const std::string& body) {
        CURL* curl = curl_easy_init();
        if (!curl) return "";

        std::string url = base_url_ + path;
        std::string response;

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "Accept: application/json");
        // Send API key as Bearer token — not in request body
        std::string auth_header = "Authorization: Bearer " + api_key_;
        headers = curl_slist_append(headers, auth_header.c_str());

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cloud_write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);

        // SSL verification — enabled by default for production safety
        // Set verify_ssl=false only for testing with self-signed certs
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify_ssl_ ? 1L : 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify_ssl_ ? 2L : 0L);

        CURLcode res = curl_easy_perform(curl);
        long status_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
        if (res != CURLE_OK) {
            fprintf(stderr, "[cloud] POST %s failed: curl error %d (%s)\n",
                    path.c_str(), res, curl_easy_strerror(res));
        } else if (status_code >= 400) {
            fprintf(stderr, "[cloud] POST %s failed: HTTP %ld\n", path.c_str(), status_code);
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return response;
    }

    void post_alerts(const std::vector<CloudAlert>& alerts) {
        std::string body = std::string("{\"device_id\":") + escape_json(device_id_)
                        + ",\"alerts\":[";

        for (size_t i = 0; i < alerts.size(); ++i) {
            const auto& a = alerts[i];
            if (i > 0) body += ",";
            body += std::string("{\"time\":") + escape_json(a.time)
                 + ",\"decision\":" + escape_json(a.decision)
                 + ",\"severity\":" + escape_json(a.severity)
                 + ",\"confidence\":" + json_number(a.confidence)
                 + ",\"source_ip\":" + escape_json(a.source_ip)
                 + ",\"dest_ip\":" + escape_json(a.dest_ip)
                 + ",\"source_port\":" + std::to_string(a.source_port)
                 + ",\"dest_port\":" + std::to_string(a.dest_port)
                 + ",\"protocol\":" + escape_json(a.protocol)
                 + ",\"attack_class\":" + escape_json(a.attack_class)
                 + ",\"anomaly_score\":" + json_number(a.anomaly_score)
                 + ",\"ae_score\":" + json_number(a.ae_score)
                 + ",\"explanation\":" + escape_json(a.explanation)
                 + "}";
        }
        body += "]}";

        post("/api/v1/ingest/alerts", body);
    }

    void post_logs(const std::vector<CloudLog>& logs) {
        std::string body = std::string("{\"device_id\":") + escape_json(device_id_)
                        + ",\"logs\":[";

        for (size_t i = 0; i < logs.size(); ++i) {
            const auto& l = logs[i];
            if (i > 0) body += ",";
            body += std::string("{\"time\":") + escape_json(l.time)
                 + ",\"type\":" + escape_json(l.type)
                 + ",\"protocol\":" + escape_json(l.protocol)
                 + ",\"src_ip\":" + escape_json(l.src_ip)
                 + ",\"src_port\":" + std::to_string(l.src_port)
                 + ",\"dst_ip\":" + escape_json(l.dst_ip)
                 + ",\"dst_port\":" + std::to_string(l.dst_port)
                 + ",\"severity\":" + escape_json(l.severity)
                 + ",\"message\":" + escape_json(l.message)
                 + "}";
        }
        body += "]}";

        post("/api/v1/ingest/logs", body);
    }

    void post_events(const std::vector<CloudEvent>& events) {
        std::string body = std::string("{\"device_id\":") + escape_json(device_id_)
                        + ",\"events\":[";

        for (size_t i = 0; i < events.size(); ++i) {
            const auto& e = events[i];
            if (i > 0) body += ",";
            body += std::string("{\"time\":") + escape_json(e.time)
                 + ",\"src_ip\":" + escape_json(e.src_ip)
                 + ",\"src_port\":" + std::to_string(e.src_port)
                 + ",\"dst_ip\":" + escape_json(e.dst_ip)
                 + ",\"dst_port\":" + std::to_string(e.dst_port)
                 + ",\"protocol\":" + escape_json(e.protocol)
                 + ",\"bytes\":" + std::to_string(e.bytes)
                 + ",\"event_type\":" + escape_json(e.event_type)
                 + ",\"metadata\":{}"
                 + "}";
        }
        body += "]}";

        post("/api/v1/ingest/events", body);
    }

    void send_heartbeat() {
        // Track a simple uptime-based load estimate
        static auto start_time = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - start_time).count();
        float load;
        {
            std::lock_guard<std::mutex> lk(mu_);
            load = std::min(1.0f, static_cast<float>(alert_queue_.size() + log_queue_.size() + event_queue_.size()) / 1000.0f);
        }
        std::string body = R"({"device_id":")" + device_id_
                        + R"(","version":"1.0.0","load":)" + json_number(load) + "}";
        post("/api/v1/device/heartbeat", body);
    }

    void send_metrics() {
        CloudMetrics m{};
        {
            std::lock_guard<std::mutex> lk(mu_);
            m = last_metrics_;
            if (metrics_fn_) m = metrics_fn_();
        }

        // Get current time ISO 8601
        auto now = std::chrono::system_clock::now();
        auto tt  = std::chrono::system_clock::to_time_t(now);
        char timebuf[64];
        std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&tt));

        std::string body = std::string("{\"device_id\":") + escape_json(device_id_)
                        + ",\"time\":" + escape_json(timebuf)
                        + ",\"events_per_sec\":" + json_number(m.events_per_sec)
                        + ",\"alerts_per_sec\":" + json_number(m.alerts_per_sec)
                        + ",\"blocks_per_sec\":" + json_number(m.blocks_per_sec)
                        + ",\"avg_latency_us\":" + json_number(m.avg_latency_us)
                        + ",\"p99_latency_us\":" + json_number(m.p99_latency_us)
                        + ",\"drift_score\":" + json_number(m.drift_score)
                        + ",\"memory_usage_pct\":" + json_number(m.memory_usage_pct)
                        + ",\"cpu_usage_pct\":" + json_number(m.cpu_usage_pct)
                        + ",\"online_updates\":" + std::to_string(m.online_updates)
                        + "}";

        post("/api/v1/ingest/metrics", body);
    }

    static std::string escape_json(const std::string& s) {
        std::string out = "\"";
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
        out += "\"";
        return out;
    }

    static float sanitize_float(float v) {
        if (!std::isfinite(v)) return 0.0f;
        return v;
    }

    static std::string json_number(float v) {
        return std::to_string(sanitize_float(v));
    }

    std::string base_url_;
    std::string device_id_;
    std::string api_key_;
    int batch_interval_s_;
    int heartbeat_interval_s_;
    bool verify_ssl_;

    std::atomic<bool> running_{false};
    std::thread thread_;
    std::mutex mu_;
    std::mutex stop_mu_;
    std::condition_variable cv_;

    std::deque<CloudAlert> alert_queue_;
    std::deque<CloudLog> log_queue_;
    std::deque<CloudEvent> event_queue_;
    CloudMetrics last_metrics_{};
    std::function<CloudMetrics()> metrics_fn_;
};

} // namespace ids
