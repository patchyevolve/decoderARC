#pragma once
#include "ids.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <fstream>
#include <map>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>
#include <unordered_map>

namespace ids {

// ─── Dataset format auto-detection ────────────────────────────
enum class DatasetFormat { Unknown, FlowCSV, CyberLog };

inline DatasetFormat detect_format(const std::string& header) {
    if (header.find("flow_id,") == 0 && header.find(",label") != std::string::npos)
        return DatasetFormat::FlowCSV;
    if (header.find("timestamp,source_ip,") == 0 ||
        header.find("timestamp,source_ip,dest_ip") == 0)
        return DatasetFormat::CyberLog;
    return DatasetFormat::Unknown;
}

// ─── Label classification ─────────────────────────────────────
inline bool is_benign(const std::string& label) {
    std::string l = label;
    std::transform(l.begin(), l.end(), l.begin(), ::tolower);
    return l.find("benign") != std::string::npos ||
           l.find("normal") != std::string::npos ||
           l == "0" || l == "-" || l.empty();
}

inline std::string normalize_label(const std::string& raw) {
    if (is_benign(raw)) return "Benign";
    std::string l = raw;
    // Collapse underscores and common prefixes
    for (auto& c : l) if (c == '_' || c == '-') c = ' ';
    // Remove common prefixes
    const char* prefixes[] = {"ddos ", "dos ", "web ", "brute ", "ftp "};
    for (auto p : prefixes) {
        if (l.find(p) == 0 || l.find(p + 5) != std::string::npos) {
            // Keep the specific type
        }
    }
    return raw; // Keep original as attack class name
}

// ─── CSV parser (header-aware, handles quoted fields) ─────────
struct CSVRow {
    std::vector<std::string> cols;
};

inline std::vector<std::string> parse_csv_line(const std::string& line) {
    std::vector<std::string> cols;
    std::string cell;
    bool in_quotes = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (c == '"') { in_quotes = !in_quotes; continue; }
        if (c == ',' && !in_quotes) {
            cols.push_back(cell);
            cell.clear();
        } else {
            cell += c;
        }
    }
    cols.push_back(cell);
    return cols;
}

// ─── Column index map ─────────────────────────────────────────
struct ColumnMap {
    int src_ip   = -1, dst_ip    = -1;
    int src_port = -1, dst_port  = -1;
    int protocol = -1, label_col = -1;
    int bytes_rate  = -1, packets_rate = -1;
    int total_bytes = -1, duration     = -1;
    int entropy     = -1;
    // Flow features
    int packets_total   = -1, packets_fwd = -1, packets_bwd = -1;
    int bytes_fwd       = -1, bytes_bwd   = -1;
    int pkt_size_mean   = -1, pkt_size_std = -1;
    int pkt_size_max    = -1, pkt_size_min = -1;
    int iat_mean        = -1, iat_std     = -1;
    int iat_max         = -1, iat_min     = -1;
    int syn_flags       = -1, fin_flags   = -1;
    int ack_flags       = -1, rst_flags   = -1;
    int down_up_rate    = -1;
    int fwd_init_win    = -1, bwd_init_win = -1;
    // CyberLog format
    int action = -1, threat_label = -1, log_type = -1;
    int bytes_transferred = -1;
};

inline std::string trim_str(std::string s) {
    while (!s.empty() && (s.back() == ' ' || s.back() == '\r')) s.pop_back();
    while (!s.empty() && (s.front() == ' ')) s.erase(s.begin());
    return s;
}

inline ColumnMap build_column_map(const std::vector<std::string>& header) {
    ColumnMap m;
    for (int i = 0; i < (int)header.size(); ++i) {
        auto h = trim_str(header[i]);
        if (h == "src_ip")              m.src_ip = i;
        if (h == "source_ip")           m.src_ip = i;
        if (h == "dst_ip")              m.dst_ip = i;
        if (h == "dest_ip")             m.dst_ip = i;
        if (h == "src_port")            m.src_port = i;
        if (h == "dst_port")            m.dst_port = i;
        if (h == "protocol")            m.protocol = i;
    if (h == "label" || h == "Label") m.label_col = i;
    if (h == "threat_label")        m.threat_label = i;
        if (h == "bytes_rate")          m.bytes_rate = i;
        if (h == "packets_rate")        m.packets_rate = i;
        if (h == "total_payload_bytes") m.total_bytes = i;
        if (h == "bytes_transferred")   m.bytes_transferred = i;
        if (h == "duration")            m.duration = i;
        if (h == "action")              m.action = i;
        if (h == "log_type")            m.log_type = i;
        if (h == "packets_count")       m.packets_total = i;
        if (h == "fwd_packets_count")   m.packets_fwd = i;
        if (h == "bwd_packets_count")   m.packets_bwd = i;
        if (h == "fwd_total_payload_bytes") m.bytes_fwd = i;
        if (h == "bwd_total_payload_bytes") m.bytes_bwd = i;
        if (h == "payload_bytes_mean")  m.pkt_size_mean = i;
        if (h == "payload_bytes_std")   m.pkt_size_std = i;
        if (h == "payload_bytes_max")   m.pkt_size_max = i;
        if (h == "payload_bytes_min")   m.pkt_size_min = i;
        if (h == "packets_IAT_mean")    m.iat_mean = i;
        if (h == "packet_IAT_std")      m.iat_std = i;
        if (h == "packet_IAT_max")      m.iat_max = i;
        if (h == "packet_IAT_min")      m.iat_min = i;
        if (h == "syn_flag_counts")     m.syn_flags = i;
        if (h == "fin_flag_counts")     m.fin_flags = i;
        if (h == "ack_flag_counts")     m.ack_flags = i;
        if (h == "rst_flag_counts")     m.rst_flags = i;
        if (h == "down_up_rate")        m.down_up_rate = i;
        if (h == "fwd_init_win_bytes")  m.fwd_init_win = i;
        if (h == "bwd_init_win_bytes")  m.bwd_init_win = i;
    }
    return m;
}

// ─── Convert CSV row to Event ─────────────────────────────────
inline Event csv_to_event(const std::vector<std::string>& cols,
                           const ColumnMap& m) {
    Event ev;
    auto safe_float = [&](int idx, float def = 0.f) -> float {
        if (idx < 0 || idx >= (int)cols.size()) return def;
        try { return std::stof(cols[idx]); }
        catch (...) { return def; }
    };
    auto safe_int = [&](int idx, int def = 0) -> int {
        if (idx < 0 || idx >= (int)cols.size()) return def;
        try { return std::stoi(cols[idx]); }
        catch (...) { return def; }
    };
    auto safe_str = [&](int idx, const std::string& def = "") -> std::string {
        if (idx < 0 || idx >= (int)cols.size()) return def;
        return cols[idx];
    };

    ev.source      = safe_str(m.src_ip, "unknown");
    ev.destination = safe_str(m.dst_ip, "unknown");
    ev.type = EventType::NetworkPacket;

    if (m.src_port >= 0) ev.payload.port_src = static_cast<uint16_t>(safe_int(m.src_port));
    if (m.dst_port >= 0) ev.payload.port_dst = static_cast<uint16_t>(safe_int(m.dst_port));

    std::string proto = safe_str(m.protocol, "UDP");
    ev.payload.protocol = (proto.find("TCP") != std::string::npos) ? 6 :
                          (proto.find("UDP") != std::string::npos) ? 17 : 0;

    if (m.bytes_rate >= 0) {
        ev.payload.rate_hz = safe_float(m.bytes_rate);
    } else if (m.bytes_transferred >= 0) {
        float dur = std::max(safe_float(m.duration, 1.f), 0.001f);
        ev.payload.rate_hz = safe_float(m.bytes_transferred) / dur;
    } else if (m.total_bytes >= 0) {
        float dur = std::max(safe_float(m.duration, 1.f), 0.001f);
        ev.payload.rate_hz = safe_float(m.total_bytes) / dur;
    }

    if (m.packets_rate >= 0)
        ev.payload.bytes_in = static_cast<uint64_t>(safe_float(m.packets_rate));

    // ── FlowStats extraction ───────────────────────────────────
    if (m.packets_total >= 0) ev.flow.packets_total = static_cast<uint64_t>(safe_float(m.packets_total));
    if (m.packets_fwd >= 0)   ev.flow.packets_fwd   = static_cast<uint64_t>(safe_float(m.packets_fwd));
    if (m.packets_bwd >= 0)   ev.flow.packets_bwd   = static_cast<uint64_t>(safe_float(m.packets_bwd));
    if (m.bytes_fwd >= 0)     ev.flow.bytes_fwd     = static_cast<uint64_t>(safe_float(m.bytes_fwd));
    if (m.bytes_bwd >= 0)     ev.flow.bytes_bwd     = static_cast<uint64_t>(safe_float(m.bytes_bwd));
    if (m.pkt_size_mean >= 0) ev.flow.packet_size_mean = safe_float(m.pkt_size_mean);
    if (m.pkt_size_std >= 0)  ev.flow.packet_size_std  = safe_float(m.pkt_size_std);
    if (m.pkt_size_max >= 0)  ev.flow.packet_size_max  = safe_float(m.pkt_size_max);
    if (m.pkt_size_min >= 0)  ev.flow.packet_size_min  = safe_float(m.pkt_size_min);
    if (m.iat_mean >= 0)      ev.flow.iat_mean = safe_float(m.iat_mean);
    if (m.iat_std >= 0)       ev.flow.iat_std  = safe_float(m.iat_std);
    if (m.iat_max >= 0)       ev.flow.iat_max  = safe_float(m.iat_max);
    if (m.iat_min >= 0)       ev.flow.iat_min  = safe_float(m.iat_min);
    if (m.syn_flags >= 0)     ev.flow.syn_count = static_cast<uint32_t>(safe_float(m.syn_flags));
    if (m.fin_flags >= 0)     ev.flow.fin_count = static_cast<uint32_t>(safe_float(m.fin_flags));
    if (m.ack_flags >= 0)     ev.flow.ack_count = static_cast<uint32_t>(safe_float(m.ack_flags));
    if (m.rst_flags >= 0)     ev.flow.rst_count = static_cast<uint32_t>(safe_float(m.rst_flags));
    if (m.down_up_rate >= 0)  ev.flow.down_up_ratio = safe_float(m.down_up_rate);
    if (m.fwd_init_win >= 0)  ev.flow.fwd_init_win = static_cast<uint32_t>(safe_float(m.fwd_init_win));
    if (m.bwd_init_win >= 0)  ev.flow.bwd_init_win = static_cast<uint32_t>(safe_float(m.bwd_init_win));
    if (m.duration >= 0)      ev.flow.duration = safe_float(m.duration);

    // Estimate entropy from payload statistics
    float payload_mean = 0.f, payload_std = 0.f;
    if (m.pkt_size_mean >= 0) payload_mean = safe_float(m.pkt_size_mean);
    if (m.pkt_size_std >= 0)  payload_std  = safe_float(m.pkt_size_std);
    ev.payload.entropy = (payload_mean > 0.f)
        ? std::clamp(0.3f + payload_std / (payload_mean + 1.f) * 0.5f, 0.f, 1.f)
        : 0.3f;

    // Store raw features in metadata for analysis
    ev.metadata["bytes_rate"] = std::to_string(ev.payload.rate_hz);

    return ev;
}

// ─── Per-class score tracking ──────────────────────────────────
struct ClassScoreDist {
    std::vector<float> scores;
    void record(float s) { scores.push_back(s); }
    float percentile(float p) const {
        if (scores.empty()) return 0.f;
        auto c = scores;
        std::sort(c.begin(), c.end());
        size_t idx = std::min(static_cast<size_t>(c.size() * p), c.size() - 1);
        return c[idx];
    }
    float max_f1_threshold(const std::vector<float>& benign_scores, float benign_alert_thr) const {
        if (scores.empty() || benign_scores.empty()) return benign_alert_thr;
        // Sweep thresholds to maximize F1
        auto s = scores;
        std::sort(s.begin(), s.end());
        float best_f1 = 0.f, best_t = benign_alert_thr;
        int tp_at_best = 0, fp_at_best = 0;
        for (size_t i = 1; i + 1 < s.size(); i += std::max<size_t>(1, s.size() / 20)) {
            float t = s[i];
            int tp = 0, fn = 0, fp = 0;
            for (float x : scores) { if (x >= t) tp++; else fn++; }
            for (float x : benign_scores) { if (x >= t) fp++; }
            float prec = (tp + fp) > 0 ? 100.f * tp / (tp + fp) : 0.f;
            float rec  = (tp + fn) > 0 ? 100.f * tp / (tp + fn) : 0.f;
            float f1   = (prec + rec) > 0 ? 2.f * prec * rec / (prec + rec) : 0.f;
            if (f1 > best_f1) { best_f1 = f1; best_t = t; tp_at_best = tp; fp_at_best = fp; }
        }
        return best_t;
    }
};

// ─── Dataset stats collector (for calibration) ────────────────
struct DatasetStats {
    uint64_t total_events   = 0;
    uint64_t benign_events  = 0;
    uint64_t attack_events  = 0;
    double   score_sum      = 0;
    double   score_sum_sq   = 0;
    float    max_score      = 0;
    float    benign_score_99th = 0;
    float    benign_score_95th = 0;
    std::vector<float> benign_scores;
    std::map<std::string, uint64_t> attack_class_counts;
    std::map<std::string, ClassScoreDist> class_dists;

    void record_score(float score, const std::string& label) {
        total_events++;
        score_sum += score;
        score_sum_sq += score * score;
        if (score > max_score) max_score = score;
        if (is_benign(label)) {
            benign_events++;
            benign_scores.push_back(score);
        } else {
            attack_events++;
            auto nl = normalize_label(label);
            attack_class_counts[nl]++;
            class_dists[nl].record(score);
        }
    }

    void finalize() {
        std::sort(benign_scores.begin(), benign_scores.end());
        if (!benign_scores.empty()) {
            size_t p99 = static_cast<size_t>(benign_scores.size() * 0.99f);
            size_t p95 = static_cast<size_t>(benign_scores.size() * 0.95f);
            benign_score_99th = benign_scores[std::min(p99, benign_scores.size()-1)];
            benign_score_95th = benign_scores[std::min(p95, benign_scores.size()-1)];
        }
    }

    ThresholdSuggestion suggest_thresholds(float fp_target = 0.01f) const {
        ThresholdSuggestion s{};
        if (benign_scores.empty()) return s;
        float pct = static_cast<float>(benign_scores.size()) * (1.f - fp_target);
        size_t idx = std::min(static_cast<size_t>(pct), benign_scores.size()-1);
        float base = benign_scores[idx];
        s.gate_threshold   = std::clamp(base * 1.2f, 0.15f, 0.50f);
        s.alert_threshold  = std::clamp(base * 1.5f, 0.30f, 0.70f);
        s.block_threshold  = std::clamp(base * 2.0f, 0.50f, 0.92f);
        s.flush_anomaly    = s.alert_threshold;
        s.promote_threshold = s.gate_threshold;
        return s;
    }

    // Per-class optimal thresholds
    std::map<std::string, float> suggest_class_thresholds(float base_alert = 0.25f) const {
        std::map<std::string, float> out;
        for (const auto& [cls, dist] : class_dists) {
            if (dist.scores.size() < 5) continue; // too few samples
            float best_t = dist.max_f1_threshold(benign_scores, base_alert);
            out[cls] = best_t;
        }
        return out;
    }
};

// ─── High-speed CSV ingester ──────────────────────────────────
class DatasetIngester {
public:
    DatasetIngester(IDS& pipeline, size_t batch_size = 1024)
        : pipeline_(pipeline), batch_size_(batch_size) {}

    void set_thresholds(const DecisionThresholds& t) { thresholds_ = t; }

    // Ingest a CSV file, returning per-row decisions and stats
    struct IngestResult {
        uint64_t rows_parsed      = 0;
        uint64_t rows_ingested    = 0;
        uint64_t tp               = 0;
        uint64_t tn               = 0;
        uint64_t fp               = 0;
        uint64_t fn               = 0;
        uint64_t alerts           = 0;
        uint64_t blocks           = 0;
        uint64_t escalations      = 0;
        DatasetStats stats;
        std::vector<std::pair<std::string, Decision>> decisions;
    };

    IngestResult ingest_file(const std::string& path,
                             bool track_decisions = false,
                             size_t max_rows = 0) {
        IngestResult result;
        std::ifstream file(path);
        if (!file.is_open()) {
            std::cerr << "Cannot open: " << path << std::endl;
            return result;
        }

        // Read header (trim \r for Windows line endings)
        std::string header_line;
        if (!std::getline(file, header_line)) return result;
        while (!header_line.empty() && (header_line.back() == '\r' || header_line.back() == '\n'))
            header_line.pop_back();
        auto header = parse_csv_line(header_line);
        auto cmap   = build_column_map(header);
        auto fmt    = detect_format(header_line);

        if (fmt == DatasetFormat::Unknown) {
            std::cerr << "Unknown format: " << path << std::endl;
            return result;
        }

        // Debug: show label column index
        if (result.rows_parsed == 0 && cmap.label_col >= 0) {
            // First pass only
        }

        std::string line;
        std::vector<Event> batch;
        batch.reserve(batch_size_);

        while (std::getline(file, line)) {
            if (max_rows > 0 && result.rows_parsed >= max_rows) break;
            if (line.empty()) continue;
            // Trim \r
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                line.pop_back();

            result.rows_parsed++;
            auto cols = parse_csv_line(line);
            if (cols.size() < 5) continue;

            // Get label
            std::string label;
            if (fmt == DatasetFormat::FlowCSV && cmap.label_col >= 0 &&
                cmap.label_col < (int)cols.size()) {
                label = cols[cmap.label_col];
            } else if (fmt == DatasetFormat::CyberLog) {
                if (cmap.threat_label >= 0 && cmap.threat_label < (int)cols.size())
                    label = cols[cmap.threat_label];
                else if (cmap.action >= 0 && cmap.action < (int)cols.size())
                    label = cols[cmap.action];
            }

    Event ev = csv_to_event(cols, cmap);
    ev.metadata["_label"] = label;
    batch.push_back(std::move(ev));

    if (batch.size() >= batch_size_) {
        flush_batch(batch, result, track_decisions);
        batch.clear();
    }
        }

        // Flush remaining
        if (!batch.empty())
            flush_batch(batch, result, track_decisions);

        result.stats.finalize();
        return result;
    }

    // Calibration run: ingest benign data to establish thresholds
    ThresholdSuggestion calibrate_from_benign(const std::vector<std::string>& paths,
                                               float fp_target = 0.01f) {
        DatasetStats stats;
        for (const auto& path : paths) {
            auto res = ingest_file(path, false);
            stats.total_events   += res.stats.total_events;
            stats.benign_events  += res.stats.benign_events;
            stats.attack_events  += res.stats.attack_events;
            stats.benign_scores.insert(stats.benign_scores.end(),
                res.stats.benign_scores.begin(), res.stats.benign_scores.end());
            for (const auto& [k,v] : res.stats.attack_class_counts)
                stats.attack_class_counts[k] += v;
        }
        stats.finalize();
        return stats.suggest_thresholds(fp_target);
    }

private:
    void flush_batch(std::vector<Event>& batch, IngestResult& result,
                     bool track) {
        for (auto& ev : batch) {
            std::string label;
            auto it = ev.metadata.find("_label");
            if (it != ev.metadata.end()) label = it->second;

            // Ingest and get per-event anomaly score
            auto state = pipeline_.ingest(ev);
            float score = state.local.anomaly_score;

            result.stats.record_score(score, label);
            result.rows_ingested++;

            // Use ingester's thresholds (set via set_thresholds)
            Decision d = score_to_decision(score, thresholds_);

            bool detected = (d == Decision::Alert || d == Decision::Block ||
                             d == Decision::Escalate);
            bool is_attack = !is_benign(label);

            if (is_attack && detected) { result.tp++; result.alerts++; }
            else if (!is_attack && !detected) result.tn++;
            else if (!is_attack && detected) { result.fp++; result.alerts++; }
            else if (is_attack && !detected) result.fn++;

            if (d == Decision::Block) result.blocks++;
            if (d == Decision::Escalate) result.escalations++;

            if (track) {
                result.decisions.push_back({label, d});
            }
        }
    }

    IDS&              pipeline_;
    size_t            batch_size_;
    DecisionThresholds thresholds_{0.05f, 0.10f, 0.25f, 0.70f, 0.90f};
};

// ─── Evaluation report ────────────────────────────────────────
inline void print_evaluation_report(const DatasetIngester::IngestResult& r,
                                     const std::string& name) {
    uint64_t total = r.tp + r.tn + r.fp + r.fn;
    float accuracy  = total > 0 ? 100.f * (r.tp + r.tn) / float(total) : 0.f;
    float prec_val = (r.tp + r.fp) > 0 ? 100.f * r.tp / float(r.tp + r.fp) : 0.f;
    float recall    = (r.tp + r.fn) > 0 ? 100.f * r.tp / float(r.tp + r.fn) : 0.f;
    float f1 = (prec_val + recall) > 0.f ? 2.f * prec_val * recall / (prec_val + recall) : 0.f;

    std::cout << "\n=== Evaluation: " << name << " ===" << std::endl;
    std::cout << "  Rows: " << r.rows_parsed << " parsed, "
              << r.rows_ingested << " ingested" << std::endl;
    std::cout << "  Benign: " << r.stats.benign_events
              << "  Attack: " << r.stats.attack_events << std::endl;
    std::cout << "  TP:" << r.tp << " TN:" << r.tn
              << " FP:" << r.fp << " FN:" << r.fn << std::endl;
    std::cout << "  Accuracy: " << std::fixed << std::setprecision(1)
              << accuracy << "%  Precision: " << prec_val
              << "%  Recall: " << recall << "%  F1: " << f1 << "%" << std::endl;
    std::cout << "  Decisions — Alerts:" << r.alerts
              << " Blocks:" << r.blocks
              << " Escalations:" << r.escalations << std::endl;
    std::cout << "  Benign 95th:% score:" << r.stats.benign_score_95th
              << "  99th:% " << r.stats.benign_score_99th << std::endl;

    if (!r.stats.attack_class_counts.empty()) {
        std::cout << "  Attack classes:" << std::endl;
        for (const auto& [cls, cnt] : r.stats.attack_class_counts)
            std::cout << "    " << cls << ": " << cnt << std::endl;
    }
}

} // namespace ids
