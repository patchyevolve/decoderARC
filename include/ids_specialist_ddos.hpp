#pragma once
#include "ids_specialist.hpp"
#include "ids_sharded.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>

namespace ids {

class DDoSSpecialist : public Specialist {
public:
    DDoSSpecialist() = default;
    ~DDoSSpecialist() override { shutdown(); }

    void initialize(const IDSConfig& cfg) override {
        IDSConfig ddos_cfg = cfg;
        ddos_cfg.distributed.unique_source_threshold = 3;
        ddos_cfg.distributed.dist_window_s = 30.0f;
        ddos_cfg.thresholds.alert_threshold = 0.50f;
        ddos_cfg.thresholds.block_threshold = 0.75f;
        ids_ = std::make_unique<ShardedIDS>(ddos_cfg, 4);
    }

    void start() {
        if (ids_) ids_->start();
    }

    void shutdown() {
        if (ids_) ids_->shutdown();
    }

    void on_alert(AlertCallback cb) {
        if (ids_) ids_->on_alert(std::move(cb));
    }

    SpecialistResult analyze(const Event& ev) override {
        SpecialistResult res;
        res.attack_class = "DDoS";
        if (ids_) ids_->ingest(ev);
        if (ev.payload.rate_hz > 1000.0f) {
            res.confidence = std::min(0.95f, 0.3f + ev.payload.rate_hz / 10000.0f);
            res.suggested_decision = res.confidence > 0.75f ? Decision::Block : Decision::Alert;
            res.details = "High rate DDoS pattern detected";
        } else if (ev.payload.rate_hz > 100.0f) {
            res.confidence = 0.4f;
            res.suggested_decision = Decision::Log;
            res.details = "Elevated rate, monitoring";
        }
        res.validated = validate_result(ev, res);
        return res;
    }

    std::string attack_class() const override { return "DDoS"; }

    void ingest_from_file(const std::string& path) {
        std::ifstream file(path);
        if (!file.is_open()) {
            std::cerr << "Failed to open dataset: " << path << std::endl;
            return;
        }

        std::string line;
        if (!std::getline(file, line)) return;

        uint32_t count = 0;
        while (std::getline(file, line)) {
            Event ev = parse_csv_line(line);
            if (!ev.source.empty()) {
                ids_->ingest(ev);
                count++;
            }
            if (count > 5000) break;
        }
        std::cout << "Ingested " << count << " events from " << path << std::endl;
    }

private:
    Event parse_csv_line(const std::string& line) {
        std::stringstream ss(line);
        std::string cell;
        std::vector<std::string> columns;

        while (std::getline(ss, cell, ',')) {
            columns.push_back(cell);
        }

        Event ev;
        if (columns.size() > 60) {
            ev.source = columns[2];
            ev.destination = columns[4];
            ev.type = EventType::NetworkPacket;

            try {
                ev.payload.port_src = static_cast<uint16_t>(std::stoi(columns[3]));
                ev.payload.port_dst = static_cast<uint16_t>(std::stoi(columns[5]));
                ev.payload.protocol = (columns[6] == "TCP" ? 6 : (columns[6] == "UDP" ? 17 : 0));
                ev.payload.rate_hz = std::stof(columns[60]);
                ev.payload.bytes_in = 0;
                ev.payload.entropy = 0.5f;
            } catch (...) {
            }
        }
        return ev;
    }

    std::unique_ptr<ShardedIDS> ids_;
};

} // namespace ids
