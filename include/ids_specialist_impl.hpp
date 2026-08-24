#pragma once
#include "ids_specialist.hpp"
#include "ids_sharded.hpp"
#include "ids.hpp"
#include <cmath>

namespace ids {

// --- Port Scan Specialist ---
class PortScanValidator : public SpecialistValidator {
public:
    bool validate(const Event& ev, const SpecialistResult& res) override {
        // Port scans target many ports; check if it's a network packet
        return ev.type == EventType::NetworkPacket && res.confidence > 0.3f;
    }
    std::string validator_name() const override { return "PortScan Connectivity Validator"; }
};

class PortScanSpecialist : public Specialist {
public:
    void initialize(const IDSConfig& cfg) override {
        ids_ = std::make_unique<ShardedIDS>(cfg, 2);
        ids_->start();
    }
    SpecialistResult analyze(const Event& ev) override {
        // Heuristic: rapid port changes for same source
        SpecialistResult res;
        res.attack_class = "PortScan";
        // Logic would normally use ids_ pipeline; here we simulate for the demo
        if (ev.payload.flags & 0x02) { // SYN flag
             res.confidence = 0.6f;
             res.suggested_decision = Decision::Log;
        }
        res.validated = validate_result(ev, res);
        return res;
    }
    std::string attack_class() const override { return "PortScan"; }
private:
    std::unique_ptr<ShardedIDS> ids_;
};

// --- Brute Force Specialist ---
class BruteForceValidator : public SpecialistValidator {
public:
    bool validate(const Event& ev, const SpecialistResult& res) override {
        return ev.type == EventType::AuthEvent || (ev.payload.port_dst == 22 || ev.payload.port_dst == 21);
    }
    std::string validator_name() const override { return "Auth Pattern Validator"; }
};

class BruteForceSpecialist : public Specialist {
public:
    void initialize(const IDSConfig& cfg) override {
        ids_ = std::make_unique<ShardedIDS>(cfg, 2);
        ids_->start();
    }
    SpecialistResult analyze(const Event& ev) override {
        SpecialistResult res;
        res.attack_class = "BruteForce";
        if (ev.type == EventType::AuthEvent && (ev.payload.flags & 0x01)) { // Failed auth
            res.confidence = 0.8f;
            res.suggested_decision = Decision::Alert;
        }
        res.validated = validate_result(ev, res);
        return res;
    }
    std::string attack_class() const override { return "BruteForce"; }
private:
    std::unique_ptr<ShardedIDS> ids_;
};

// --- Web Exploit Specialist (SQLi, XSS) ---
class WebExploitValidator : public SpecialistValidator {
public:
    bool validate(const Event& ev, const SpecialistResult& res) override {
        return ev.payload.port_dst == 80 || ev.payload.port_dst == 443 || ev.payload.port_dst == 8080;
    }
    std::string validator_name() const override { return "Web Protocol Validator"; }
};

class WebExploitSpecialist : public Specialist {
public:
    void initialize(const IDSConfig& cfg) override {
        ids_ = std::make_unique<ShardedIDS>(cfg, 2);
        ids_->start();
    }
    SpecialistResult analyze(const Event& ev) override {
        SpecialistResult res;
        res.attack_class = "WebExploit";
        // High entropy in payload often indicates exploit attempts or encoded payloads
        if (ev.payload.entropy > 0.8f) {
            res.confidence = 0.75f;
            res.suggested_decision = Decision::Block;
            res.details = "High entropy web payload detected";
        }
        res.validated = validate_result(ev, res);
        return res;
    }
    std::string attack_class() const override { return "WebExploit"; }
private:
    std::unique_ptr<ShardedIDS> ids_;
};

// --- Ransomware/Encryption Specialist ---
class RansomwareValidator : public SpecialistValidator {
public:
    bool validate(const Event& ev, const SpecialistResult& res) override {
        return ev.type == EventType::FileAccess || ev.payload.entropy > 0.9f;
    }
    std::string validator_name() const override { return "Entropy Validator"; }
};

class RansomwareSpecialist : public Specialist {
public:
    void initialize(const IDSConfig& cfg) override {
        ids_ = std::make_unique<ShardedIDS>(cfg, 2);
        ids_->start();
    }
    SpecialistResult analyze(const Event& ev) override {
        SpecialistResult res;
        res.attack_class = "Ransomware";
        if (ev.type == EventType::FileAccess && ev.payload.entropy > 0.95f) {
            res.confidence = 0.9f;
            res.suggested_decision = Decision::Block;
            res.details = "Encrypted file write detected";
        }
        res.validated = validate_result(ev, res);
        return res;
    }
    std::string attack_class() const override { return "Ransomware"; }
private:
    std::unique_ptr<ShardedIDS> ids_;
};

// --- Insider Threat Specialist ---
class InsiderValidator : public SpecialistValidator {
public:
    bool validate(const Event& ev, const SpecialistResult& res) override {
        return !ev.source.empty(); // Every internal user is a potential insider
    }
    std::string validator_name() const override { return "Identity Validator"; }
};

class InsiderSpecialist : public Specialist {
public:
    void initialize(const IDSConfig& cfg) override {
        ids_ = std::make_unique<ShardedIDS>(cfg, 1);
        ids_->start();
    }
    SpecialistResult analyze(const Event& ev) override {
        SpecialistResult res;
        res.attack_class = "Insider";
        // Insider threats often involve unusual data volume egress
        if (ev.payload.bytes_out > 50000) {
            res.confidence = 0.65f;
            res.suggested_decision = Decision::Escalate;
            res.details = "Large data egress by internal source";
        }
        res.validated = validate_result(ev, res);
        return res;
    }
    std::string attack_class() const override { return "Insider"; }
private:
    std::unique_ptr<ShardedIDS> ids_;
};

// --- Zero-Day / Mix-Day Specialist ---
class ZeroDayValidator : public SpecialistValidator {
public:
    bool validate(const Event& ev, const SpecialistResult& res) override {
        // Zero-day is validated if anomaly is high but doesn't match known classes
        return res.confidence > 0.5f;
    }
    std::string validator_name() const override { return "Novelty Validator"; }
};

class ZeroDaySpecialist : public Specialist {
public:
    void initialize(const IDSConfig& cfg) override {
        ids_ = std::make_unique<ShardedIDS>(cfg, 4);
        ids_->start();
    }
    SpecialistResult analyze(const Event& ev) override {
        auto state = ids_->ingest(ev);
        SpecialistResult res;
        res.attack_class = "ZeroDay";
        // Use the core SSM's drift and anomaly signals for novelty detection
        // Note: In a real implementation, this would look at the GlobalState/Drift
        if (ev.payload.entropy > 0.7f && ev.payload.rate_hz > 1000.f) {
            res.confidence = 0.7f;
            res.suggested_decision = Decision::Alert;
            res.details = "Unknown behavioral drift detected";
        }
        res.validated = validate_result(ev, res);
        return res;
    }
    std::string attack_class() const override { return "ZeroDay"; }
private:
    std::unique_ptr<ShardedIDS> ids_;
};

// --- MITRE Framework Specialist ---
class MitreSpecialist : public ComplexThreatSpecialist {
public:
    void initialize(const IDSConfig& cfg) override {
        ids_ = std::make_unique<ShardedIDS>(cfg, 2);
        ids_->start();
    }
    SpecialistResult analyze(const Event& ev) override {
        SpecialistResult res;
        res.attack_class = "MITRE-T1059"; // Command and Scripting Interpreter
        if (ev.type == EventType::SysLog && ev.payload.entropy > 0.85f) {
            res.confidence = 0.8f;
            res.suggested_decision = Decision::Escalate;
            res.details = "Matched Technique T1059 (Execution)";
        }
        res.validated = validate_result(ev, res);
        return res;
    }
    std::string attack_class() const override { return "MITRE"; }
    std::vector<std::string> mitre_techniques() const override {
        return {"T1059", "T1071", "T1021"};
    }
private:
    std::unique_ptr<ShardedIDS> ids_;
};

} // namespace ids
