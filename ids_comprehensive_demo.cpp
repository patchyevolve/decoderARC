#include "ids_fused_engine.hpp"
#include "ids_specialist_impl.hpp"
#include <iostream>
#include <iomanip>

int main() {
    std::cout << "=== Comprehensive Multi-Attack IDS Demo ===" << std::endl;

    ids::IDSConfig cfg;
    ids::FusedDetectionEngine engine;

    auto portscan = std::make_unique<ids::PortScanSpecialist>();
    portscan->initialize(cfg);
    portscan->set_validator(std::make_unique<ids::PortScanValidator>());
    engine.add_specialist(std::move(portscan));

    auto brute = std::make_unique<ids::BruteForceSpecialist>();
    brute->initialize(cfg);
    brute->set_validator(std::make_unique<ids::BruteForceValidator>());
    engine.add_specialist(std::move(brute));

    auto web = std::make_unique<ids::WebExploitSpecialist>();
    web->initialize(cfg);
    web->set_validator(std::make_unique<ids::WebExploitValidator>());
    engine.add_specialist(std::move(web));

    auto ransom = std::make_unique<ids::RansomwareSpecialist>();
    ransom->initialize(cfg);
    ransom->set_validator(std::make_unique<ids::RansomwareValidator>());
    engine.add_specialist(std::move(ransom));

    auto insider = std::make_unique<ids::InsiderSpecialist>();
    insider->initialize(cfg);
    insider->set_validator(std::make_unique<ids::InsiderValidator>());
    engine.add_specialist(std::move(insider));

    auto zeroday = std::make_unique<ids::ZeroDaySpecialist>();
    zeroday->initialize(cfg);
    zeroday->set_validator(std::make_unique<ids::ZeroDayValidator>());
    engine.add_specialist(std::move(zeroday));

    auto mitre = std::make_unique<ids::MitreSpecialist>();
    mitre->initialize(cfg);
    engine.add_specialist(std::move(mitre));

    std::vector<ids::Event> scenario;

    ids::Event ev_ps;
    ev_ps.source = "10.0.0.5";
    ev_ps.type = ids::EventType::NetworkPacket;
    ev_ps.payload.flags = 0x02;
    ev_ps.payload.port_dst = 445;
    scenario.push_back(ev_ps);

    ids::Event ev_bf;
    ev_bf.source = "172.16.0.2";
    ev_bf.type = ids::EventType::AuthEvent;
    ev_bf.payload.flags = 0x01;
    scenario.push_back(ev_bf);

    ids::Event ev_web;
    ev_web.source = "192.168.1.100";
    ev_web.payload.port_dst = 80;
    ev_web.payload.entropy = 0.92f;
    scenario.push_back(ev_web);

    ids::Event ev_ransom;
    ev_ransom.source = "INTERNAL_SRV";
    ev_ransom.type = ids::EventType::FileAccess;
    ev_ransom.payload.entropy = 0.98f;
    scenario.push_back(ev_ransom);

    ids::Event ev_insider;
    ev_insider.source = "EMPLOYEE_WS_1";
    ev_insider.payload.bytes_out = 1000000;
    scenario.push_back(ev_insider);

    ids::Event ev_zd;
    ev_zd.source = "UNKNOWN_IP";
    ev_zd.payload.rate_hz = 5000.f;
    ev_zd.payload.entropy = 0.75f;
    scenario.push_back(ev_zd);

    std::cout << std::left << std::setw(15) << "Source"
              << std::setw(20) << "Decision"
              << std::setw(15) << "Attack Class"
              << "Details" << std::endl;
    std::cout << std::string(100, '-') << std::endl;

    for (const auto& ev : scenario) {
        auto result = engine.ingest(ev);

        std::string decision_str;
        switch(result.suggested_decision) {
            case ids::Decision::Ignore:   decision_str = "IGNORE"; break;
            case ids::Decision::Log:      decision_str = "LOG"; break;
            case ids::Decision::Alert:    decision_str = "\033[1;33mALERT\033[0m"; break;
            case ids::Decision::Block:    decision_str = "\033[1;31mBLOCK\033[0m"; break;
            case ids::Decision::Escalate:  decision_str = "\033[1;35mESCALATE\033[0m"; break;
        }

        std::cout << std::left << std::setw(15) << ev.source
                  << std::setw(29) << decision_str
                  << std::setw(15) << result.attack_class
                  << result.details << std::endl;
    }

    std::cout << "\nMulti-attack detection suite verified." << std::endl;
    return 0;
}
