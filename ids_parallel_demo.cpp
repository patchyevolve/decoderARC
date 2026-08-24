#include "ids_fused_engine.hpp"
#include "ids_specialist_impl.hpp"
#include "ids_specialist_ddos.hpp"
#include <iostream>
#include <iomanip>

int main() {
    std::cout << "=== IDS Fused Parallel Architecture Demo ===" << std::endl;

    ids::IDSConfig cfg;
    ids::FusedDetectionEngine engine;

    auto ddos = std::make_unique<ids::DDoSSpecialist>();
    ddos->initialize(cfg);

    engine.add_specialist(std::move(ddos));

    std::vector<ids::Event> test_events;

    ids::Event e1;
    e1.source = "192.168.1.10";
    e1.destination = "8.8.8.8";
    e1.payload.rate_hz = 10.0f;
    e1.payload.port_dst = 443;
    test_events.push_back(e1);

    ids::Event e2;
    e2.source = "10.0.0.1";
    e2.destination = "192.168.1.1";
    e2.payload.rate_hz = 5000.0f;
    e2.payload.port_dst = 80;
    test_events.push_back(e2);

    std::cout << std::left << std::setw(15) << "Source"
              << std::setw(15) << "Decision"
              << std::setw(10) << "Conf"
              << "Details" << std::endl;
    std::cout << std::string(80, '-') << std::endl;

    for (const auto& ev : test_events) {
        ids::SpecialistResult result = engine.ingest(ev);

        std::string decision_str;
        switch(result.suggested_decision) {
            case ids::Decision::Ignore:  decision_str = "IGNORE"; break;
            case ids::Decision::Log:     decision_str = "LOG"; break;
            case ids::Decision::Alert:   decision_str = "\033[1;33mALERT\033[0m"; break;
            case ids::Decision::Block:   decision_str = "\033[1;31mBLOCK\033[0m"; break;
            case ids::Decision::Escalate: decision_str = "\033[1;35mESCALATE\033[0m"; break;
        }

        std::cout << std::left << std::setw(15) << ev.source
                  << std::setw(24) << decision_str
                  << std::fixed << std::setprecision(2) << std::setw(10) << result.confidence
                  << result.details << std::endl;
    }

    std::cout << "\nDemo finished." << std::endl;
    return 0;
}
