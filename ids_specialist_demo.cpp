#include "ids_specialist_ddos.hpp"
#include <iostream>
#include <iomanip>
#include <csignal>
#include <atomic>
#include <thread>

std::atomic<bool> keep_running{true};

void signal_handler(int) {
    keep_running = false;
}

int main() {
    std::signal(SIGINT, signal_handler);

    std::cout << "=== IDS Specialist Demo: DDoS Detection ===" << std::endl;
    
    // 1. Setup Configuration
    ids::IDSConfig cfg;
    cfg.telemetry.routing_debug = true;
    
    // 2. Create and Initialize the Specialist
    // Using 4 shards for horizontal scaling
    ids::DDoSSpecialist ddos_specialist;
    ddos_specialist.initialize(cfg);
    
    // 3. Set Alert Callbacks
    ddos_specialist.on_alert([](const ids::Alert& a) {
        std::cout << "\033[1;31m[DDoS ALERT]\033[0m "
                  << "Conf: " << std::fixed << std::setprecision(2) << a.confidence
                  << " | Src: " << a.source
                  << " | Dest: " << a.destination
                  << " | Type: " << a.trace.correlation_type
                  << std::endl;
    });
    
    // 4. Start the Specialist
    std::cout << "Starting specialist with 4 shards..." << std::endl;
    ddos_specialist.start();
    
    // 5. Ingest data from the real dataset
    std::string dataset_path = "real_datasets/ddos_loit.csv";
    std::cout << "Ingesting data from " << dataset_path << "..." << std::endl;
    ddos_specialist.ingest_from_file(dataset_path);
    
    std::cout << "Ingestion complete. Monitoring for alerts (Ctrl+C to stop)..." << std::endl;
    
    // Keep running for a bit to let shards process queues
    int timeout = 10;
    while (keep_running && timeout-- > 0) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    // 6. Shutdown
    std::cout << "Shutting down specialist..." << std::endl;
    ddos_specialist.shutdown();
    
    std::cout << "Demo finished." << std::endl;
    
    return 0;
}
