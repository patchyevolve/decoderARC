// ─────────────────────────────────────────────────────────────
//  ids_collector — real-time packet capture → IDS events
//
//  Two capture backends:
//    default — AF_PACKET socket (no deps, needs CAP_NET_RAW)
//    ebpf    — eBPF/XDP (needs libbpf, kernel ≥5.0)
//
//  Build:
//    clang++ -std=c++17 -O2 -I../include ids_collector.cpp -o ids_collector -lpthread
//    sudo ./ids_collector eth0
// ─────────────────────────────────────────────────────────────
#include "ids.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <ctime>
#include <cerrno>
#include <iomanip>
#include <iostream>
#include <thread>

// ─── AF_PACKET socket headers ────────────────────────────────
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace ids {

// ─── Packet → Event conversion ───────────────────────────────
Event packet_to_event(const uint8_t* pkt, size_t len) {
    Event ev;
    ev.time = std::chrono::steady_clock::now();
    ev.type = EventType::NetworkPacket;

    auto* eth = reinterpret_cast<const struct ether_header*>(pkt);
    if (len < sizeof(struct ether_header)) return ev;

    // Parse source/dest MAC for IP identification
    char src_str[64], dst_str[64];
    auto* ip = reinterpret_cast<const struct iphdr*>(pkt + sizeof(struct ether_header));
    size_t ip_off = sizeof(struct ether_header);

    if (eth->ether_type != htons(ETHERTYPE_IP)) return ev;
    if (ip_off + sizeof(struct iphdr) > len) return ev;

    inet_ntop(AF_INET, &ip->saddr, src_str, sizeof(src_str));
    inet_ntop(AF_INET, &ip->daddr, dst_str, sizeof(dst_str));
    ev.source = src_str;
    ev.destination = dst_str;
    ev.payload.protocol = ip->protocol;

    size_t hdr_len = ip->ihl * 4;
    size_t transport_off = ip_off + hdr_len;

    if (ip->protocol == IPPROTO_TCP && transport_off + sizeof(struct tcphdr) <= len) {
        auto* tcp = reinterpret_cast<const struct tcphdr*>(pkt + transport_off);
        ev.payload.port_src = ntohs(tcp->source);
        ev.payload.port_dst = ntohs(tcp->dest);
        ev.payload.flags = tcp->th_flags;
        ev.payload.bytes_in = len;
        ev.payload.rate_hz = 1.0f;
        // Payload size = total - headers
        size_t tcp_hdr = tcp->th_off * 4;
        ev.payload.bytes_out = static_cast<uint64_t>(len - transport_off - tcp_hdr);
    } else if (ip->protocol == IPPROTO_UDP && transport_off + sizeof(struct udphdr) <= len) {
        auto* udp = reinterpret_cast<const struct udphdr*>(pkt + transport_off);
        ev.payload.port_src = ntohs(udp->source);
        ev.payload.port_dst = ntohs(udp->dest);
        ev.payload.bytes_in = len;
        ev.payload.rate_hz = 1.0f;
        ev.payload.bytes_out = static_cast<uint64_t>(len - transport_off - sizeof(struct udphdr));
    }

    return ev;
}

// ─── Capture loop (AF_PACKET) ────────────────────────────────
void capture_loop(IDS& pipeline, const char* iface, bool verbose = false) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        std::cerr << "socket(AF_PACKET): " << strerror(errno) << std::endl;
        std::cerr << "  Try: sudo ./ids_collector " << iface << std::endl;
        return;
    }

    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        std::cerr << "ioctl(SIOCGIFINDEX): " << strerror(errno) << std::endl;
        close(sock);
        return;
    }

    struct sockaddr_ll sll{};
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        std::cerr << "bind: " << strerror(errno) << std::endl;
        close(sock);
        return;
    }

    std::cout << "Capturing on " << iface << " (AF_PACKET raw socket)" << std::endl;
    std::cout << "Press Ctrl+C to stop." << std::endl;

    uint64_t pkt_count = 0, alert_count = 0;
    auto start = std::chrono::steady_clock::now();

    uint8_t buf[65536];
    while (true) {
        struct sockaddr_ll src_addr{};
        socklen_t addr_len = sizeof(src_addr);
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                             (struct sockaddr*)&src_addr, &addr_len);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }

        auto ev = packet_to_event(buf, static_cast<size_t>(n));
        if (ev.source.empty()) continue;

        auto state = pipeline.ingest(ev);
        pkt_count++;

        if (verbose && pkt_count % 1000 == 0) {
            auto now = std::chrono::system_clock::now();
            auto tt = std::chrono::system_clock::to_time_t(now);
            std::cout << "\033[1;32m[INFO]\033[0m  "
                      << std::put_time(std::localtime(&tt), "%H:%M:%S")
                      << " " << ev.source << ":" << ev.payload.port_src
                      << " → " << ev.destination << ":" << ev.payload.port_dst
                      << " score=" << std::fixed << std::setprecision(3)
                      << state.local.anomaly_score
                      << " ae=" << state.local.ae_score
                      << std::endl;
        }

        // Print stats every 10000 packets
        if (pkt_count % 10000 == 0) {
            auto elapsed = std::chrono::duration<float>(
                std::chrono::steady_clock::now() - start).count();
            std::cout << "\033[1;33m[STATS]\033[0m "
                      << pkt_count << " pkts, "
                      << alert_count << " alerts, "
                      << std::fixed << std::setprecision(1)
                      << pkt_count / elapsed << " pkt/s"
                      << std::endl;
        }
    }

    close(sock);
}

} // namespace ids

int main(int argc, char** argv) {
    const char* iface = "eth0";
    bool verbose = false;

    if (argc > 1) iface = argv[1];
    if (argc > 2) verbose = (std::strcmp(argv[2], "-v") == 0);

    ids::IDSConfig cfg;
    ids::IDS pipeline(cfg);
    uint64_t global_alert_count = 0;
    pipeline.on_alert([&](const ids::Alert& a) {
        global_alert_count++;
        auto now = std::chrono::system_clock::now();
        auto tt = std::chrono::system_clock::to_time_t(now);
        std::cout << "\033[1;31m[ALERT #" << global_alert_count << "]\033[0m "
                  << std::put_time(std::localtime(&tt), "%H:%M:%S")
                  << " " << a.source << " → " << a.destination
                  << " " << a.explanation << std::endl;
    });

    ids::capture_loop(pipeline, iface, verbose);
    return 0;
}
