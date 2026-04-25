#pragma once
// ─────────────────────────────────────────────────────────────
//  ids_capture.hpp — libpcap → IDS::Event bridge
// ─────────────────────────────────────────────────────────────
#include "ids.hpp"
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
// FIX L13: removed unused <net/ethernet.h>
#include <arpa/inet.h>
#include <atomic>
#include <cmath>
#include <functional>
#include <string>
#include <thread>
#include <vector>

namespace ids {

// ── Packet → Event conversion ─────────────────────────────────
inline Event packet_to_event(const struct pcap_pkthdr* hdr,
                              const uint8_t* pkt)
{
    Event ev;
    ev.type = EventType::NetworkPacket;

    if (hdr->caplen < 14) return ev;
    const uint8_t* ip_start = pkt + 14;
    uint32_t remaining = hdr->caplen - 14;

    if (remaining < sizeof(struct ip)) return ev;
    const struct ip* iph = reinterpret_cast<const struct ip*>(ip_start);
    if (iph->ip_v != 4) return ev;

    char src_buf[INET_ADDRSTRLEN], dst_buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->ip_src, src_buf, sizeof(src_buf));
    inet_ntop(AF_INET, &iph->ip_dst, dst_buf, sizeof(dst_buf));
    ev.source      = src_buf;
    ev.destination = dst_buf;

    ev.payload.protocol = iph->ip_p;
    ev.payload.bytes_in = ntohs(iph->ip_len);

    uint32_t ip_hdr_len = iph->ip_hl * 4u;

    // FIX L51: guard against truncated / corrupted header before subtracting
    if (ip_hdr_len < sizeof(struct ip) || ip_hdr_len > remaining)
        return ev;

    const uint8_t* transport = ip_start + ip_hdr_len;
    uint32_t transport_len   = remaining - ip_hdr_len;  // safe: remaining >= ip_hdr_len

    if (iph->ip_p == IPPROTO_TCP && transport_len >= sizeof(struct tcphdr)) {
        const struct tcphdr* th = reinterpret_cast<const struct tcphdr*>(transport);
        ev.payload.port_src = ntohs(th->th_sport);
        ev.payload.port_dst = ntohs(th->th_dport);
        ev.payload.flags    = th->th_flags;
    } else if (iph->ip_p == IPPROTO_UDP && transport_len >= sizeof(struct udphdr)) {
        const struct udphdr* uh = reinterpret_cast<const struct udphdr*>(transport);
        ev.payload.port_src = ntohs(uh->uh_sport);
        ev.payload.port_dst = ntohs(uh->uh_dport);
    }

    // Shannon entropy from up to 256 payload bytes
    if (transport_len > 8) {
        uint32_t counts[256] = {};
        const uint8_t* payload = transport + 8;
        uint32_t plen = std::min(transport_len - 8u, 256u);
        for (uint32_t i = 0; i < plen; ++i) counts[payload[i]]++;
        float ent = 0.f;
        for (int i = 0; i < 256; ++i) {
            if (!counts[i]) continue;
            float p = float(counts[i]) / float(plen);
            ent -= p * std::log2f(p);
        }
        ev.payload.entropy = ent / 8.f;
    }

    // FIX L80: rate_hz = bytes * 100 was 100x too large, saturating L0 normalisation.
    // Use bytes_in directly as a byte-rate proxy (assumes ~1 packet/sec baseline).
    // A rolling per-IP rate tracker gives better results in production.
    ev.payload.rate_hz = static_cast<float>(ev.payload.bytes_in);

    return ev;
}

// ── CaptureStats ──────────────────────────────────────────────
struct CaptureStats {
    std::atomic<uint64_t> packets_captured {0};
    std::atomic<uint64_t> packets_dropped  {0};
    std::atomic<uint64_t> bytes_total      {0};
    std::atomic<bool>     running          {false};
    std::string           interface;
    std::string           filter;
    std::string           last_error;

    // Atomics are non-copyable — provide explicit snapshot for callers
    // that need a value copy (e.g. the visualizer render loop)
    struct Snapshot {
        uint64_t packets_captured;
        uint64_t packets_dropped;
        uint64_t bytes_total;
        bool     running;
    };
    Snapshot snapshot() const {
        return { packets_captured.load(),
                 packets_dropped.load(),
                 bytes_total.load(),
                 running.load() };
    }
};

// ── PacketCapture ─────────────────────────────────────────────
class PacketCapture {
public:
    using IngestFn = std::function<void(const Event&)>;

    explicit PacketCapture(const std::string& iface,
                           const std::string& bpf_filter = "",
                           int snaplen    = 65535,
                           int timeout_ms = 100)
        : iface_(iface), filter_(bpf_filter),
          snaplen_(snaplen), timeout_ms_(timeout_ms)
    {
        stats_.interface = iface;
        stats_.filter    = bpf_filter;
    }

    ~PacketCapture() { stop(); }

    void on_event(IngestFn fn) { ingest_fn_ = std::move(fn); }

    bool start() {
        char errbuf[PCAP_ERRBUF_SIZE];
        handle_ = pcap_open_live(iface_.c_str(), snaplen_,
                                 1 /*promisc*/, timeout_ms_, errbuf);
        if (!handle_) {
            stats_.last_error = errbuf;
            return false;
        }
        if (!filter_.empty()) {
            struct bpf_program fp;
            if (pcap_compile(handle_, &fp, filter_.c_str(), 0,
                             PCAP_NETMASK_UNKNOWN) < 0 ||
                pcap_setfilter(handle_, &fp) < 0) {
                stats_.last_error = pcap_geterr(handle_);
                pcap_close(handle_);
                handle_ = nullptr;
                return false;
            }
            pcap_freecode(&fp);
        }
        stats_.running = true;
        thread_ = std::thread([this]() { captureLoop(); });
        return true;
    }

    void stop() {
        stats_.running = false;
        if (handle_) pcap_breakloop(handle_);
        if (thread_.joinable()) thread_.join();
        if (handle_) { pcap_close(handle_); handle_ = nullptr; }
    }

    // FIX L86: return const ref — callers must use .snapshot() for value copies
    const CaptureStats& stats() const { return stats_; }

    static std::vector<std::string> list_interfaces() {
        std::vector<std::string> result;
        pcap_if_t* devs = nullptr;
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_findalldevs(&devs, errbuf) == 0) {
            for (pcap_if_t* d = devs; d; d = d->next)
                result.push_back(d->name);
            pcap_freealldevs(devs);
        }
        return result;
    }

private:
    void captureLoop() {
        while (stats_.running.load()) {
            struct pcap_pkthdr* hdr;
            const uint8_t* pkt;
            int ret = pcap_next_ex(handle_, &hdr, &pkt);
            if (ret == 0) continue;
            if (ret < 0)  break;
            stats_.packets_captured++;
            stats_.bytes_total += hdr->caplen;
            if (ingest_fn_) {
                Event ev = packet_to_event(hdr, pkt);
                if (!ev.source.empty())
                    ingest_fn_(ev);
                else
                    stats_.packets_dropped++;
            }
        }
    }

    std::string  iface_;
    std::string  filter_;
    int          snaplen_;
    int          timeout_ms_;
    pcap_t*      handle_  = nullptr;
    std::thread  thread_;
    IngestFn     ingest_fn_;
    CaptureStats stats_;
};

}  // namespace ids
