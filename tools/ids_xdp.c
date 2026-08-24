// ─────────────────────────────────────────────────────────────
//  ids_xdp.c — eBPF/XDP packet parser for IDS
//
//  Self-contained — uses only kernel headers, no libbpf.
//  Captures TCP/UDP packets via perf ring buffer to userspace.
//
//  Build:
//    clang -O2 -target bpf -c ids_xdp.c -o ids_xdp.o
//
//  Load:
//    ip link set dev eth0 xdp obj ids_xdp.o
//    bpftool prog load ids_xdp.o /sys/fs/bpf/ids_xdp
// ─────────────────────────────────────────────────────────────
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// ─── Helper macros ───────────────────────────────────────────
#define SEC(NAME) __attribute__((section(NAME), used))
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)

// ─── Perf event output helper (inlined) ──────────────────────
static long (*bpf_perf_event_output_impl)(void *ctx, void *map,
                                          unsigned long long flags,
                                          void *data, unsigned long long size) =
    (void *)BPF_FUNC_perf_event_output;

#define bpf_perf_event_output(ctx, map, flags, data, size) \
    bpf_perf_event_output_impl(ctx, map, flags, data, size)

// ─── Packet event struct ─────────────────────────────────────
struct packet_event {
    unsigned int src_ip;
    unsigned int dst_ip;
    unsigned short src_port;
    unsigned short dst_port;
    unsigned char  protocol;
    unsigned char  flags;
    unsigned int   pkt_len;
};

// ─── Perf event array map ────────────────────────────────────
struct {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
} packet_events SEC(".maps") = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(unsigned int),
    .value_size = sizeof(unsigned int),
    .max_entries = 128,
};

// ─── XDP program ─────────────────────────────────────────────
SEC("xdp")
int ids_xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(unsigned long)ctx->data_end;
    void *data     = (void *)(unsigned long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    unsigned short ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(struct iphdr))
        return XDP_PASS;

    void *trans = (void *)ip + ip_hlen;
    if (trans > data_end)
        return XDP_PASS;

    struct packet_event ev = {};
    ev.src_ip   = ip->saddr;
    ev.dst_ip   = ip->daddr;
    ev.protocol = ip->protocol;
    ev.pkt_len  = bpf_ntohs(ip->tot_len);

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)trans;
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        ev.src_port = bpf_ntohs(tcp->source);
        ev.dst_port = bpf_ntohs(tcp->dest);
        ev.flags = *((unsigned char *)tcp + 13);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)trans;
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        ev.src_port = bpf_ntohs(udp->source);
        ev.dst_port = bpf_ntohs(udp->dest);
    } else {
        return XDP_PASS;
    }

    bpf_perf_event_output(ctx, &packet_events, 0xffffffffULL,
                          &ev, sizeof(ev));

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
