# IDS Visualizer — Linux Setup & Run Guide

## Prerequisites

Install build tools and runtime dependencies:

```bash
# Debian / Ubuntu
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev libncurses-dev

# RHEL / Fedora / Rocky
sudo dnf install -y gcc-c++ cmake libpcap-devel ncurses-devel

# Arch
sudo pacman -S base-devel cmake libpcap ncurses
```

Verify versions:

```bash
cmake --version   # need >= 3.16
g++ --version     # need >= 9 (C++17)
```

---

## Build

```bash
# from the project root
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target ids_visualizer -j$(nproc)
```

The binary lands at `build/ids_visualizer`.

---

## Find Your Network Interface

```bash
ip link show
# or
ls /sys/class/net/
```

Common names: `eth0`, `ens3`, `enp3s0`, `wlan0`, `any` (all interfaces).

---

## Run

The visualizer requires root (or `CAP_NET_RAW`) to open a raw pcap socket.

```bash
# capture all IP traffic on eth0
sudo ./build/ids_visualizer eth0

# capture only TCP port 80/443
sudo ./build/ids_visualizer eth0 "tcp port 80 or tcp port 443"

# capture all interfaces
sudo ./build/ids_visualizer any

# no BPF filter (everything including ARP, ICMP, etc.)
sudo ./build/ids_visualizer eth0 ""
```

Press `q` to quit. A session summary prints on exit.

---

## Run Without Root (capability approach)

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./build/ids_visualizer
./build/ids_visualizer eth0
```

Remove the capability when done:

```bash
sudo setcap -r ./build/ids_visualizer
```

---

## BPF Filter Examples

| Goal | Filter |
|---|---|
| All IP | `ip` (default) |
| HTTP/HTTPS only | `tcp port 80 or tcp port 443` |
| Exclude SSH | `not tcp port 22` |
| Single host | `host 192.168.1.100` |
| Inbound only | `dst host <your-ip>` |
| UDP only | `udp` |
| High-volume scan detection | `tcp[tcpflags] & tcp-syn != 0` |

---

## Dashboard Layout

```
┌─ IDS Live | iface: eth0 | filter: ip | HH:MM:SS | LIVE ──────────────┐
├─ Events/s  Total  Alerts  Blocks  Escalations  Reasoning%  Faults  Campaigns ─┤
│  L0:Xµs  L1:Xµs  Retrieval:Xµs  Reasoning:Xµs  Total:Xµs  Drift:X  Pkts:X  │
├─ Throughput (ev/s) ──────────┬─ Pipeline State ──────────────────────────────┤
│  sparkline                   │  Drift   [████████--] X.X                     │
│                              │  Anomaly [████------] X.XX                    │
│                              │  MemWr   [██--------]                         │
│                              │  Campaigns: N                                 │
├─ Alert Feed ─────────────────────────────────────────────────────────────────┤
│  Time     Decision   Source           Attack Class                 Conf       │
│  ...                                                                          │
└─ [q] quit | frame N | cap: Xk pkts | normal ────────────────────────────────┘
```

---

## Troubleshooting

**`Failed to start capture: PCAP: You don't have permission`**
→ Run with `sudo` or set the capability as shown above.

**`No network interfaces found`**
→ Run as root. Non-root users cannot enumerate raw interfaces.

**`ids_visualizer` target not built**
→ CMake skipped it because libpcap or ncurses was not found. Re-run after installing the dev packages, then re-run `cmake -B build` and rebuild.

**Terminal too small / garbled layout**
→ Minimum recommended size is 120×30. Resize the terminal and the dashboard redraws automatically (`KEY_RESIZE` handled).

**High CPU on `any` interface**
→ Use a specific interface and a BPF filter to reduce packet volume fed into the pipeline.
