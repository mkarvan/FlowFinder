# FlowFinder

A real-time network packet capture tool with a rich terminal UI — built in Rust.

```
┌─ Packets (1,284) ──────────────────────────────────────────┐ ┌─ Bandwidth ─────────────┐
│ 12:01:05.123  192.168.1.5:52341 → 8.8.8.8:443     TLS  1440B│ │ ▁▃▅▇▅▃▂▄▆▇  24.3 Mbps  │
│ 12:01:05.124  10.0.0.1:53      → 192.168.1.5      DNS    80B│ │ 24.3 Mbps (peak 58.1)   │
│ 12:01:05.125  192.168.1.1:67   → 192.168.1.5      DHCP  548B│ └─────────────────────────┘
│ 12:01:05.126  192.168.1.5:80   → 203.0.113.1:8080 HTTP  240B│ ┌─ Protocols ─────────────┐
│ ...                                                          │ │ TLS  ████████ 62%       │
└──────────────────────────────────────────────────────────────┘ │ UDP  ████     21%       │
┌─ Flow Detail ──────────────────────────────────────────────┐ │ ICMP ██        9%       │
│ Src  192.168.1.5:52341     Dst  8.8.8.8:443                │ │ ARP  █         8%       │
│ Encap  Ethernet → IPv4 → TCP → TLS                         │ └─────────────────────────┘
│ Time  2024-01-15 12:01:05.123456                            │
│ Len   1440 bytes (hdr 66B payload 1374B)                    │
│ L3    IPv4  TTL 64                                          │
│ L4    TCP  Flags [SYN ACK]                                  │
│ L7    TLS                                                   │
│   Ver   TLS 1.2 (ClientHello)                               │
│   SNI   example.com                                         │
└──────────────────────────────────────────────────────────────┘
 [q]uit [p]ause [tab]focus [f]ilter [c]lear │ iface: en0  pkts: 1,284  bytes: 4.2MB
```

## Features

- **Full Ratatui TUI** — four live panes: packet list, flow detail, bandwidth sparkline, protocol distribution
- **Deep protocol decoding** across L2–L7:
  - **L2**: Ethernet II, 802.1Q VLAN tagging, MAC addresses
  - **L3**: IPv4, IPv6, ARP
  - **L4**: TCP (all flags, options), UDP, ICMPv4/v6
  - **L7**: DNS (queries + answers), HTTP/1.x (method, host, path, status), TLS (SNI extraction, version, handshake type), DHCP (message type), QUIC (version identification), HTTP/2 (preface detection)
- **Live bandwidth sparkline** with EWMA smoothing and peak tracking
- **Per-protocol distribution** bar chart
- **BPF filter expressions** — full libpcap filter syntax
- **PCAP file export** (`-w`) — standard `.pcap` format, readable by Wireshark
- **PCAP replay** (`-r`) — analyse saved captures offline
- **Plain text mode** (`--no-tui`) — pipe-friendly line output
- **Cross-platform** — macOS and Linux via libpcap

---

## Prerequisites

### macOS
libpcap is bundled with the OS. No extra installation needed.

```bash
# Grant BPF access without sudo (optional but recommended):
sudo chmod o+r /dev/bpf*
# Or add yourself to the 'access_bpf' group if your system supports it.
```

### Linux
```bash
# Debian/Ubuntu
sudo apt install libpcap-dev

# Fedora/RHEL
sudo dnf install libpcap-devel

# Arch
sudo pacman -S libpcap
```

### Rust toolchain
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

---

## Building

```bash
git clone <repo-url>
cd FlowFinder

# Development build
cargo build

# Optimised release build (recommended for capture performance)
cargo build --release
```

The binary is placed at `target/release/flowfinder`.

### Optional: install system-wide

```bash
cargo install --path .
```

---

## Running

Live capture requires elevated privileges to open the network interface.

```bash
# macOS — sudo
sudo ./target/release/flowfinder

# Linux — sudo
sudo ./target/release/flowfinder -i eth0

# Linux — grant capability to binary instead of using sudo (preferred)
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/flowfinder
./target/release/flowfinder -i eth0
```

---

## Usage

```
flowfinder [OPTIONS] [FILTER]

Arguments:
  [FILTER]   BPF filter expression (e.g. "tcp port 443")

Options:
  -i, --interface <IFACE>   Interface to capture on [default: first non-loopback]
  -w, --write <FILE>        Write captured packets to a .pcap file
  -r, --read  <FILE>        Replay from an existing .pcap file
  -n, --count <N>           Stop after N packets
      --no-tui              Plain text output, no TUI
  -v, --verbose             Extra header detail (encap chain, TTL, flags)
  -h, --help                Print help
```

### Examples

```bash
# Capture all traffic on default interface
sudo flowfinder

# Capture on a specific interface
sudo flowfinder -i eth0

# Filter: only HTTPS traffic
sudo flowfinder "tcp port 443"

# Filter: traffic to/from a specific host
sudo flowfinder "host 8.8.8.8"

# Filter: DNS queries only
sudo flowfinder "udp port 53"

# Filter: exclude your SSH session
sudo flowfinder "not tcp port 22"

# Filter: HTTP or DNS
sudo flowfinder "tcp port 80 or udp port 53"

# Capture 100 packets then stop
sudo flowfinder -n 100

# Save capture to file (also shows TUI)
sudo flowfinder -w capture.pcap "tcp port 443"

# Replay from file (no sudo needed)
flowfinder -r capture.pcap

# Plain text output — pipe to grep
sudo flowfinder --no-tui | grep TLS

# Verbose plain text with encap chain
sudo flowfinder --no-tui -v "udp port 53"
```

---

## TUI Layout

```
┌──────────────────────────────────────────┬──────────────────────┐
│                                          │   Bandwidth          │
│             Packet List                  │   sparkline + rate   │
│           (scrollable)                   ├──────────────────────┤
│                                          │   Protocol           │
├──────────────────────────────────────────┤   Distribution       │
│                                          │   bar chart          │
│             Flow Detail                  │                      │
│           (selected packet)              │                      │
└──────────────────────────────────────────┴──────────────────────┘
 Status bar: keys │ interface │ packet count │ total bytes │ filter
```

### Panes

| Pane | Contents |
|------|----------|
| **Packet List** | Scrollable table — timestamp, src, dst, protocol, length, L7 summary |
| **Flow Detail** | Full breakdown of the selected packet: encap chain, IPs, ports, TTL, TCP flags, L7 details |
| **Bandwidth** | Sparkline history (~6 seconds) of bytes/tick + current/peak rate |
| **Protocols** | Percentage bar chart of traffic by protocol (top 8) |

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `j` / `↓` | Scroll down one packet |
| `k` / `↑` | Scroll up one packet |
| `PgDn` | Scroll down 20 packets |
| `PgUp` | Scroll up 20 packets |
| `G` | Jump to newest packet (re-enables auto-scroll) |
| `g` | Jump to oldest packet |
| `End` | Jump to bottom |
| `Home` | Jump to top |
| `Tab` | Cycle focus between Packet List and Flow Detail panes |
| `p` / `Space` | Pause / resume capture display |
| `f` | Open inline BPF filter editor (Enter to apply, Esc to cancel) |
| `c` | Clear all packets and reset statistics |
| `q` | Quit |
| `Ctrl+C` | Quit |

> **Auto-scroll**: the packet list follows new packets automatically. Scrolling up disables auto-scroll; pressing `G` or `End` re-enables it.

---

## Protocol Support

| Layer | Protocols | Decoded Fields |
|-------|-----------|----------------|
| L2 | Ethernet II | src/dst MAC, EtherType |
| L2 | 802.1Q VLAN | VLAN ID |
| L3 | IPv4 | src/dst IP, TTL, protocol, total length, flags |
| L3 | IPv6 | src/dst IP, hop limit, next header, payload length |
| L3 | ARP | operation, sender/target IP and MAC |
| L4 | TCP | src/dst port, seq/ack, flags (SYN/ACK/FIN/RST/PSH/URG), data offset |
| L4 | UDP | src/dst port, length |
| L4 | ICMPv4/v6 | type, code |
| L7 | DNS | query name + type, answer A/AAAA/CNAME records |
| L7 | HTTP/1.x | method, host, path, response status |
| L7 | TLS | record type, handshake type, SNI (from ClientHello), version |
| L7 | DHCP | message type (Discover/Offer/Request/Ack/…) |
| L7 | QUIC | long-header detection, version field |
| L7 | HTTP/2 | client preface detection |

---

## BPF Filter Reference

`flowfinder` passes filter expressions directly to libpcap, so the full BPF syntax is supported.

```bash
# By protocol
tcp
udp
icmp
arp

# By port
port 443
tcp port 80
udp port 53

# By host
host 192.168.1.1
src host 10.0.0.1
dst host 8.8.8.8

# By network
net 192.168.0.0/24
src net 10.0.0.0/8

# Combinations
tcp and port 443
host 8.8.8.8 and not port 22
tcp port 80 or tcp port 443

# Packet size
less 128
greater 1400
```

---

## Project Structure

```
src/
├── main.rs               Entry point — CLI parsing, thread setup, dispatch
├── cli.rs                clap argument struct
├── capture/
│   ├── mod.rs            pcap capture loop (live and offline), pcap write
│   └── writer.rs         Optional NDJSON export (future)
├── decode/
│   ├── mod.rs            Decode pipeline: raw bytes → PacketInfo; data structures
│   └── application.rs    L7 decoders: DNS, HTTP, TLS, DHCP, QUIC, HTTP/2
├── stats.rs              FlowTable, per-flow EWMA rates, bandwidth history
└── tui/
    ├── mod.rs            Terminal setup, main render loop
    ├── app.rs            AppState: packet ring buffer, scroll, pause
    ├── events.rs         Keyboard event handler
    └── widgets/
        ├── packet_list.rs    Scrollable packet table
        ├── flow_detail.rs    Selected-packet detail pane
        ├── bandwidth.rs      Bandwidth sparkline
        └── protocol_chart.rs Protocol distribution bar chart
```

---

## Running Tests

```bash
cargo test
```

The test suite covers:
- L7 application-layer decoders (DNS, HTTP, TLS SNI extraction, DHCP, QUIC detection, HTTP/2)
- Full packet decode pipeline (Ethernet + IPv4/IPv6 + TCP/UDP/ICMP + L7)
- Flow key normalisation and stats aggregation
- App state management (scrolling, auto-scroll, pause, clear)

---

## Performance Notes

- Packets are captured in a dedicated thread and decoded on the main thread to prevent dropped frames.
- The TUI renders at ~20 fps (50 ms tick). Under heavy traffic (>100k pps), consider `--no-tui` and pipe to a file.
- The packet ring buffer keeps the last 10,000 packets in memory. Older packets are evicted automatically.
- PCAP write (if `-w` is specified) happens in the capture thread before any decoding, ensuring no packets are missed.
