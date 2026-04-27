# FlowFinder

A real-time, flow-centric network packet capture and analysis tool with a rich terminal UI — built in Rust.

```
┌─ Flows (47) ───────────────────────────────────────────────┐ ┌─ Bandwidth ─────────────┐
│ ▶ example.com:443 → 192.168.1.5:52341  TLS  234  1.2MB ... │ │ ▁▃▅▇▅▃▂▄▆▇  24.3 Mbps  │
│   8.8.8.8:53      → 192.168.1.5:5353   DNS    8   3.1KB ... │ │ 24.3 Mbps (peak 58.1)   │
│   192.168.1.1:67  → 192.168.1.5       DHCP    2   1.0KB ... │ └─────────────────────────┘
│   10.0.0.1:22     → 192.168.1.5:51284  TCP  120 240.0KB ... │ ┌─ Protocols ─────────────┐
│ ...                                                           │ │ TLS  ████████ 62%       │
└──────────────────────────────────────────────────────────────┘ │ UDP  ████     21%       │
┌─ Flow Summary ─────────────────────────────────────────────┐ │ ICMP ██        9%       │
│ Src   192.168.1.5:52341                                     │ │ ARP  █         8%       │
│       myhost.local                                           │ └─────────────────────────┘
│ Dst   93.184.216.34:443
│       example.com
│ Proto TLS  Pkts 234 (200 captured)  Bytes 1.2 MB
│ Age   1m 23s    Avg 117 Kbps    Now 24.3 Mbps
└──────────────────────────────────────────────────────────────┘
 [q]uit [p]ause [↵] open [f]ilter [c]lear │ iface: en0  pkts: 1,284  bytes: 4.2MB
```

Press **Enter** on a flow to drill into its packet list, then highlight a packet to see its full header dump and payload hex view:

```
┌─ 192.168.1.5:52341 → 93.184.216.34:443 | 234 packets (showing 200) ─┐
│ ▶ 12:01:05.123  →  1440  ClientHello SNI=example.com                 │
│   12:01:05.124  ←  1440  ServerHello CipherSuite=TLS_AES_128_GCM     │
│   12:01:05.130  →    66  PSH ACK                                     │
│ ...                                                                   │
└────────────────────────────────────────────────────────────────────────┘
┌─ Flow Detail ──────────────────────────────────────────────────────┐
│ Src   192.168.1.5:52341  Dst  93.184.216.34:443                    │
│ Host  myhost.local → example.com                                    │
│ Encap Ethernet→IPv4→TCP→TLS                                         │
│ L3    IPv4  TTL 64                                                  │
│   IHL 20B  DSCP 0x00  ECN 0b00  Total 1440B                         │
│   ID  0x4d2a  Frag [DF] off 0  Cksum 0xa1b2                         │
│ L4    TCP  Flags [SYN ACK ECE]                                      │
│   Seq 1234567890   Ack 9876543210                                   │
│   Win 65535  DataOff 32B  UrgPtr 0  Cksum 0xabcd                    │
│   Opts MSS=1460  WS=7  SACKp  TS=(987654, 123456)                   │
│ L7    TLS                                                           │
│   Ver TLS 1.2 (ClientHello)                                         │
│   SNI example.com                                                   │
│                                                                     │
│ Payload (128 of 1374 bytes)                                         │
│ 0000  16 03 01 05 ad 01 00 05  a9 03 03 ab cd ef ...  |..........|  │
│ ...                                                                 │
└────────────────────────────────────────────────────────────────────────┘
```

## Features

- **Flow-centric TUI** — top-level view shows unique 5-tuple flows; press Enter to drill into a flow's packet list; press Esc to go back
- **Bidirectional flow aggregation** — A↔B and B↔A normalize to the same flow with combined byte/packet counts and EWMA rates
- **Hostname resolution** — IPs are resolved to hostnames by snooping captured DNS responses (no extra network traffic, no leaks)
- **Full L2–L7 protocol decode** with per-field display:
  - **L2**: Ethernet II, 802.1Q VLAN tagging (with VID, PCP, DEI), MAC addresses
  - **L3**: IPv4 (IHL, DSCP, ECN, total length, ID, DF/MF flags, fragment offset, checksum), IPv6 (traffic class, flow label, payload length, next header), ARP
  - **L4**: TCP (seq, ack, window, data offset, checksum, urgent pointer, all 9 flags including ECE/CWR/NS, options: MSS/WindowScale/SACK-permitted/Timestamps), UDP, ICMPv4 + ICMPv6 (type with human name, code, checksum)
  - **L7**: DNS (queries + answers), HTTP/1.x (method, host, path, status), TLS (SNI from ClientHello, real negotiated version, handshake type), DHCP (message type), QUIC (long-header detection, version), HTTP/2 (preface detection)
- **Tunnel decoding** — automatic detection and inner-packet decode for **GRE**, **IP-in-IP**, **IPv6-in-IPv4 (6in4)**, and **VXLAN**; tunnel ID (VNI / GRE key) and outer endpoints shown in the detail pane
- **Hex + ASCII payload preview** — first 128 bytes of L7 payload shown as a hex dump in the flow detail pane
- **Live BPF filter editing** — press `f` and apply a new filter on the running capture without restart; compile errors surface in red in the status bar
- **Live bandwidth sparkline** with EWMA smoothing and peak tracking
- **Per-protocol distribution** bar chart
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
│   Flow List   (or  Packet List           │   sparkline + rate   │
│                    once a flow is open)  ├──────────────────────┤
│                                          │   Protocol           │
├──────────────────────────────────────────┤   Distribution       │
│                                          │   bar chart          │
│   Flow Summary  (or  Flow Detail         │                      │
│                      once a flow is open)│                      │
└──────────────────────────────────────────┴──────────────────────┘
 Status bar: keys │ interface │ packet count │ total bytes │ filter │ BPF errors
```

The top-left and bottom-left panes are mode-aware:

| Mode | Top-left | Bottom-left |
|------|----------|-------------|
| **Flow list** (default) | Flow table — `Src→Dst`, proto, packets, bytes, rate, age | Selected flow summary — endpoints, hostnames, totals, duration, current rate |
| **Inside a flow** (after pressing Enter) | Per-flow packet list — time, direction (→/←), length, info | Selected packet's full header dump + payload hex preview |

The bandwidth sparkline and protocol distribution panes are always visible.

### Panes

| Pane | Contents |
|------|----------|
| **Flow List** | Table of unique 5-tuple flows. Bidirectional packets share one row. New flow rows append at the bottom; the open flow is shown in italics. |
| **Flow Summary** | Selected flow's stats — IPs, hostnames (when known), protocol, total bytes/packets, age, average and current bandwidth. |
| **Flow Packets** | Per-flow packet list shown after pressing Enter. Shows direction arrows relative to the flow's canonical src side. |
| **Flow Detail** | Full breakdown of the selected packet (when inside a flow): encap chain, hostnames, IP/TCP/UDP/ICMP header fields, TCP options, L7 details, tunnel info if any, MAC addresses, and a 128-byte hex+ASCII payload preview. |
| **Bandwidth** | Sparkline history (~6 seconds) of bytes/tick + current/peak rate. |
| **Protocols** | Percentage bar chart of traffic by protocol (top 8). |

### Keyboard Shortcuts

| Key | Flow list mode | Inside an open flow |
|-----|---------------|---------------------|
| `j` / `↓` | Highlight next flow | Highlight next packet |
| `k` / `↑` | Highlight previous flow | Highlight previous packet |
| `PgDn` | Scroll down 20 | Scroll down 20 |
| `PgUp` | Scroll up 20 | Scroll up 20 |
| `g` | Jump to first | Jump to first packet |
| `G` / `End` | Jump to newest (re-enables auto-scroll) | Jump to newest packet |
| `Home` | Jump to first | Jump to first packet |
| `Enter` (`↵`) | **Open the highlighted flow** | — |
| `Esc` | — | **Close the open flow, return to flow list** |
| `Tab` | Cycle focus between top and bottom pane | same |
| `p` / `Space` | Pause / resume capture display | same |
| `f` | Open inline BPF filter editor (Enter to apply, Esc to cancel) | same |
| `c` | Clear all flows, reset stats and hostname cache | same |
| `q` / `Ctrl+C` | Quit | Quit |

> **Auto-scroll**: the flow list and the per-flow packet list both follow newest-first by default. Scrolling up disables auto-scroll for that view; pressing `G` or `End` re-enables it.

> **Live BPF filter**: pressing `f` opens an editor in the status bar. Apply with Enter; an empty expression clears the filter and resumes matching everything. Compile errors from libpcap appear in red in the status bar; the previous filter remains active.

---

## Protocol Support

| Layer | Protocol | Decoded Fields |
|-------|----------|----------------|
| L2 | Ethernet II | src/dst MAC, EtherType |
| L2 | 802.1Q VLAN | VID, PCP, DEI |
| L3 | IPv4 | src/dst IP, IHL, DSCP, ECN, total length, ID, DF/MF flags, fragment offset, TTL, protocol, checksum |
| L3 | IPv6 | src/dst IP, traffic class, flow label, payload length, next header, hop limit |
| L3 | ARP | operation, sender/target IP, sender/target MAC |
| L4 | TCP | src/dst port, seq, ack, data offset, window, checksum, urgent pointer, all 9 flags (SYN/ACK/FIN/RST/PSH/URG/ECE/CWR/NS), options: MSS, Window Scale, SACK-permitted, Timestamps |
| L4 | UDP | src/dst port, length |
| L4 | ICMPv4 / ICMPv6 | type (with human name — Echo Request, Dest Unreachable, etc.), code, checksum |
| Tunnel | GRE | outer endpoints, GRE key, inner protocol (IPv4 / IPv6 / Transparent Ethernet Bridging) |
| Tunnel | IP-in-IP | outer endpoints, inner IPv4 |
| Tunnel | IPv6-in-IPv4 (6in4) | outer endpoints, inner IPv6 |
| Tunnel | VXLAN | outer endpoints, VNI, inner Ethernet frame |
| L7 | DNS | query name + type, answer A/AAAA/CNAME records (also feeds the hostname cache) |
| L7 | HTTP/1.x | method, host, path, response status |
| L7 | TLS | record type, handshake type, SNI (from ClientHello), negotiated version |
| L7 | DHCP | message type (Discover / Offer / Request / Ack / …) |
| L7 | QUIC | long-header detection, version |
| L7 | HTTP/2 | client preface detection |

---

## Hostname Resolution

FlowFinder snoops DNS responses observed in the live capture and builds an `IpAddr → hostname` cache. Whenever a flow's IP appears in that cache, the resolved name is shown alongside the IP in the flow list, summary, and detail panes.

- No extra DNS traffic is generated — it only resolves what your applications already queried.
- Useful in real time: launch FlowFinder, browse to a site, and watch its IPs light up with names.
- `c` clears the cache along with the flow table.

If an IP was never queried via DNS during the capture window, it shows up as a bare IP — there is no fallback to system rDNS.

---

## BPF Filter Reference

`flowfinder` passes filter expressions directly to libpcap, so the full BPF syntax is supported. Filters can be set on the command line via `-f`/the positional `FILTER` argument, or live from inside the TUI via the `f` key.

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
├── main.rs               Entry point — CLI parsing, channel + thread setup
├── cli.rs                clap argument struct
├── stats.rs              FlowKey, per-flow EWMA rates, bandwidth history, protocol counters
├── capture/
│   ├── mod.rs            pcap capture loop (live + offline replay), live BPF re-filter, pcap write
│   └── writer.rs         NDJSON export stub (unused)
├── decode/
│   ├── mod.rs            Decode pipeline: raw bytes → PacketInfo; L2-L4 + tunnel decoders + Headers struct
│   └── application.rs    L7 decoders: DNS, HTTP, TLS SNI, DHCP, QUIC, HTTP/2
└── tui/
    ├── mod.rs            Terminal setup, render loop, status bar, mode-aware pane dispatch
    ├── app.rs            AppState: flow_table (IndexMap<FlowKey, FlowEntry>), hostname cache, navigation
    ├── events.rs         Keyboard event handler (mode-aware: flow list vs open flow)
    └── widgets/
        ├── flow_list.rs       Flow table (top-left in list mode)
        ├── flow_summary.rs    Selected flow's stats (bottom-left in list mode)
        ├── flow_packets.rs    Per-flow packet table (top-left when a flow is open)
        ├── flow_detail.rs     Full header + payload dump (bottom-left when a flow is open)
        ├── bandwidth.rs       Bandwidth sparkline
        └── protocol_chart.rs  Protocol distribution bar chart
```

---

## Running Tests

```bash
cargo test
```

The test suite (96 tests) covers:
- L7 application-layer decoders (DNS, HTTP, TLS SNI extraction, DHCP, QUIC detection, HTTP/2)
- Full packet decode pipeline (Ethernet + 802.1Q VLAN + IPv4/IPv6 + TCP/UDP/ICMP + L7)
- Tunnel decoding for GRE, IPIP, 6in4, VXLAN with inner-packet endpoint extraction
- TCP options parsing (MSS, Window Scale, SACK-permitted, Timestamps) and extended TCP flags (ECE, CWR, NS)
- IPv4 and ICMP detail field extraction (DSCP, ECN, fragment flags, ICMP type names)
- Flow key normalisation, bidirectional flow aggregation, EWMA stats
- AppState management — flow table eviction, drill-down navigation, hostname cache from DNS snooping, scrolling, auto-scroll, pause, clear

---

## Performance Notes

- Packets are captured in a dedicated thread and decoded on the main thread to prevent dropped frames.
- The TUI renders at ~20 fps (50 ms tick). Under heavy traffic (>100k pps), consider `--no-tui` and pipe to a file.
- Each flow keeps its most recent 200 packets (older ones are evicted); the flow table itself is capped at 10,000 flows with the oldest-seen flow evicted on overflow.
- Each captured packet retains the first 128 bytes of its L7 payload for the hex dump pane.
- PCAP write (if `-w` is specified) happens in the capture thread before any decoding, ensuring no packets are missed.
- Live BPF filter changes are applied to the open libpcap handle via `pcap_setfilter` on the next timeout tick — no thread restart, no packet loss.
