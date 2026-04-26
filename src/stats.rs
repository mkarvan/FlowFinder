use std::collections::VecDeque;
use std::time::Instant;

use indexmap::IndexMap;

use crate::decode::PacketInfo;

const BW_HISTORY_LEN: usize = 120;
const EWMA_ALPHA: f64 = 0.2;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: String,
    pub dst: String,
    pub proto: String,
}

impl FlowKey {
    pub fn from_packet(p: &PacketInfo) -> Self {
        let src = p.src.display();
        let dst = p.dst.display();
        let proto = p.proto_label();
        // Normalise direction so A↔B and B↔A map to the same key
        if src <= dst {
            FlowKey { src, dst, proto }
        } else {
            FlowKey { src: dst, dst: src, proto }
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowStats {
    pub packets: u64,
    pub bytes: u64,
    pub pps: f64,
    pub bps: f64,
    pub last: Instant,
}

impl FlowStats {
    fn new() -> Self {
        FlowStats { packets: 0, bytes: 0, pps: 0.0, bps: 0.0, last: Instant::now() }
    }

    fn update(&mut self, bytes: usize) {
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64().max(1e-9);
        self.packets += 1;
        self.bytes += bytes as u64;
        self.pps = EWMA_ALPHA * (1.0 / dt) + (1.0 - EWMA_ALPHA) * self.pps;
        self.bps = EWMA_ALPHA * (bytes as f64 * 8.0 / dt) + (1.0 - EWMA_ALPHA) * self.bps;
        self.last = now;
    }
}

#[derive(Debug)]
pub struct StatsState {
    pub flows: IndexMap<FlowKey, FlowStats>,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub proto_counts: IndexMap<String, u64>,

    // Rolling bandwidth samples (bytes per tick)
    pub bw_history: VecDeque<u64>,
    pub bw_interval_bytes: u64,
    pub bw_interval_start: Instant,

    pub peak_bps: f64,
    pub current_bps: f64,
}

impl StatsState {
    pub fn new() -> Self {
        StatsState {
            flows: IndexMap::new(),
            total_packets: 0,
            total_bytes: 0,
            proto_counts: IndexMap::new(),
            bw_history: VecDeque::with_capacity(BW_HISTORY_LEN),
            bw_interval_bytes: 0,
            bw_interval_start: Instant::now(),
            peak_bps: 0.0,
            current_bps: 0.0,
        }
    }

    pub fn ingest(&mut self, p: &PacketInfo) {
        self.total_packets += 1;
        self.total_bytes += p.wire_len as u64;
        self.bw_interval_bytes += p.wire_len as u64;

        // Protocol counter
        *self.proto_counts.entry(p.proto_label()).or_insert(0) += 1;

        // Flow table
        let key = FlowKey::from_packet(p);
        self.flows.entry(key).or_insert_with(FlowStats::new).update(p.wire_len);
    }

    /// Called every ~50ms tick to commit the bandwidth sample.
    pub fn tick(&mut self) {
        let now = Instant::now();
        let dt = now.duration_since(self.bw_interval_start).as_secs_f64();
        if dt >= 0.05 {
            let bytes = self.bw_interval_bytes;
            if self.bw_history.len() >= BW_HISTORY_LEN {
                self.bw_history.pop_front();
            }
            self.bw_history.push_back(bytes);
            self.current_bps = EWMA_ALPHA * (bytes as f64 * 8.0 / dt) + (1.0 - EWMA_ALPHA) * self.current_bps;
            if self.current_bps > self.peak_bps {
                self.peak_bps = self.current_bps;
            }
            self.bw_interval_bytes = 0;
            self.bw_interval_start = now;
        }
    }

    #[allow(dead_code)]
    pub fn top_flows(&self, n: usize) -> Vec<(&FlowKey, &FlowStats)> {
        let mut v: Vec<_> = self.flows.iter().collect();
        v.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes));
        v.truncate(n);
        v
    }

    pub fn proto_distribution(&self) -> Vec<(String, u64)> {
        let mut v: Vec<_> = self.proto_counts.iter().map(|(k, v)| (k.clone(), *v)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }

    pub fn bw_sparkline_data(&self) -> Vec<u64> {
        self.bw_history.iter().copied().collect()
    }

    pub fn format_bps(bps: f64) -> String {
        if bps >= 1_000_000_000.0 {
            format!("{:.1} Gbps", bps / 1_000_000_000.0)
        } else if bps >= 1_000_000.0 {
            format!("{:.1} Mbps", bps / 1_000_000.0)
        } else if bps >= 1_000.0 {
            format!("{:.1} Kbps", bps / 1_000.0)
        } else {
            format!("{:.0} bps", bps)
        }
    }
}

impl Default for StatsState {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::decode::{Endpoint, L3Proto, L4Proto, L7Info, PacketInfo};

    fn make_packet(src_ip: [u8; 4], src_port: u16, dst_ip: [u8; 4], dst_port: u16, proto: &str, len: usize) -> PacketInfo {
        let l4 = match proto {
            "TCP" => Some(L4Proto::Tcp),
            "UDP" => Some(L4Proto::Udp),
            "ICMP" => Some(L4Proto::Icmp),
            _ => None,
        };
        PacketInfo {
            ts: chrono::Local::now(),
            wire_len: len,
            encap_chain: vec!["Ethernet".into(), "IPv4".into(), proto.into()],
            src: Endpoint {
                ip: Some(IpAddr::V4(Ipv4Addr::from(src_ip))),
                port: Some(src_port),
                mac: None,
            },
            dst: Endpoint {
                ip: Some(IpAddr::V4(Ipv4Addr::from(dst_ip))),
                port: Some(dst_port),
                mac: None,
            },
            l3_proto: L3Proto::Ipv4,
            l4_proto: l4,
            ttl: Some(64),
            header_len: 54,
            payload_len: len.saturating_sub(54),
            tcp_flags: None,
            l7: None,
        }
    }

    fn make_dns_packet(src_ip: [u8; 4], len: usize) -> PacketInfo {
        let mut p = make_packet(src_ip, 54321, [8, 8, 8, 8], 53, "UDP", len);
        p.l7 = Some(L7Info::Dns {
            query: "example.com".into(),
            qtype: "A".into(),
            answers: vec![],
            is_response: false,
        });
        p.encap_chain.push("DNS".into());
        p
    }

    // ── flow key tests ────────────────────────────────────────────────────────

    #[test]
    fn test_flow_key_normalised_bidirectional() {
        let fwd = make_packet([192,168,1,1], 1000, [8,8,8,8], 443, "TCP", 100);
        let rev = make_packet([8,8,8,8], 443, [192,168,1,1], 1000, "TCP", 100);
        assert_eq!(FlowKey::from_packet(&fwd), FlowKey::from_packet(&rev),
            "forward and reverse flows must share the same key");
    }

    #[test]
    fn test_flow_key_different_ports_different_key() {
        let p1 = make_packet([1,2,3,4], 1000, [5,6,7,8], 80, "TCP", 100);
        let p2 = make_packet([1,2,3,4], 1001, [5,6,7,8], 80, "TCP", 100);
        assert_ne!(FlowKey::from_packet(&p1), FlowKey::from_packet(&p2));
    }

    #[test]
    fn test_flow_key_different_protocols_different_key() {
        let tcp = make_packet([1,2,3,4], 1000, [5,6,7,8], 80, "TCP", 100);
        let udp = make_packet([1,2,3,4], 1000, [5,6,7,8], 80, "UDP", 100);
        assert_ne!(FlowKey::from_packet(&tcp), FlowKey::from_packet(&udp));
    }

    // ── stats ingestion tests ─────────────────────────────────────────────────

    #[test]
    fn test_ingest_increments_packet_count() {
        let mut s = StatsState::new();
        s.ingest(&make_packet([1,2,3,4], 1000, [5,6,7,8], 80, "TCP", 100));
        s.ingest(&make_packet([1,2,3,4], 1000, [5,6,7,8], 80, "TCP", 200));
        assert_eq!(s.total_packets, 2);
    }

    #[test]
    fn test_ingest_accumulates_bytes() {
        let mut s = StatsState::new();
        s.ingest(&make_packet([1,2,3,4], 1000, [5,6,7,8], 80, "TCP", 100));
        s.ingest(&make_packet([1,2,3,4], 1000, [5,6,7,8], 80, "TCP", 400));
        assert_eq!(s.total_bytes, 500);
    }

    #[test]
    fn test_ingest_creates_flow_entry() {
        let mut s = StatsState::new();
        let p = make_packet([192,168,1,1], 1000, [8,8,8,8], 443, "TCP", 100);
        s.ingest(&p);
        assert_eq!(s.flows.len(), 1);
        let flow = s.flows.values().next().unwrap();
        assert_eq!(flow.packets, 1);
        assert_eq!(flow.bytes, 100);
    }

    #[test]
    fn test_ingest_merges_bidirectional_into_one_flow() {
        let mut s = StatsState::new();
        let fwd = make_packet([1,2,3,4], 1000, [5,6,7,8], 443, "TCP", 100);
        let rev = make_packet([5,6,7,8], 443, [1,2,3,4], 1000, "TCP", 80);
        s.ingest(&fwd);
        s.ingest(&rev);
        assert_eq!(s.flows.len(), 1, "bidirectional packets should share one flow");
        let flow = s.flows.values().next().unwrap();
        assert_eq!(flow.packets, 2);
        assert_eq!(flow.bytes, 180);
    }

    #[test]
    fn test_ingest_tracks_protocol_counts() {
        let mut s = StatsState::new();
        s.ingest(&make_packet([1,2,3,4], 1, [5,6,7,8], 80, "TCP", 60));
        s.ingest(&make_packet([1,2,3,4], 2, [5,6,7,8], 80, "TCP", 60));
        s.ingest(&make_dns_packet([1,2,3,4], 100));
        let counts = s.proto_counts.clone();
        assert_eq!(counts["TCP"], 2);
        assert_eq!(counts["DNS"], 1);
    }

    // ── protocol distribution tests ───────────────────────────────────────────

    #[test]
    fn test_proto_distribution_sorted_by_count() {
        let mut s = StatsState::new();
        for _ in 0..5 { s.ingest(&make_packet([1,2,3,4], 1, [5,6,7,8], 80, "TCP", 60)); }
        for _ in 0..2 { s.ingest(&make_dns_packet([1,2,3,4], 100)); }
        let dist = s.proto_distribution();
        assert_eq!(dist[0].0, "TCP");
        assert_eq!(dist[0].1, 5);
        assert_eq!(dist[1].0, "DNS");
        assert_eq!(dist[1].1, 2);
    }

    #[test]
    fn test_proto_distribution_empty() {
        let s = StatsState::new();
        assert!(s.proto_distribution().is_empty());
    }

    // ── bandwidth tests ───────────────────────────────────────────────────────

    #[test]
    fn test_bandwidth_tick_appends_sample() {
        let mut s = StatsState::new();
        s.ingest(&make_packet([1,2,3,4], 1, [5,6,7,8], 80, "TCP", 500));
        // Force the tick interval to expire by manipulating the start time
        s.bw_interval_start = std::time::Instant::now() - std::time::Duration::from_millis(100);
        s.tick();
        assert_eq!(s.bw_history.len(), 1);
        assert_eq!(s.bw_history[0], 500);
    }

    #[test]
    fn test_bandwidth_tick_resets_interval_bytes() {
        let mut s = StatsState::new();
        s.ingest(&make_packet([1,2,3,4], 1, [5,6,7,8], 80, "TCP", 200));
        s.bw_interval_start = std::time::Instant::now() - std::time::Duration::from_millis(100);
        s.tick();
        assert_eq!(s.bw_interval_bytes, 0, "interval bytes should reset after tick");
    }

    #[test]
    fn test_bandwidth_tick_no_effect_before_interval() {
        let mut s = StatsState::new();
        s.ingest(&make_packet([1,2,3,4], 1, [5,6,7,8], 80, "TCP", 100));
        // bw_interval_start is "now", so < 50ms hasn't elapsed
        s.tick();
        assert_eq!(s.bw_history.len(), 0);
    }

    #[test]
    fn test_bw_sparkline_data_matches_history() {
        let mut s = StatsState::new();
        for bytes in [100u64, 200, 300] {
            s.bw_history.push_back(bytes);
        }
        let sparkline = s.bw_sparkline_data();
        assert_eq!(sparkline, vec![100, 200, 300]);
    }

    // ── format_bps tests ──────────────────────────────────────────────────────

    #[test]
    fn test_format_bps_bytes() {
        assert_eq!(StatsState::format_bps(800.0), "800 bps");
    }

    #[test]
    fn test_format_bps_kilobits() {
        assert_eq!(StatsState::format_bps(1_500.0), "1.5 Kbps");
    }

    #[test]
    fn test_format_bps_megabits() {
        assert_eq!(StatsState::format_bps(24_300_000.0), "24.3 Mbps");
    }

    #[test]
    fn test_format_bps_gigabits() {
        assert_eq!(StatsState::format_bps(1_200_000_000.0), "1.2 Gbps");
    }
}
