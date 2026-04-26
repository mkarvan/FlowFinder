use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::Instant;

use indexmap::IndexMap;

use crate::decode::{L7Info, PacketInfo};
use crate::stats::{FlowKey, StatsState};

const MAX_FLOW_PACKETS: usize = 200;
const MAX_FLOWS: usize = 10_000;
const EWMA_ALPHA: f64 = 0.2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusPane {
    FlowList,
    Detail,
}

pub struct FlowEntry {
    pub packets: VecDeque<PacketInfo>,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub first_seen: chrono::DateTime<chrono::Local>,
    pub last_seen: chrono::DateTime<chrono::Local>,
    pub last_instant: Instant,
    pub bps: f64,
    pub pps: f64,
    /// IP for the side that matches `FlowKey::src` (key direction is normalized).
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

impl FlowEntry {
    fn new(p: &PacketInfo, key: &FlowKey) -> Self {
        let (src_ip, dst_ip, src_port, dst_port) = if p.src.display() == key.src {
            (p.src.ip, p.dst.ip, p.src.port, p.dst.port)
        } else {
            (p.dst.ip, p.src.ip, p.dst.port, p.src.port)
        };
        FlowEntry {
            packets: VecDeque::with_capacity(MAX_FLOW_PACKETS),
            total_packets: 0,
            total_bytes: 0,
            first_seen: p.ts,
            last_seen: p.ts,
            last_instant: Instant::now(),
            bps: 0.0,
            pps: 0.0,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        }
    }

    fn ingest(&mut self, p: PacketInfo) {
        self.total_packets += 1;
        self.total_bytes += p.wire_len as u64;
        self.last_seen = p.ts;
        let now = Instant::now();
        let dt = now.duration_since(self.last_instant).as_secs_f64().max(1e-3);
        self.pps = EWMA_ALPHA * (1.0 / dt) + (1.0 - EWMA_ALPHA) * self.pps;
        self.bps = EWMA_ALPHA * (p.wire_len as f64 * 8.0 / dt) + (1.0 - EWMA_ALPHA) * self.bps;
        self.last_instant = now;
        if self.packets.len() >= MAX_FLOW_PACKETS {
            self.packets.pop_front();
        }
        self.packets.push_back(p);
    }

    pub fn duration_secs(&self) -> f64 {
        self.last_seen
            .signed_duration_since(self.first_seen)
            .num_milliseconds()
            .max(0) as f64
            / 1000.0
    }
}

pub struct AppState {
    /// All flows in insertion order.
    pub flow_table: IndexMap<FlowKey, FlowEntry>,
    /// Index into `flow_table` of the highlighted row.
    pub selected_flow: usize,
    pub flow_scroll: usize,

    /// Key of the currently drilled-into flow (None = flow list mode).
    pub open_flow: Option<FlowKey>,
    /// Selected packet index within the open flow's packet list.
    pub flow_pkt_sel: usize,
    pub flow_pkt_scroll: usize,
    /// Follow the newest packet while a flow is open.
    pub pkt_auto_scroll: bool,

    pub stats: StatsState,
    pub paused: bool,
    pub focus: FocusPane,
    pub filter_input: Option<String>,
    pub filter_editing: bool,
    pub filter_error: Option<String>,
    pub interface_name: String,
    /// Follow the most recently active flow in the flow list.
    pub flow_auto_scroll: bool,
    /// IP → hostname snooped from observed DNS responses.
    pub hostname_cache: HashMap<IpAddr, String>,
}

impl AppState {
    pub fn new(interface_name: String) -> Self {
        AppState {
            flow_table: IndexMap::new(),
            selected_flow: 0,
            flow_scroll: 0,
            open_flow: None,
            flow_pkt_sel: 0,
            flow_pkt_scroll: 0,
            pkt_auto_scroll: true,
            stats: StatsState::new(),
            paused: false,
            focus: FocusPane::FlowList,
            filter_input: None,
            filter_editing: false,
            filter_error: None,
            interface_name,
            flow_auto_scroll: true,
            hostname_cache: HashMap::new(),
        }
    }

    pub fn add_packet(&mut self, p: PacketInfo) {
        if self.paused {
            return;
        }
        self.stats.ingest(&p);

        // Snoop DNS responses to learn IP→hostname mappings.
        if let Some(L7Info::Dns { query, answers, is_response: true, .. }) = &p.l7 {
            if !query.is_empty() {
                for ans in answers {
                    if let Ok(ip) = ans.parse::<IpAddr>() {
                        self.hostname_cache.insert(ip, query.clone());
                    }
                }
            }
        }

        let key = FlowKey::from_packet(&p);

        // Evict the oldest-seen flow if we're at capacity and this is a new flow.
        if !self.flow_table.contains_key(&key) && self.flow_table.len() >= MAX_FLOWS {
            if let Some(oldest) = self.flow_table
                .iter()
                .min_by_key(|(_, e)| e.last_seen)
                .map(|(k, _)| k.clone())
            {
                if let Some(pos) = self.flow_table.get_index_of(&oldest) {
                    if pos < self.selected_flow && self.selected_flow > 0 {
                        self.selected_flow -= 1;
                    }
                }
                self.flow_table.shift_remove(&oldest);
            }
        }

        let is_new = !self.flow_table.contains_key(&key);
        let key_for_new = key.clone();
        let entry = self
            .flow_table
            .entry(key.clone())
            .or_insert_with(|| FlowEntry::new(&p, &key_for_new));
        entry.ingest(p);

        // Auto-scroll flow list to newest flow on insertion.
        if is_new && self.flow_auto_scroll {
            self.selected_flow = self.flow_table.len().saturating_sub(1);
        }

        // Auto-scroll packet list within the open flow.
        if self.pkt_auto_scroll {
            if self.open_flow.as_ref() == Some(&key) {
                if let Some(e) = self.flow_table.get(&key) {
                    self.flow_pkt_sel = e.packets.len().saturating_sub(1);
                }
            }
        }
    }

    pub fn tick(&mut self) {
        self.stats.tick();
    }

    pub fn selected_flow_entry(&self) -> Option<(&FlowKey, &FlowEntry)> {
        self.flow_table.get_index(self.selected_flow)
    }

    pub fn open_flow_entry(&self) -> Option<&FlowEntry> {
        self.open_flow.as_ref().and_then(|k| self.flow_table.get(k))
    }

    pub fn selected_packet(&self) -> Option<&PacketInfo> {
        self.open_flow_entry()?.packets.get(self.flow_pkt_sel)
    }

    // ── flow list navigation ──────────────────────────────────────────────────

    pub fn open_selected_flow(&mut self) {
        if let Some((key, entry)) = self.flow_table.get_index(self.selected_flow) {
            self.open_flow = Some(key.clone());
            self.flow_pkt_sel = entry.packets.len().saturating_sub(1);
            self.flow_pkt_scroll = 0;
            self.pkt_auto_scroll = true;
        }
    }

    pub fn close_flow(&mut self) {
        self.open_flow = None;
    }

    pub fn scroll_flow_up(&mut self) {
        self.flow_auto_scroll = false;
        self.selected_flow = self.selected_flow.saturating_sub(1);
    }

    pub fn scroll_flow_down(&mut self) {
        if self.selected_flow + 1 < self.flow_table.len() {
            self.selected_flow += 1;
        }
        if self.selected_flow + 1 >= self.flow_table.len() {
            self.flow_auto_scroll = true;
        }
    }

    pub fn page_flow_up(&mut self, n: usize) {
        self.flow_auto_scroll = false;
        self.selected_flow = self.selected_flow.saturating_sub(n);
    }

    pub fn page_flow_down(&mut self, n: usize) {
        let max = self.flow_table.len().saturating_sub(1);
        self.selected_flow = (self.selected_flow + n).min(max);
        if self.selected_flow >= max {
            self.flow_auto_scroll = true;
        }
    }

    // ── packet list navigation (within open flow) ─────────────────────────────

    pub fn scroll_pkt_up(&mut self) {
        self.pkt_auto_scroll = false;
        self.flow_pkt_sel = self.flow_pkt_sel.saturating_sub(1);
    }

    pub fn scroll_pkt_down(&mut self) {
        let max = self
            .open_flow_entry()
            .map(|e| e.packets.len().saturating_sub(1))
            .unwrap_or(0);
        if self.flow_pkt_sel < max {
            self.flow_pkt_sel += 1;
        }
        if self.flow_pkt_sel >= max {
            self.pkt_auto_scroll = true;
        }
    }

    pub fn page_pkt_up(&mut self, n: usize) {
        self.pkt_auto_scroll = false;
        self.flow_pkt_sel = self.flow_pkt_sel.saturating_sub(n);
    }

    pub fn page_pkt_down(&mut self, n: usize) {
        let max = self
            .open_flow_entry()
            .map(|e| e.packets.len().saturating_sub(1))
            .unwrap_or(0);
        self.flow_pkt_sel = (self.flow_pkt_sel + n).min(max);
        if self.flow_pkt_sel >= max {
            self.pkt_auto_scroll = true;
        }
    }

    // ── misc ──────────────────────────────────────────────────────────────────

    pub fn clear(&mut self) {
        self.flow_table.clear();
        self.selected_flow = 0;
        self.flow_scroll = 0;
        self.open_flow = None;
        self.flow_pkt_sel = 0;
        self.flow_pkt_scroll = 0;
        self.stats = StatsState::new();
        self.hostname_cache.clear();
    }

    /// Look up a hostname for the given IP from snooped DNS responses.
    pub fn resolve_ip(&self, ip: &IpAddr) -> Option<&str> {
        self.hostname_cache.get(ip).map(|s| s.as_str())
    }

    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused;
    }

    pub fn cycle_focus(&mut self) {
        self.focus = match self.focus {
            FocusPane::FlowList => FocusPane::Detail,
            FocusPane::Detail => FocusPane::FlowList,
        };
    }

    pub fn set_filter_error(&mut self, e: String) {
        self.filter_error = Some(e);
    }

    pub fn clear_filter_error(&mut self) {
        self.filter_error = None;
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::decode::{Endpoint, L3Proto, L4Proto, PacketInfo};

    fn make_packet(src_ip: [u8; 4], src_port: u16, dst_ip: [u8; 4], dst_port: u16, len: usize) -> PacketInfo {
        PacketInfo {
            ts: chrono::Local::now(),
            wire_len: len,
            encap_chain: vec!["Ethernet".into(), "IPv4".into(), "TCP".into()],
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
            l4_proto: Some(L4Proto::Tcp),
            ttl: Some(64),
            header_len: 54,
            payload_len: len.saturating_sub(54),
            tcp_flags: None,
            l7: None,
            tunnel: None,
            payload_preview: Vec::new(),
        }
    }

    #[test]
    fn test_add_packet_creates_flow() {
        let mut app = AppState::new("en0".into());
        app.add_packet(make_packet([1,2,3,4], 1000, [5,6,7,8], 80, 100));
        assert_eq!(app.flow_table.len(), 1);
        let (_, entry) = app.flow_table.get_index(0).unwrap();
        assert_eq!(entry.total_packets, 1);
        assert_eq!(entry.total_bytes, 100);
    }

    #[test]
    fn test_add_packet_same_flow_accumulates() {
        let mut app = AppState::new("en0".into());
        app.add_packet(make_packet([1,2,3,4], 1000, [5,6,7,8], 80, 100));
        app.add_packet(make_packet([1,2,3,4], 1000, [5,6,7,8], 80, 200));
        assert_eq!(app.flow_table.len(), 1);
        let (_, entry) = app.flow_table.get_index(0).unwrap();
        assert_eq!(entry.total_packets, 2);
        assert_eq!(entry.total_bytes, 300);
    }

    #[test]
    fn test_add_packet_bidirectional_same_flow() {
        let mut app = AppState::new("en0".into());
        app.add_packet(make_packet([1,2,3,4], 1000, [5,6,7,8], 80, 100));
        app.add_packet(make_packet([5,6,7,8], 80, [1,2,3,4], 1000, 50));
        assert_eq!(app.flow_table.len(), 1, "forward and reverse are the same flow");
        let (_, entry) = app.flow_table.get_index(0).unwrap();
        assert_eq!(entry.total_packets, 2);
    }

    #[test]
    fn test_add_packet_different_dst_port_new_flow() {
        let mut app = AppState::new("en0".into());
        app.add_packet(make_packet([1,2,3,4], 1000, [5,6,7,8], 80, 100));
        app.add_packet(make_packet([1,2,3,4], 1000, [5,6,7,8], 443, 100));
        assert_eq!(app.flow_table.len(), 2);
    }

    #[test]
    fn test_paused_drops_packets() {
        let mut app = AppState::new("en0".into());
        app.toggle_pause();
        app.add_packet(make_packet([1,2,3,4], 1000, [5,6,7,8], 80, 100));
        assert!(app.flow_table.is_empty());
    }

    #[test]
    fn test_open_and_close_flow() {
        let mut app = AppState::new("en0".into());
        app.add_packet(make_packet([1,2,3,4], 1000, [5,6,7,8], 80, 100));
        assert!(app.open_flow.is_none());
        app.open_selected_flow();
        assert!(app.open_flow.is_some());
        app.close_flow();
        assert!(app.open_flow.is_none());
    }

    #[test]
    fn test_selected_packet_from_open_flow() {
        let mut app = AppState::new("en0".into());
        app.add_packet(make_packet([1,2,3,4], 1000, [5,6,7,8], 80, 100));
        app.add_packet(make_packet([1,2,3,4], 1000, [5,6,7,8], 80, 200));
        app.open_selected_flow();
        app.flow_pkt_sel = 0;
        assert_eq!(app.selected_packet().unwrap().wire_len, 100);
        app.flow_pkt_sel = 1;
        assert_eq!(app.selected_packet().unwrap().wire_len, 200);
    }

    #[test]
    fn test_flow_packet_ring_capped_at_200() {
        let mut app = AppState::new("en0".into());
        for _ in 0..250 {
            app.add_packet(make_packet([1,2,3,4], 1000, [5,6,7,8], 80, 60));
        }
        let (_, entry) = app.flow_table.get_index(0).unwrap();
        assert_eq!(entry.packets.len(), 200);
        assert_eq!(entry.total_packets, 250);
    }

    #[test]
    fn test_scroll_flow_up_clamps_at_zero() {
        let mut app = AppState::new("en0".into());
        app.add_packet(make_packet([1,2,3,4], 1000, [5,6,7,8], 80, 60));
        app.selected_flow = 0;
        app.scroll_flow_up();
        assert_eq!(app.selected_flow, 0);
    }

    #[test]
    fn test_scroll_flow_down_clamps_at_last() {
        let mut app = AppState::new("en0".into());
        app.add_packet(make_packet([1,2,3,4], 1000, [5,6,7,8], 80, 60));
        app.add_packet(make_packet([1,2,3,4], 2000, [5,6,7,8], 80, 60));
        app.selected_flow = 1; // last
        app.scroll_flow_down();
        assert_eq!(app.selected_flow, 1);
    }

    #[test]
    fn test_scroll_flow_up_disables_auto_scroll() {
        let mut app = AppState::new("en0".into());
        app.add_packet(make_packet([1,2,3,4], 1000, [5,6,7,8], 80, 60));
        assert!(app.flow_auto_scroll);
        app.scroll_flow_up();
        assert!(!app.flow_auto_scroll);
    }

    #[test]
    fn test_clear_resets_all() {
        let mut app = AppState::new("en0".into());
        app.add_packet(make_packet([1,2,3,4], 1000, [5,6,7,8], 80, 100));
        app.open_selected_flow();
        app.clear();
        assert!(app.flow_table.is_empty());
        assert!(app.open_flow.is_none());
        assert_eq!(app.selected_flow, 0);
        assert_eq!(app.stats.total_packets, 0);
    }

    #[test]
    fn test_dns_response_populates_hostname_cache() {
        let mut app = AppState::new("en0".into());
        let mut p = make_packet([192,168,1,1], 53, [192,168,1,2], 5353, 200);
        p.l7 = Some(crate::decode::L7Info::Dns {
            query: "example.com".into(),
            qtype: "A".into(),
            answers: vec!["93.184.216.34".into(), "93.184.216.35".into()],
            is_response: true,
        });
        app.add_packet(p);

        let ip1: IpAddr = "93.184.216.34".parse().unwrap();
        let ip2: IpAddr = "93.184.216.35".parse().unwrap();
        assert_eq!(app.resolve_ip(&ip1), Some("example.com"));
        assert_eq!(app.resolve_ip(&ip2), Some("example.com"));
    }

    #[test]
    fn test_dns_query_does_not_populate_cache() {
        let mut app = AppState::new("en0".into());
        let mut p = make_packet([192,168,1,2], 5353, [192,168,1,1], 53, 80);
        p.l7 = Some(crate::decode::L7Info::Dns {
            query: "example.com".into(),
            qtype: "A".into(),
            answers: vec![],
            is_response: false,
        });
        app.add_packet(p);
        assert!(app.hostname_cache.is_empty());
    }

    #[test]
    fn test_flow_entry_records_canonical_ips_and_ports() {
        let mut app = AppState::new("en0".into());
        // Send the reverse-direction packet first to exercise the swap.
        app.add_packet(make_packet([8,8,8,8], 443, [192,168,1,5], 54321, 100));
        let (key, entry) = app.flow_table.get_index(0).unwrap();
        // FlowKey normalizes by string ordering — entry.src_ip must align with key.src
        let displayed_src = entry
            .src_ip
            .map(|ip| match entry.src_port {
                Some(port) => format!("{}:{}", ip, port),
                None => ip.to_string(),
            })
            .unwrap_or_default();
        assert_eq!(displayed_src, key.src);
    }

    #[test]
    fn test_cycle_focus() {
        let mut app = AppState::new("en0".into());
        assert_eq!(app.focus, FocusPane::FlowList);
        app.cycle_focus();
        assert_eq!(app.focus, FocusPane::Detail);
        app.cycle_focus();
        assert_eq!(app.focus, FocusPane::FlowList);
    }
}
