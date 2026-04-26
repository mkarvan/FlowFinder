use std::collections::VecDeque;

use crate::decode::PacketInfo;
use crate::stats::StatsState;

const MAX_PACKETS: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusPane {
    PacketList,
    FlowDetail,
}

pub struct AppState {
    pub packets: VecDeque<PacketInfo>,
    pub selected: usize,
    pub scroll_offset: usize,
    pub stats: StatsState,
    pub paused: bool,
    pub focus: FocusPane,
    pub filter_input: Option<String>,
    pub filter_editing: bool,
    pub filter_error: Option<String>,
    pub interface_name: String,
    pub auto_scroll: bool,
}

impl AppState {
    pub fn new(interface_name: String) -> Self {
        AppState {
            packets: VecDeque::with_capacity(MAX_PACKETS),
            selected: 0,
            scroll_offset: 0,
            stats: StatsState::new(),
            paused: false,
            focus: FocusPane::PacketList,
            filter_input: None,
            filter_editing: false,
            filter_error: None,
            interface_name,
            auto_scroll: true,
        }
    }

    pub fn set_filter_error(&mut self, e: String) {
        self.filter_error = Some(e);
    }

    pub fn clear_filter_error(&mut self) {
        self.filter_error = None;
    }

    pub fn add_packet(&mut self, p: PacketInfo) {
        if self.paused {
            return;
        }
        self.stats.ingest(&p);
        if self.packets.len() >= MAX_PACKETS {
            self.packets.pop_front();
            if self.selected > 0 {
                self.selected -= 1;
            }
        }
        self.packets.push_back(p);
        if self.auto_scroll {
            self.selected = self.packets.len().saturating_sub(1);
        }
    }

    pub fn tick(&mut self) {
        self.stats.tick();
    }

    pub fn scroll_up(&mut self) {
        self.auto_scroll = false;
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn scroll_down(&mut self) {
        if self.selected + 1 < self.packets.len() {
            self.selected += 1;
        }
        // Re-enable auto-scroll if at bottom
        if self.selected + 1 >= self.packets.len() {
            self.auto_scroll = true;
        }
    }

    pub fn page_up(&mut self, page_size: usize) {
        self.auto_scroll = false;
        self.selected = self.selected.saturating_sub(page_size);
    }

    pub fn page_down(&mut self, page_size: usize) {
        let new = (self.selected + page_size).min(self.packets.len().saturating_sub(1));
        self.selected = new;
        if self.selected + 1 >= self.packets.len() {
            self.auto_scroll = true;
        }
    }

    pub fn selected_packet(&self) -> Option<&PacketInfo> {
        self.packets.get(self.selected)
    }

    pub fn clear(&mut self) {
        self.packets.clear();
        self.selected = 0;
        self.scroll_offset = 0;
        self.stats = StatsState::new();
    }

    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused;
    }

    pub fn cycle_focus(&mut self) {
        self.focus = match self.focus {
            FocusPane::PacketList => FocusPane::FlowDetail,
            FocusPane::FlowDetail => FocusPane::PacketList,
        };
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::decode::{Endpoint, L3Proto, L4Proto, PacketInfo};

    fn dummy_packet(len: usize) -> PacketInfo {
        PacketInfo {
            ts: chrono::Local::now(),
            wire_len: len,
            encap_chain: vec!["Ethernet".into(), "IPv4".into(), "TCP".into()],
            src: Endpoint {
                ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                port: Some(1000),
                mac: None,
            },
            dst: Endpoint {
                ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                port: Some(443),
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
        }
    }

    fn app_with_packets(n: usize) -> AppState {
        let mut app = AppState::new("test0".to_string());
        for i in 0..n {
            app.add_packet(dummy_packet(60 + i));
        }
        app
    }

    // ── add_packet / basic state ──────────────────────────────────────────────

    #[test]
    fn test_add_packet_increases_len() {
        let mut app = AppState::new("en0".to_string());
        assert_eq!(app.packets.len(), 0);
        app.add_packet(dummy_packet(100));
        assert_eq!(app.packets.len(), 1);
    }

    #[test]
    fn test_add_packet_updates_stats() {
        let mut app = AppState::new("en0".to_string());
        app.add_packet(dummy_packet(200));
        assert_eq!(app.stats.total_packets, 1);
        assert_eq!(app.stats.total_bytes, 200);
    }

    #[test]
    fn test_add_packet_auto_scroll_follows_bottom() {
        let mut app = app_with_packets(5);
        assert_eq!(app.selected, 4, "auto-scroll: selected should be last index");
    }

    #[test]
    fn test_add_packet_paused_drops_packet() {
        let mut app = AppState::new("en0".to_string());
        app.toggle_pause();
        app.add_packet(dummy_packet(100));
        assert_eq!(app.packets.len(), 0, "paused app must not accept packets");
    }

    #[test]
    fn test_add_packet_ring_buffer_evicts_oldest() {
        let mut app = AppState::new("en0".to_string());
        // Fill beyond MAX_PACKETS (10_000)
        for i in 0..10_001 {
            app.add_packet(dummy_packet(60 + (i % 100)));
        }
        assert_eq!(app.packets.len(), 10_000);
    }

    // ── scrolling ─────────────────────────────────────────────────────────────

    #[test]
    fn test_scroll_up_decrements_selected() {
        let mut app = app_with_packets(10);
        assert_eq!(app.selected, 9); // auto-scroll at bottom
        app.scroll_up();
        assert_eq!(app.selected, 8);
    }

    #[test]
    fn test_scroll_up_clamps_at_zero() {
        let mut app = app_with_packets(5);
        app.selected = 0;
        app.scroll_up();
        assert_eq!(app.selected, 0, "cannot scroll above index 0");
    }

    #[test]
    fn test_scroll_down_increments_selected() {
        let mut app = app_with_packets(10);
        app.selected = 0;
        app.scroll_down();
        assert_eq!(app.selected, 1);
    }

    #[test]
    fn test_scroll_down_clamps_at_last() {
        let mut app = app_with_packets(5);
        // already at last (auto-scroll)
        app.scroll_down();
        assert_eq!(app.selected, 4, "cannot scroll past last packet");
    }

    #[test]
    fn test_scroll_up_disables_auto_scroll() {
        let mut app = app_with_packets(10);
        assert!(app.auto_scroll);
        app.scroll_up();
        assert!(!app.auto_scroll, "scrolling up must disable auto-scroll");
    }

    #[test]
    fn test_scroll_down_to_bottom_reenables_auto_scroll() {
        let mut app = app_with_packets(5);
        app.scroll_up(); // disables auto-scroll, moves to index 3
        app.scroll_down(); // back to index 4 (bottom)
        assert!(app.auto_scroll, "reaching the bottom must re-enable auto-scroll");
    }

    #[test]
    fn test_page_up_moves_by_page() {
        let mut app = app_with_packets(50);
        app.selected = 40;
        app.auto_scroll = false;
        app.page_up(20);
        assert_eq!(app.selected, 20);
    }

    #[test]
    fn test_page_down_moves_by_page() {
        let mut app = app_with_packets(50);
        app.selected = 0;
        app.auto_scroll = false;
        app.page_down(20);
        assert_eq!(app.selected, 20);
    }

    #[test]
    fn test_page_up_clamps_at_zero() {
        let mut app = app_with_packets(10);
        app.selected = 3;
        app.page_up(20); // would go below 0
        assert_eq!(app.selected, 0);
    }

    // ── pause / clear ─────────────────────────────────────────────────────────

    #[test]
    fn test_toggle_pause_flips_state() {
        let mut app = AppState::new("en0".to_string());
        assert!(!app.paused);
        app.toggle_pause();
        assert!(app.paused);
        app.toggle_pause();
        assert!(!app.paused);
    }

    #[test]
    fn test_clear_resets_packets_and_stats() {
        let mut app = app_with_packets(20);
        app.clear();
        assert_eq!(app.packets.len(), 0);
        assert_eq!(app.selected, 0);
        assert_eq!(app.stats.total_packets, 0);
        assert_eq!(app.stats.total_bytes, 0);
    }

    #[test]
    fn test_clear_allows_new_packets_after() {
        let mut app = app_with_packets(5);
        app.clear();
        app.add_packet(dummy_packet(100));
        assert_eq!(app.packets.len(), 1);
    }

    // ── focus cycling ─────────────────────────────────────────────────────────

    #[test]
    fn test_cycle_focus_toggles() {
        let mut app = AppState::new("en0".to_string());
        assert_eq!(app.focus, FocusPane::PacketList);
        app.cycle_focus();
        assert_eq!(app.focus, FocusPane::FlowDetail);
        app.cycle_focus();
        assert_eq!(app.focus, FocusPane::PacketList);
    }

    // ── selected_packet ───────────────────────────────────────────────────────

    #[test]
    fn test_selected_packet_returns_correct_entry() {
        let mut app = AppState::new("en0".to_string());
        app.add_packet(dummy_packet(100));
        app.add_packet(dummy_packet(200));
        app.selected = 0;
        assert_eq!(app.selected_packet().unwrap().wire_len, 100);
        app.selected = 1;
        assert_eq!(app.selected_packet().unwrap().wire_len, 200);
    }

    #[test]
    fn test_selected_packet_none_on_empty() {
        let app = AppState::new("en0".to_string());
        assert!(app.selected_packet().is_none());
    }
}
