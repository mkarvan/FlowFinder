use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
};

use crate::decode::PacketInfo;
use crate::tui::app::{AppState, FocusPane};

pub fn render(f: &mut Frame, area: Rect, app: &mut AppState) {
    let focused = app.focus == FocusPane::FlowList && app.open_flow.is_some();
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let Some(flow_key) = app.open_flow.clone() else {
        return;
    };

    let Some(entry) = app.flow_table.get(&flow_key) else {
        return;
    };

    let title = format!(
        " {} → {} | {} packets (showing {}) ",
        flow_key.src,
        flow_key.dst,
        entry.total_packets,
        entry.packets.len(),
    );

    let header = Row::new(vec![
        Cell::from("Time").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Cell::from("Dir").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Cell::from("Len").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Cell::from("Info").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
    ])
    .style(Style::default().bg(Color::DarkGray));

    let flow_src = flow_key.src.clone();
    let rows: Vec<Row> = entry
        .packets
        .iter()
        .map(|p| make_row(p, &flow_src))
        .collect();

    let widths = [
        Constraint::Length(16),
        Constraint::Length(3),
        Constraint::Length(6),
        Constraint::Fill(1),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::new()
                .borders(Borders::ALL)
                .title(title)
                .border_style(border_style),
        )
        .row_highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");

    let total_pkts = entry.packets.len();
    let visible_rows = area.height.saturating_sub(3) as usize;
    let selected = app.flow_pkt_sel.min(total_pkts.saturating_sub(1));

    if selected < app.flow_pkt_scroll {
        app.flow_pkt_scroll = selected;
    } else if selected >= app.flow_pkt_scroll + visible_rows {
        app.flow_pkt_scroll = selected + 1 - visible_rows;
    }

    let mut state = TableState::default();
    state.select(if total_pkts > 0 { Some(selected) } else { None });
    *state.offset_mut() = app.flow_pkt_scroll;

    f.render_stateful_widget(table, area, &mut state);
}

fn make_row<'a>(p: &'a PacketInfo, flow_src: &str) -> Row<'a> {
    let time = p.ts.format("%H:%M:%S%.3f").to_string();
    let dir = if p.src.display() == flow_src { "→" } else { "←" };
    let len = p.wire_len.to_string();
    let info = packet_info_str(p);

    let dir_style = if dir == "→" {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::Yellow)
    };

    Row::new(vec![
        Cell::from(time).style(Style::default().fg(Color::DarkGray)),
        Cell::from(dir).style(dir_style),
        Cell::from(len).style(Style::default().fg(Color::Gray)),
        Cell::from(info),
    ])
}

fn packet_info_str(p: &PacketInfo) -> String {
    if let Some(ref l7) = p.l7 {
        return l7.summary();
    }
    if let Some(ref flags) = p.tcp_flags {
        let f = flags.display();
        if !f.is_empty() {
            return f;
        }
    }
    format!("{} bytes payload", p.payload_len)
}
