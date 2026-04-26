use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
};

use crate::decode::PacketInfo;
use crate::tui::app::{AppState, FocusPane};

pub fn render(f: &mut Frame, area: Rect, app: &mut AppState) {
    let focused = app.focus == FocusPane::PacketList;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let header = Row::new(vec![
        Cell::from("Time").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Src").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Dst").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Proto").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Len").style(Style::default().add_modifier(Modifier::BOLD)),
        Cell::from("Info").style(Style::default().add_modifier(Modifier::BOLD)),
    ])
    .style(Style::default().bg(Color::DarkGray));

    let rows: Vec<Row> = app
        .packets
        .iter()
        .map(|p| make_row(p))
        .collect();

    let widths = [
        ratatui::layout::Constraint::Length(12),
        ratatui::layout::Constraint::Length(22),
        ratatui::layout::Constraint::Length(22),
        ratatui::layout::Constraint::Length(8),
        ratatui::layout::Constraint::Length(6),
        ratatui::layout::Constraint::Fill(1),
    ];

    let title = format!(
        " Packets ({}) {} ",
        app.packets.len(),
        if app.paused { "[PAUSED]" } else { "" }
    );

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::new()
                .borders(Borders::ALL)
                .title(title)
                .border_style(border_style),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    let visible_rows = area.height.saturating_sub(3) as usize; // header + borders
    let selected = app.selected;

    // Adjust scroll offset to keep selected visible
    if selected < app.scroll_offset {
        app.scroll_offset = selected;
    } else if selected >= app.scroll_offset + visible_rows {
        app.scroll_offset = selected + 1 - visible_rows;
    }

    let mut state = TableState::default();
    state.select(Some(selected));
    *state.offset_mut() = app.scroll_offset;

    f.render_stateful_widget(table, area, &mut state);
}

fn make_row(p: &PacketInfo) -> Row<'_> {
    let time = p.ts.format("%H:%M:%S%.3f").to_string();
    let src = truncate(&p.src.display(), 21);
    let dst = truncate(&p.dst.display(), 21);
    let proto = p.proto_label();
    let len = p.wire_len.to_string();
    let info = packet_info_str(p);

    let proto_style = proto_color(&proto);

    Row::new(vec![
        Cell::from(time).style(Style::default().fg(Color::DarkGray)),
        Cell::from(src).style(Style::default().fg(Color::Green)),
        Cell::from(dst).style(Style::default().fg(Color::Yellow)),
        Cell::from(proto).style(proto_style),
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
        if !f.is_empty() { return f; }
    }
    format!("{} bytes", p.payload_len)
}

fn proto_color(proto: &str) -> Style {
    match proto {
        "TCP" => Style::default().fg(Color::Cyan),
        "UDP" => Style::default().fg(Color::Blue),
        "DNS" => Style::default().fg(Color::Magenta),
        "TLS" => Style::default().fg(Color::LightGreen),
        "HTTP" => Style::default().fg(Color::LightYellow),
        "HTTP/2" => Style::default().fg(Color::LightYellow),
        "QUIC" => Style::default().fg(Color::LightMagenta),
        "ICMP" | "ICMPv6" => Style::default().fg(Color::Red),
        "ARP" => Style::default().fg(Color::LightCyan),
        "DHCP" => Style::default().fg(Color::LightBlue),
        _ => Style::default().fg(Color::White),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}
