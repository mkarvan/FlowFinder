use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
};

use crate::stats::StatsState;
use crate::tui::app::{AppState, FocusPane};

pub fn render(f: &mut Frame, area: Rect, app: &mut AppState) {
    let focused = app.focus == FocusPane::FlowList && app.open_flow.is_none();
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let title = format!(
        " Flows ({}) {} ",
        app.flow_table.len(),
        if app.paused { "[PAUSED]" } else { "" }
    );

    let header = Row::new(vec![
        Cell::from("Src → Dst").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Cell::from("Proto").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Cell::from("Pkts").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Cell::from("Bytes").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Cell::from("Rate").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
        Cell::from("Age").style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)),
    ])
    .style(Style::default().bg(Color::DarkGray));

    let open_key = app.open_flow.clone();

    let rows: Vec<Row> = app
        .flow_table
        .iter()
        .map(|(key, entry)| {
            let src_label = endpoint_label(
                entry.src_ip.as_ref().and_then(|ip| app.hostname_cache.get(ip)).map(|s| s.as_str()),
                entry.src_port,
                &key.src,
            );
            let dst_label = endpoint_label(
                entry.dst_ip.as_ref().and_then(|ip| app.hostname_cache.get(ip)).map(|s| s.as_str()),
                entry.dst_port,
                &key.dst,
            );
            let src_dst = format!("{} → {}", src_label, dst_label);
            let rate = StatsState::format_bps(entry.bps);
            let age = format_age(entry.duration_secs());
            let bytes = format_bytes(entry.total_bytes);
            let proto_style = proto_color(&key.proto);
            let is_open = open_key.as_ref() == Some(key);

            Row::new(vec![
                Cell::from(src_dst).style(Style::default().fg(Color::White)),
                Cell::from(key.proto.clone()).style(proto_style),
                Cell::from(entry.total_packets.to_string())
                    .style(Style::default().fg(Color::Green)),
                Cell::from(bytes).style(Style::default().fg(Color::Yellow)),
                Cell::from(rate).style(Style::default().fg(Color::Cyan)),
                Cell::from(age).style(Style::default().fg(Color::DarkGray)),
            ])
            .style(if is_open {
                Style::default().add_modifier(Modifier::ITALIC)
            } else {
                Style::default()
            })
        })
        .collect();

    let widths = [
        Constraint::Fill(1),
        Constraint::Length(8),
        Constraint::Length(7),
        Constraint::Length(8),
        Constraint::Length(11),
        Constraint::Length(6),
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

    let visible_rows = area.height.saturating_sub(3) as usize;
    let selected = app.selected_flow;

    if selected < app.flow_scroll {
        app.flow_scroll = selected;
    } else if selected >= app.flow_scroll + visible_rows {
        app.flow_scroll = selected + 1 - visible_rows;
    }

    let mut state = TableState::default();
    state.select(Some(selected));
    *state.offset_mut() = app.flow_scroll;

    f.render_stateful_widget(table, area, &mut state);
}

fn endpoint_label(host: Option<&str>, port: Option<u16>, fallback: &str) -> String {
    match (host, port) {
        (Some(h), Some(p)) => format!("{}:{}", h, p),
        (Some(h), None) => h.to_string(),
        _ => fallback.to_string(),
    }
}

fn format_age(secs: f64) -> String {
    if secs < 1.0 {
        format!("{:.0}ms", secs * 1000.0)
    } else if secs < 60.0 {
        format!("{:.0}s", secs)
    } else if secs < 3600.0 {
        format!("{:.0}m", secs / 60.0)
    } else {
        format!("{:.0}h", secs / 3600.0)
    }
}

fn format_bytes(b: u64) -> String {
    if b >= 1_073_741_824 {
        format!("{:.1}GB", b as f64 / 1_073_741_824.0)
    } else if b >= 1_048_576 {
        format!("{:.1}MB", b as f64 / 1_048_576.0)
    } else if b >= 1_024 {
        format!("{:.1}KB", b as f64 / 1_024.0)
    } else {
        format!("{}B", b)
    }
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
