use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

use crate::stats::StatsState;
use crate::tui::app::AppState;

pub fn render(f: &mut Frame, area: Rect, app: &AppState) {
    let block = Block::new()
        .borders(Borders::ALL)
        .title(" Flow Summary ")
        .border_style(Style::default().fg(Color::DarkGray));

    let Some((key, entry)) = app.selected_flow_entry() else {
        let para = Paragraph::new("No flows captured").block(block);
        f.render_widget(para, area);
        return;
    };

    let duration = entry.duration_secs();
    let avg_bps = if duration > 0.0 {
        StatsState::format_bps(entry.total_bytes as f64 * 8.0 / duration)
    } else {
        "—".into()
    };

    let lines = vec![
        Line::from(vec![
            label("Src  "),
            value(&key.src),
        ]),
        Line::from(vec![
            label("Dst  "),
            value(&key.dst),
        ]),
        Line::from(vec![
            label("Proto"),
            value(&key.proto),
        ]),
        Line::from(vec![
            label("Pkts "),
            value(&format!("{} ({} captured)", entry.total_packets, entry.packets.len())),
        ]),
        Line::from(vec![
            label("Bytes"),
            value(&format_bytes(entry.total_bytes)),
        ]),
        Line::from(vec![
            label("Age  "),
            value(&format_duration(duration)),
        ]),
        Line::from(vec![
            label("Avg  "),
            value(&avg_bps),
            Span::raw("   "),
            label("Now  "),
            Span::styled(
                StatsState::format_bps(entry.bps),
                Style::default().fg(Color::Cyan),
            ),
        ]),
    ];

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn format_duration(secs: f64) -> String {
    if secs < 1.0 {
        format!("{:.0}ms", secs * 1000.0)
    } else if secs < 60.0 {
        format!("{:.1}s", secs)
    } else if secs < 3600.0 {
        let m = (secs / 60.0) as u64;
        let s = (secs % 60.0) as u64;
        format!("{}m {}s", m, s)
    } else {
        let h = (secs / 3600.0) as u64;
        let m = ((secs % 3600.0) / 60.0) as u64;
        format!("{}h {}m", h, m)
    }
}

fn format_bytes(b: u64) -> String {
    if b >= 1_073_741_824 {
        format!("{:.2} GB", b as f64 / 1_073_741_824.0)
    } else if b >= 1_048_576 {
        format!("{:.2} MB", b as f64 / 1_048_576.0)
    } else if b >= 1_024 {
        format!("{:.2} KB", b as f64 / 1_024.0)
    } else {
        format!("{} B", b)
    }
}

fn label(s: &str) -> Span<'static> {
    Span::styled(s.to_string(), Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD))
}

fn value(s: &str) -> Span<'static> {
    Span::styled(s.to_string(), Style::default().fg(Color::White))
}
