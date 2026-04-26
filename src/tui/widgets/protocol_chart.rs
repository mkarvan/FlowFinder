use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Style},
    widgets::{Bar, BarChart, BarGroup, Block, Borders},
};

use crate::tui::app::AppState;

pub fn render(f: &mut Frame, area: Rect, app: &AppState) {
    let block = Block::new()
        .borders(Borders::ALL)
        .title(" Protocols ")
        .border_style(Style::default().fg(Color::DarkGray));

    let dist = app.stats.proto_distribution();
    let total: u64 = dist.iter().map(|(_, c)| c).sum();

    if total == 0 {
        f.render_widget(block, area);
        return;
    }

    let colors = [
        Color::Cyan,
        Color::Blue,
        Color::Magenta,
        Color::LightGreen,
        Color::Yellow,
        Color::Red,
        Color::LightCyan,
        Color::LightBlue,
    ];

    let bars: Vec<Bar> = dist
        .iter()
        .take(8)
        .enumerate()
        .map(|(i, (name, count))| {
            let pct = (*count * 100) / total;
            let color = colors[i % colors.len()];
            Bar::default()
                .value(pct)
                .label(ratatui::text::Line::from(name.as_str()))
                .value_style(Style::default().fg(color))
                .style(Style::default().fg(color))
        })
        .collect();

    let group = BarGroup::default().bars(&bars);

    let chart = BarChart::default()
        .block(block)
        .data(group)
        .bar_width(3)
        .bar_gap(1)
        .max(100);

    f.render_widget(chart, area);
}
