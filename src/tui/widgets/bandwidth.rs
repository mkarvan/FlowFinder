use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Paragraph, Sparkline},
};

use crate::stats::StatsState;
use crate::tui::app::AppState;

pub fn render(f: &mut Frame, area: Rect, app: &AppState) {
    let block = Block::new()
        .borders(Borders::ALL)
        .title(" Bandwidth ")
        .border_style(Style::default().fg(Color::DarkGray));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 2 {
        return;
    }

    let [sparkline_area, label_area] =
        Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(inner);

    let data = app.stats.bw_sparkline_data();
    let sparkline = Sparkline::default()
        .data(&data)
        .style(Style::default().fg(Color::Green));
    f.render_widget(sparkline, sparkline_area);

    let current = StatsState::format_bps(app.stats.current_bps);
    let peak = StatsState::format_bps(app.stats.peak_bps);
    let label_text = format!("{} (peak {})", current, peak);
    let label = Paragraph::new(Line::from(label_text))
        .style(Style::default().fg(Color::Gray));
    f.render_widget(label, label_area);
}
