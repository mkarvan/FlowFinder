pub mod app;
pub mod events;
pub mod widgets;

use std::io;
use std::time::Duration;

use crossterm::{
    event::{self, Event},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crossbeam_channel::{Receiver, Sender};

use crate::decode::RawPacket;
use app::AppState;
use events::Action;

pub fn run(
    interface_name: String,
    raw_rx: Receiver<RawPacket>,
    filter_tx: Sender<Option<String>>,
    err_rx: Receiver<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = AppState::new(interface_name);
    let result = run_loop(&mut terminal, &mut app, raw_rx, filter_tx, err_rx);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut AppState,
    raw_rx: Receiver<RawPacket>,
    filter_tx: Sender<Option<String>>,
    err_rx: Receiver<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        // Drain available packets (non-blocking)
        loop {
            match raw_rx.try_recv() {
                Ok(raw) => {
                    let info = crate::decode::decode(&raw);
                    app.add_packet(info);
                }
                Err(crossbeam_channel::TryRecvError::Empty) => break,
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    // Capture thread finished; drain is done; mark paused for display
                    break;
                }
            }
        }

        // Pick up any BPF filter errors from the capture thread
        while let Ok(e) = err_rx.try_recv() {
            app.set_filter_error(e);
        }

        app.tick();

        terminal.draw(|f| render(f, app))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                match events::handle_key(app, key, &filter_tx) {
                    Action::Quit => break,
                    Action::Continue => {}
                }
            }
        }
    }
    Ok(())
}

fn render(f: &mut Frame, app: &mut AppState) {
    let area = f.area();

    // Split off 1-line status bar at the bottom
    let [main_area, status_area] =
        Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(area);

    // Left 65% / Right 35%
    let [left_area, right_area] =
        Layout::horizontal([Constraint::Percentage(65), Constraint::Percentage(35)])
            .areas(main_area);

    // Left: top list pane (55%) + bottom detail/summary pane (45%)
    let [list_area, bottom_area] =
        Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)])
            .areas(left_area);

    // Right: bandwidth (top 35%) + protocol chart (bottom 65%)
    let [bandwidth_area, proto_area] =
        Layout::vertical([Constraint::Percentage(35), Constraint::Percentage(65)])
            .areas(right_area);

    // Top-left: flow list or per-flow packet list depending on drill-down state
    if app.open_flow.is_some() {
        widgets::flow_packets::render(f, list_area, app);
        widgets::flow_detail::render(f, bottom_area, app);
    } else {
        widgets::flow_list::render(f, list_area, app);
        widgets::flow_summary::render(f, bottom_area, app);
    }

    widgets::bandwidth::render(f, bandwidth_area, app);
    widgets::protocol_chart::render(f, proto_area, app);
    render_status(f, status_area, app);
}

fn render_status(f: &mut Frame, area: ratatui::layout::Rect, app: &AppState) {
    let filter_str = if app.filter_editing {
        format!(
            " filter: {}▌",
            app.filter_input.as_deref().unwrap_or("")
        )
    } else if let Some(ref flt) = app.filter_input {
        if !flt.is_empty() {
            format!(" filter: {}", flt)
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let nav_hint = if app.open_flow.is_some() {
        Span::styled("[esc] back ", Style::default().fg(Color::DarkGray))
    } else {
        Span::styled("[↵] open ", Style::default().fg(Color::DarkGray))
    };

    let mut spans = vec![
        Span::styled(" [q]uit ", Style::default().fg(Color::DarkGray)),
        Span::styled("[p]ause ", Style::default().fg(Color::DarkGray)),
        nav_hint,
        Span::styled("[f]ilter ", Style::default().fg(Color::DarkGray)),
        Span::styled("[c]lear ", Style::default().fg(Color::DarkGray)),
        Span::styled(" │ ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("iface: {} ", app.interface_name),
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(
            format!("pkts: {} ", app.stats.total_packets),
            Style::default().fg(Color::Green),
        ),
        Span::styled(
            format!("bytes: {} ", format_bytes(app.stats.total_bytes)),
            Style::default().fg(Color::Yellow),
        ),
        Span::styled(filter_str, Style::default().fg(Color::Magenta)),
    ];

    if let Some(ref err) = app.filter_error {
        spans.push(Span::styled(
            format!(" [BPF error: {}]", err),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
    } else if app.paused {
        spans.push(Span::styled(
            " [PAUSED]",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
    }

    let status = Line::from(spans);

    let para = Paragraph::new(status).style(Style::default().bg(Color::Black));
    f.render_widget(para, area);
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
