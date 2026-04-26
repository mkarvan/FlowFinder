use crossbeam_channel::Sender;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::app::AppState;

pub enum Action {
    Quit,
    Continue,
}

pub fn handle_key(app: &mut AppState, key: KeyEvent, filter_tx: &Sender<Option<String>>) -> Action {
    if app.filter_editing {
        return handle_filter_input(app, key, filter_tx);
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Char('Q') => return Action::Quit,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            return Action::Quit;
        }
        KeyCode::Char('p') | KeyCode::Char(' ') => app.toggle_pause(),
        KeyCode::Char('c') => app.clear(),
        KeyCode::Tab => app.cycle_focus(),
        KeyCode::Char('f') => {
            app.filter_editing = true;
            if app.filter_input.is_none() {
                app.filter_input = Some(String::new());
            }
        }
        KeyCode::Esc => {
            if app.open_flow.is_some() {
                app.close_flow();
            }
        }
        KeyCode::Enter => {
            if app.open_flow.is_none() {
                app.open_selected_flow();
            }
        }
        KeyCode::Char('G') => {
            if app.open_flow.is_some() {
                let max = app
                    .open_flow_entry()
                    .map(|e| e.packets.len().saturating_sub(1))
                    .unwrap_or(0);
                app.flow_pkt_sel = max;
                app.pkt_auto_scroll = true;
            } else {
                app.selected_flow = app.flow_table.len().saturating_sub(1);
                app.flow_auto_scroll = true;
            }
        }
        KeyCode::Char('g') => {
            if app.open_flow.is_some() {
                app.flow_pkt_sel = 0;
                app.pkt_auto_scroll = false;
            } else {
                app.selected_flow = 0;
                app.flow_auto_scroll = false;
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if app.open_flow.is_some() {
                app.scroll_pkt_up();
            } else {
                app.scroll_flow_up();
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.open_flow.is_some() {
                app.scroll_pkt_down();
            } else {
                app.scroll_flow_down();
            }
        }
        KeyCode::PageUp => {
            if app.open_flow.is_some() {
                app.page_pkt_up(20);
            } else {
                app.page_flow_up(20);
            }
        }
        KeyCode::PageDown => {
            if app.open_flow.is_some() {
                app.page_pkt_down(20);
            } else {
                app.page_flow_down(20);
            }
        }
        KeyCode::Home => {
            if app.open_flow.is_some() {
                app.flow_pkt_sel = 0;
                app.pkt_auto_scroll = false;
            } else {
                app.selected_flow = 0;
                app.flow_auto_scroll = false;
            }
        }
        KeyCode::End => {
            if app.open_flow.is_some() {
                let max = app
                    .open_flow_entry()
                    .map(|e| e.packets.len().saturating_sub(1))
                    .unwrap_or(0);
                app.flow_pkt_sel = max;
                app.pkt_auto_scroll = true;
            } else {
                app.selected_flow = app.flow_table.len().saturating_sub(1);
                app.flow_auto_scroll = true;
            }
        }
        _ => {}
    }
    Action::Continue
}

fn handle_filter_input(app: &mut AppState, key: KeyEvent, filter_tx: &Sender<Option<String>>) -> Action {
    match key.code {
        KeyCode::Esc => {
            app.filter_editing = false;
        }
        KeyCode::Enter => {
            app.filter_editing = false;
            app.clear_filter_error();
            let expr = app.filter_input.as_ref().and_then(|s| {
                if s.is_empty() { None } else { Some(s.clone()) }
            });
            let _ = filter_tx.send(expr);
        }
        KeyCode::Backspace => {
            if let Some(ref mut s) = app.filter_input {
                s.pop();
            }
        }
        KeyCode::Char(c) => {
            if let Some(ref mut s) = app.filter_input {
                s.push(c);
            }
        }
        _ => {}
    }
    Action::Continue
}
