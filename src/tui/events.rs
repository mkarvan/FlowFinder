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
        KeyCode::Char('G') => {
            app.auto_scroll = true;
            app.selected = app.packets.len().saturating_sub(1);
        }
        KeyCode::Char('g') => {
            app.auto_scroll = false;
            app.selected = 0;
        }
        KeyCode::Up | KeyCode::Char('k') => app.scroll_up(),
        KeyCode::Down | KeyCode::Char('j') => app.scroll_down(),
        KeyCode::PageUp => app.page_up(20),
        KeyCode::PageDown => app.page_down(20),
        KeyCode::Home => {
            app.auto_scroll = false;
            app.selected = 0;
        }
        KeyCode::End => {
            app.auto_scroll = true;
            app.selected = app.packets.len().saturating_sub(1);
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
