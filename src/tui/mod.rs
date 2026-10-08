pub mod app;
pub mod ui;

use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::{self, IsTerminal};
use std::time::Duration;

pub use self::app::{App, TuiAction};
use crate::error::SentrisError;
use crate::model::Finding;

/// Terminal cleanup guard to ensure terminal state is restored on exit or panic
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

/// Runs the interactive terminal UI review session for the given detected findings
pub fn run_interactive_review(findings: Vec<Finding>) -> Result<Option<TuiAction>, SentrisError> {
    if !io::stdout().is_terminal() {
        eprintln!("Interactive review requires a TTY terminal. Use 'sentris scan' or 'sentris remediate' in non-interactive CI/CD.");
        return Ok(None);
    }

    if findings.is_empty() {
        println!("✔ No findings detected to review. Repository is clean!");
        return Ok(None);
    }

    // Initialize raw terminal mode and alternate screen
    enable_raw_mode()
        .map_err(|e| SentrisError::Config(format!("Failed to enable raw mode: {e}")))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)
        .map_err(|e| SentrisError::Config(format!("Failed to enter alternate screen: {e}")))?;

    // Guard will automatically restore terminal on exit
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)
        .map_err(|e| SentrisError::Config(format!("Failed to initialize terminal: {e}")))?;

    let mut app = App::new(findings);

    loop {
        terminal
            .draw(|f| ui::draw(f, &app))
            .map_err(|e| SentrisError::Config(format!("Failed to draw TUI frame: {e}")))?;

        if app.should_quit {
            break;
        }

        if event::poll(Duration::from_millis(100))
            .map_err(|e| SentrisError::Config(format!("Event poll error: {e}")))?
        {
            if let Event::Key(key) =
                event::read().map_err(|e| SentrisError::Config(format!("Event read error: {e}")))?
            {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            app.should_quit = true;
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            app.select_previous();
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            app.select_next();
                        }
                        KeyCode::Enter | KeyCode::Char('r') => {
                            app.trigger_remediate();
                        }
                        KeyCode::Char('b') => {
                            app.trigger_baseline();
                        }
                        KeyCode::Char('i') => {
                            app.trigger_ignore();
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(app.pending_action)
}

#[cfg(test)]
mod tests {
    use super::app::{App, TuiAction};
    use crate::model::{Finding, Severity};

    fn make_test_finding(rule_id: &str, line: usize, sev: Severity) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            description: "Test description".to_string(),
            severity: sev,
            file_path: "src/sample.rs".to_string(),
            line_number: line,
            column: 10,
            redacted_match: "sk_live_***".to_string(),
            entropy: 4.5,
            fingerprint: format!("fp_{rule_id}_{line}"),
            commit_hash: None,
        }
    }

    #[test]
    fn test_app_navigation_and_counts() {
        let f1 = make_test_finding("stripe-key", 10, Severity::Critical);
        let f2 = make_test_finding("aws-key", 20, Severity::High);
        let f3 = make_test_finding("github-pat", 30, Severity::Medium);

        let mut app = App::new(vec![f1, f2, f3]);

        assert_eq!(app.count_by_severity(Severity::Critical), 1);
        assert_eq!(app.count_by_severity(Severity::High), 1);
        assert_eq!(app.count_by_severity(Severity::Medium), 1);
        assert_eq!(app.count_by_severity(Severity::Low), 0);

        assert_eq!(app.selected_index, 0);
        app.select_next();
        assert_eq!(app.selected_index, 1);
        app.select_next();
        assert_eq!(app.selected_index, 2);
        app.select_next();
        assert_eq!(app.selected_index, 0); // wrap around

        app.select_previous();
        assert_eq!(app.selected_index, 2); // wrap around backward
    }

    #[test]
    fn test_app_actions() {
        let f1 = make_test_finding("stripe-key", 10, Severity::Critical);
        let mut app = App::new(vec![f1]);

        app.trigger_baseline();
        assert_eq!(app.pending_action, Some(TuiAction::AddToBaseline(0)));

        app.trigger_ignore();
        assert_eq!(app.pending_action, Some(TuiAction::IgnoreFinding(0)));

        app.trigger_remediate();
        assert_eq!(app.pending_action, Some(TuiAction::Remediate(0)));
        assert!(app.should_quit);
    }
}
