use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use super::app::App;
use crate::model::Severity;

pub fn draw(f: &mut Frame, app: &App) {
    let size = f.area();

    // Split into Header (3 lines), Main Area (flexible), Footer (3 lines)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(size);

    draw_header(f, app, chunks[0]);
    draw_main(f, app, chunks[1]);
    draw_footer(f, app, chunks[2]);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let crit_count = app.count_by_severity(Severity::Critical);
    let high_count = app.count_by_severity(Severity::High);
    let med_count = app.count_by_severity(Severity::Medium);
    let low_count = app.count_by_severity(Severity::Low);
    let total_count = app.findings.len();

    let header_spans = vec![
        Span::styled(
            " ⚡ SENTRIS ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  Interactive Security Review  │  "),
        Span::styled(
            format!("Total: {total_count}"),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  •  "),
        Span::styled(
            format!("CRITICAL: {crit_count}"),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  •  "),
        Span::styled(
            format!("HIGH: {high_count}"),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  •  "),
        Span::styled(
            format!("MEDIUM: {med_count}"),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw("  •  "),
        Span::styled(
            format!("LOW: {low_count}"),
            Style::default().fg(Color::Blue),
        ),
    ];

    let header = Paragraph::new(Line::from(header_spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(header, area);
}

fn draw_main(f: &mut Frame, app: &App, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    draw_findings_list(f, app, columns[0]);
    draw_finding_details(f, app, columns[1]);
}

fn draw_findings_list(f: &mut Frame, app: &App, area: Rect) {
    if app.findings.is_empty() {
        let empty_msg = Paragraph::new("✔ No findings detected. Repository is clean!")
            .style(Style::default().fg(Color::Green))
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .title(" Detected Secrets ")
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded),
            );
        f.render_widget(empty_msg, area);
        return;
    }

    let items: Vec<ListItem> = app
        .findings
        .iter()
        .enumerate()
        .map(|(i, finding)| {
            let is_selected = i == app.selected_index;
            let (sev_badge, sev_color) = match finding.severity {
                Severity::Critical => ("[CRIT]", Color::Red),
                Severity::High => ("[HIGH]", Color::Yellow),
                Severity::Medium => ("[MED] ", Color::Yellow),
                Severity::Low => ("[LOW] ", Color::Blue),
            };

            let pointer = if is_selected { "▶ " } else { "  " };

            let line = Line::from(vec![
                Span::styled(
                    pointer,
                    if is_selected {
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    },
                ),
                Span::styled(
                    format!("{sev_badge} "),
                    Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    &finding.rule_id,
                    if is_selected {
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Gray)
                    },
                ),
                Span::raw(" ("),
                Span::styled(
                    format!("{}:{}", finding.file_path, finding.line_number),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(")"),
            ]);

            let item_style = if is_selected {
                Style::default().bg(Color::Rgb(30, 35, 45))
            } else {
                Style::default()
            };

            ListItem::new(line).style(item_style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .title(format!(" Detected Secrets ({}) ", app.findings.len()))
            .title_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan)),
    );

    f.render_widget(list, area);
}

fn draw_finding_details(f: &mut Frame, app: &App, area: Rect) {
    let finding = match app.selected_finding() {
        Some(f) => f,
        None => {
            let empty_block = Block::default()
                .title(" Finding Details ")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded);
            f.render_widget(empty_block, area);
            return;
        }
    };

    let inner_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7), // Metadata overview
            Constraint::Min(6),    // Code context preview
            Constraint::Length(3), // Recommended action banner
        ])
        .split(area);

    // 1. Metadata Overview Block
    let (sev_color, sev_text) = match finding.severity {
        Severity::Critical => (Color::Red, "CRITICAL (Immediate Action Required)"),
        Severity::High => (Color::Yellow, "HIGH (Rotation Recommended)"),
        Severity::Medium => (Color::Yellow, "MEDIUM"),
        Severity::Low => (Color::Blue, "LOW"),
    };

    let metadata_lines = vec![
        Line::from(vec![
            Span::styled("Rule ID:     ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                &finding.rule_id,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("   Severity: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                sev_text,
                Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Target:      ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{}:{}", finding.file_path, finding.line_number),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" (Col {})", finding.column),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            Span::styled("Entropy:     ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{:.2} bits", finding.entropy),
                Style::default().fg(Color::Magenta),
            ),
            Span::styled("   Fingerprint: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                &finding.fingerprint[..16.min(finding.fingerprint.len())],
                Style::default().fg(Color::Gray),
            ),
        ]),
        Line::from(vec![
            Span::styled("Secret Mask: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                &finding.redacted_match,
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        ]),
    ];

    let meta_paragraph = Paragraph::new(metadata_lines).block(
        Block::default()
            .title(" Vulnerability Metadata ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(meta_paragraph, inner_chunks[0]);

    // 2. Code Context Viewer
    let (start_line, context_lines, target_offset) =
        app.get_code_context(&finding.file_path, finding.line_number, 3);

    let mut code_spans = Vec::new();
    for (idx, line_str) in context_lines.iter().enumerate() {
        let current_line_no = start_line + idx;
        let is_target = idx == target_offset;

        let line_prefix = if is_target { "▶ " } else { "  " };
        let line_no_str = format!("{line_prefix}{current_line_no:4} │ ");

        if is_target {
            let env_var = crate::remediator::Remediator::env_var_name_for_rule(&finding.rule_id);
            let accessor = crate::remediator::code_replacer::CodeReplacer::get_env_accessor(
                &finding.file_path,
                env_var,
            );
            code_spans.push(Line::from(vec![
                Span::styled(
                    format!("- {current_line_no:4} │ "),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    line_str,
                    Style::default()
                        .fg(Color::White)
                        .bg(Color::Rgb(60, 20, 20))
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
            code_spans.push(Line::from(vec![
                Span::styled(
                    format!("+ {current_line_no:4} │ "),
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("  [Staged Patch -> {accessor}]"),
                    Style::default()
                        .fg(Color::Green)
                        .bg(Color::Rgb(16, 48, 28))
                        .add_modifier(Modifier::BOLD),
                ),
            ]));
        } else {
            code_spans.push(Line::from(vec![
                Span::styled(line_no_str, Style::default().fg(Color::DarkGray)),
                Span::styled(line_str, Style::default().fg(Color::Cyan)),
            ]));
        }
    }

    let code_block = Paragraph::new(code_spans).wrap(Wrap { trim: false }).block(
        Block::default()
            .title(format!(" Source Context: {} ", finding.file_path))
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Yellow)),
    );
    f.render_widget(code_block, inner_chunks[1]);

    // 3. Recommended Action Banner
    let action_line = Line::from(vec![
        Span::styled(
            "🛡️  Recommended Action: ",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("Press "),
        Span::styled(
            "[r]",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" to auto-remediate with 24h safe dual-key deprecation window (0s downtime)"),
    ]);
    let action_block = Paragraph::new(action_line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Green)),
    );
    f.render_widget(action_block, inner_chunks[2]);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let footer_text = if let Some(msg) = &app.status_message {
        Line::from(vec![
            Span::styled(
                " ✔ ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                msg,
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled(
                " [↑/k] ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Up "),
            Span::styled(
                " [↓/j] ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Down  │  "),
            Span::styled(
                " [r/Enter] ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Remediate  "),
            Span::styled(
                " [b] ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Baseline  "),
            Span::styled(
                " [i] ",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("Ignore  │  "),
            Span::styled(
                " [q/Esc] ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw("Quit"),
        ])
    };

    let footer = Paragraph::new(footer_text)
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    f.render_widget(footer, area);
}
