use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::model::{Finding, Severity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuiAction {
    Remediate(usize),
    AddToBaseline(usize),
    IgnoreFinding(usize),
}

pub struct App {
    pub findings: Vec<Finding>,
    pub selected_index: usize,
    pub file_cache: HashMap<String, Vec<String>>,
    pub status_message: Option<String>,
    pub should_quit: bool,
    pub pending_action: Option<TuiAction>,
}

impl App {
    pub fn new(findings: Vec<Finding>) -> Self {
        let mut app = Self {
            findings,
            selected_index: 0,
            file_cache: HashMap::new(),
            status_message: None,
            should_quit: false,
            pending_action: None,
        };
        app.preload_file_cache();
        app
    }

    /// Pre-caches file lines for selected finding code previews
    fn preload_file_cache(&mut self) {
        for finding in &self.findings {
            if !self.file_cache.contains_key(&finding.file_path) {
                let path = Path::new(&finding.file_path);
                if path.is_file() {
                    if let Ok(content) = fs::read_to_string(path) {
                        let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
                        self.file_cache.insert(finding.file_path.clone(), lines);
                    }
                }
            }
        }
    }

    pub fn selected_finding(&self) -> Option<&Finding> {
        self.findings.get(self.selected_index)
    }

    pub fn select_next(&mut self) {
        if !self.findings.is_empty() {
            if self.selected_index + 1 < self.findings.len() {
                self.selected_index += 1;
            } else {
                self.selected_index = 0; // wrap around
            }
        }
    }

    pub fn select_previous(&mut self) {
        if !self.findings.is_empty() {
            if self.selected_index > 0 {
                self.selected_index -= 1;
            } else {
                self.selected_index = self.findings.len() - 1; // wrap around
            }
        }
    }

    pub fn trigger_remediate(&mut self) {
        if !self.findings.is_empty() {
            self.pending_action = Some(TuiAction::Remediate(self.selected_index));
            self.status_message = Some(format!(
                "Triggering remediation for {}...",
                self.findings[self.selected_index].rule_id
            ));
            self.should_quit = true;
        }
    }

    pub fn trigger_baseline(&mut self) {
        if !self.findings.is_empty() {
            self.pending_action = Some(TuiAction::AddToBaseline(self.selected_index));
            self.status_message = Some(format!(
                "Added {} to baseline.",
                self.findings[self.selected_index].fingerprint
            ));
        }
    }

    pub fn trigger_ignore(&mut self) {
        if !self.findings.is_empty() {
            self.pending_action = Some(TuiAction::IgnoreFinding(self.selected_index));
            self.status_message = Some(format!(
                "Added inline ignore for finding at line {}.",
                self.findings[self.selected_index].line_number
            ));
        }
    }

    pub fn count_by_severity(&self, target: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == target)
            .count()
    }

    /// Returns lines around the vulnerable line: (start_line_1_indexed, lines_slice, target_offset)
    pub fn get_code_context(
        &self,
        file_path: &str,
        target_line: usize,
        context_radius: usize,
    ) -> (usize, Vec<String>, usize) {
        let empty_vec = Vec::new();
        let lines = self.file_cache.get(file_path).unwrap_or(&empty_vec);

        if lines.is_empty() || target_line == 0 || target_line > lines.len() {
            return (
                1,
                vec!["[Source file unavailable for preview]".to_string()],
                0,
            );
        }

        let target_idx = target_line - 1;
        let start_idx = target_idx.saturating_sub(context_radius);
        let end_idx = (target_idx + context_radius + 1).min(lines.len());

        let slice = lines[start_idx..end_idx].to_vec();
        let target_offset = target_idx - start_idx;

        (start_idx + 1, slice, target_offset)
    }
}
