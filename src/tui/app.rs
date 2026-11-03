use std::fs::File;
use std::io::{BufRead, BufReader};
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
    pub status_message: Option<String>,
    pub should_quit: bool,
    pub pending_action: Option<TuiAction>,
}

impl App {
    pub fn new(findings: Vec<Finding>) -> Self {
        Self {
            findings,
            selected_index: 0,
            status_message: None,
            should_quit: false,
            pending_action: None,
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
            self.should_quit = true;
        }
    }

    pub fn trigger_ignore(&mut self) {
        if !self.findings.is_empty() {
            self.pending_action = Some(TuiAction::IgnoreFinding(self.selected_index));
            self.status_message = Some(format!(
                "Added inline ignore for finding at line {}.",
                self.findings[self.selected_index].line_number
            ));
            self.should_quit = true;
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
        let unavailable = || {
            (
                1,
                vec!["[Source file unavailable for preview]".to_string()],
                0,
            )
        };
        if target_line == 0 {
            return unavailable();
        }
        let path = Path::new(file_path);
        let Ok(file) = File::open(path) else {
            return unavailable();
        };

        let target_idx = target_line - 1;
        let start_idx = target_idx.saturating_sub(context_radius);
        let window_len = (target_idx - start_idx) + context_radius + 1;
        let target_offset = target_idx - start_idx;

        let slice: Vec<String> = BufReader::new(file)
            .lines()
            .skip(start_idx)
            .take(window_len)
            .map_while(Result::ok)
            .collect();

        if slice.len() <= target_offset {
            return unavailable();
        }

        (start_idx + 1, slice, target_offset)
    }
}
