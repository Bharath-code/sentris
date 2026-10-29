use std::path::PathBuf;

use super::remediate::scan_target_for;
use super::{die, fail, print_json, record_audit_event};
use crate::audit::AuditAction;
use crate::cli::Cli;
use crate::error::SentrisError;
use crate::git::GitManager;
use crate::investigate::investigate_target;
use crate::scanner::Scanner;

pub fn handle_investigate(cli: &Cli, finding_id: Option<String>, known_ips: Vec<String>) {
    let scanner = Scanner::new().unwrap_or_else(|err| die("Failed to initialize scanner", err));
    let target = scan_target_for(finding_id.as_deref());
    let repo = GitManager::find_git_root().unwrap_or_else(|_| PathBuf::from("."));
    let inv = investigate_target(&scanner, &target, finding_id.as_deref(), &known_ips, &repo)
        .unwrap_or_else(|err| match err {
            SentrisError::Refused(msg) => {
                eprintln!("REFUSED: {msg}");
                std::process::exit(2)
            }
            other => die("Investigation failed", other),
        })
        .unwrap_or_else(|| fail("Could not find a matching finding to investigate."));

    if inv.supported {
        record_audit_event(
            AuditAction::InvestigationRun {
                finding_id: inv.finding_id.clone(),
                provider: "AWS".to_string(),
            },
            serde_json::json!({"rule_id": inv.rule_id, "known_ip_count": known_ips.len()}),
        );
    }
    if cli.is_agent_mode() {
        print_json(inv.to_json());
    } else {
        print!("{}", inv.to_text());
    }
}
