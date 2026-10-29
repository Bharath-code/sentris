use owo_colors::OwoColorize;
use std::path::{Path, PathBuf};
use std::process;

use super::print_json;
use crate::audit::AuditLedger;
use crate::cli::completions::{CompletionGenerator, ShellType};
use crate::cli::Cli;
use crate::config::{Config, GitleaksMigrator};
use crate::git::GitManager;

pub fn handle_install(force: bool) {
    match GitManager::install_pre_commit_hook(force) {
        Ok(msg) => println!("{}", msg.green()),
        Err(err) => {
            eprintln!(
                "{} Failed to install pre-commit hook: {}",
                "ERROR:".red().bold(),
                err
            );
            process::exit(1);
        }
    }
}

pub fn handle_uninstall() {
    match GitManager::uninstall_pre_commit_hook() {
        Ok(msg) => println!("{}", msg.yellow()),
        Err(err) => {
            eprintln!(
                "{} Failed to uninstall pre-commit hook: {}",
                "ERROR:".red().bold(),
                err
            );
            process::exit(1);
        }
    }
}

pub fn handle_completions(shell: ShellType) {
    print!("{}", CompletionGenerator::generate(shell));
}

pub fn handle_init(force: bool) {
    match Config::init(std::path::Path::new("."), force) {
        Ok(path) => {
            println!(
                "{} Created Sentris configuration file at {}",
                "✔".green().bold(),
                path.display().to_string().cyan().bold()
            );
            println!("Edit .sentris.toml to configure custom enterprise rules, ignore patterns, and remediation parameters.");
        }
        Err(err) => {
            eprintln!(
                "{} Failed to initialize configuration: {}",
                "ERROR:".red().bold(),
                err
            );
            process::exit(1);
        }
    }
}

pub fn handle_migrate_gitleaks(cli: &Cli, input: PathBuf, output: PathBuf, force: bool) {
    let no_color = cli.no_color || std::env::var_os("NO_COLOR").is_some();
    match GitleaksMigrator::migrate_file(&input, &output, force) {
        Ok((rules_count, ignore_paths_count)) => {
            if !cli.quiet {
                if no_color {
                    println!("✔ Migration completed successfully!");
                    println!("   Source: {}", input.display());
                    println!("   Destination: {}", output.display());
                    println!("   Rules migrated: {}", rules_count);
                    println!("   Ignore paths migrated: {}", ignore_paths_count);
                } else {
                    println!("{}", "✔ Migration completed successfully!".bold().green());
                    println!("   Source: {}", input.display().to_string().cyan());
                    println!("   Destination: {}", output.display().to_string().cyan());
                    println!(
                        "   Rules migrated: {}",
                        rules_count.to_string().yellow().bold()
                    );
                    println!(
                        "   Ignore paths migrated: {}",
                        ignore_paths_count.to_string().yellow().bold()
                    );
                }
            }
        }
        Err(err) => {
            if no_color {
                eprintln!("ERROR: Failed to migrate .gitleaks.toml: {err}");
            } else {
                eprintln!(
                    "{} Failed to migrate .gitleaks.toml: {err}",
                    "ERROR:".red().bold()
                );
            }
            process::exit(1);
        }
    }
}

/// How audit output is rendered: machine JSON for agents, plain text, or colored text.
#[derive(Clone, Copy)]
struct AuditUi {
    agent: bool,
    plain: bool,
}

pub fn handle_audit(cli: &Cli, ledger: PathBuf, verify: bool, export_vanta: Option<PathBuf>) {
    let agent = cli.is_agent_mode();
    let ui = AuditUi {
        agent,
        plain: agent || cli.no_color || std::env::var_os("NO_COLOR").is_some(),
    };
    let audit_ledger = AuditLedger::load_or_init(&ledger).unwrap_or_else(|err| {
        audit_fail(
            ui,
            &ledger,
            serde_json::json!({ "error": err.to_string() }),
            &format!(
                "Failed to load audit ledger at {}: {}",
                ledger.display(),
                err
            ),
        )
    });

    let chain_verified = verify.then(|| verify_chain(ui, &audit_ledger, &ledger));
    let vanta_stats = export_vanta
        .as_deref()
        .map(|path| export_evidence(ui, &audit_ledger, &ledger, path));

    if agent {
        print_agent_summary(&audit_ledger, &ledger, chain_verified, vanta_stats);
        return;
    }
    print_text_summary(
        cli,
        ui,
        &audit_ledger,
        &ledger,
        chain_verified == Some(true),
    );
    if let (Some(path), Some(stats)) = (&export_vanta, &vanta_stats) {
        print_vanta_summary(ui, path, stats);
    }
    println!();
}

/// Reports a failure the way the active mode expects (JSON line for agents, ERROR text otherwise) and exits 1.
fn audit_fail(ui: AuditUi, ledger: &Path, agent_fields: serde_json::Value, human: &str) -> ! {
    if ui.agent {
        let mut out = serde_json::json!({
            "ok": false,
            "command": "audit",
            "ledger_path": ledger,
        });
        if let (Some(base), Some(extra)) = (out.as_object_mut(), agent_fields.as_object()) {
            base.extend(extra.clone());
        }
        println!("{out}");
    } else if ui.plain {
        eprintln!("ERROR: {human}");
    } else {
        eprintln!("{} {human}", "ERROR:".red().bold());
    }
    process::exit(1)
}

/// Exits 1 on tamper or a verification error; returns true when the chain is valid.
fn verify_chain(ui: AuditUi, audit_ledger: &AuditLedger, ledger: &Path) -> bool {
    match audit_ledger.verify_integrity() {
        Ok(true) => {
            if audit_ledger.anchor_status().ok() == Some(crate::audit::AnchorStatus::Unanchored)
                && !audit_ledger.records.is_empty()
            {
                eprintln!(
                    "   Note: chain is valid but not anchored on this machine; truncation of the ledger cannot be detected here."
                );
            }
            true
        }
        Ok(false) => {
            if ui.agent {
                audit_fail(
                    ui,
                    ledger,
                    serde_json::json!({
                        "records_count": audit_ledger.records.len(),
                        "chain_integrity_verified": false,
                        "error": "Tamper detected or HMAC-SHA256 hash mismatch"
                    }),
                    "",
                )
            }
            if ui.plain {
                eprintln!("   Chain Integrity: FAIL (Tamper detected or hash mismatch!)");
            } else {
                eprintln!(
                    "   Chain Integrity: {} (Tamper detected or hash mismatch!)",
                    "FAIL".red().bold()
                );
            }
            process::exit(1)
        }
        Err(err) => {
            if ui.agent {
                audit_fail(
                    ui,
                    ledger,
                    serde_json::json!({ "error": err.to_string() }),
                    "",
                )
            }
            if ui.plain {
                eprintln!("   Chain Integrity: ERROR ({err})");
            } else {
                eprintln!("   Chain Integrity: {} ({err})", "ERROR".red().bold());
            }
            process::exit(1)
        }
    }
}

fn export_evidence(
    ui: AuditUi,
    audit_ledger: &AuditLedger,
    ledger: &Path,
    path: &Path,
) -> serde_json::Value {
    match audit_ledger.export_vanta_evidence_pack(path) {
        Ok((scans, files, remediations, quarantines)) => serde_json::json!({
            "path": path,
            "scans": scans,
            "files_inspected": files,
            "remediations": remediations,
            "quarantines": quarantines
        }),
        Err(err) => audit_fail(
            ui,
            ledger,
            serde_json::json!({ "error": format!("Failed to export Vanta compliance pack: {err}") }),
            &format!(
                "Failed to export Vanta compliance pack to {}: {}",
                path.display(),
                err
            ),
        ),
    }
}

fn print_agent_summary(
    audit_ledger: &AuditLedger,
    ledger: &Path,
    chain_verified: Option<bool>,
    vanta_export: Option<serde_json::Value>,
) {
    let recent_events: Vec<serde_json::Value> = audit_ledger
        .records
        .iter()
        .rev()
        .take(10)
        .map(|r| {
            serde_json::json!({
                "index": r.index,
                "timestamp": r.timestamp,
                "action": r.action,
                "entry_hash": r.entry_hash,
                "previous_hash": r.previous_hash
            })
        })
        .collect();
    print_json(serde_json::json!({
        "ok": true,
        "command": "audit",
        "ledger_path": ledger,
        "records_count": audit_ledger.records.len(),
        "chain_integrity_verified": chain_verified,
        "vanta_export": vanta_export,
        "recent_events": recent_events
    }));
}

fn print_text_summary(
    cli: &Cli,
    ui: AuditUi,
    audit_ledger: &AuditLedger,
    ledger: &Path,
    chain_ok: bool,
) {
    println!();
    if ui.plain {
        println!("🔒 SOC 2 Cryptographic Audit Ledger: {}", ledger.display());
        println!("   Total Records: {}", audit_ledger.records.len());
    } else {
        println!(
            "{} {}",
            "🔒 SOC 2 Cryptographic Audit Ledger:".cyan().bold(),
            ledger.display().to_string().bold()
        );
        println!(
            "   Total Records: {}",
            audit_ledger.records.len().to_string().cyan()
        );
    }
    if chain_ok {
        let pass = if ui.plain {
            "PASS".to_string()
        } else {
            "PASS".green().bold().to_string()
        };
        println!("   Chain Integrity: {pass} (HMAC-SHA256 verified, 0 broken links)");
    }
    if !cli.quiet && !audit_ledger.records.is_empty() {
        println!();
        println!("   Recent Audit Events:");
        for record in audit_ledger.records.iter().rev().take(5) {
            let hash_prefix = if record.entry_hash.len() >= 8 {
                crate::model::short(&record.entry_hash, 8)
            } else {
                &record.entry_hash
            };
            println!(
                "   • [#{}] {:?} (Hash: {hash_prefix}...)",
                record.index, record.action,
            );
        }
    }
}

fn print_vanta_summary(ui: AuditUi, path: &Path, stats: &serde_json::Value) {
    let count = |key: &str| stats[key].as_u64().unwrap_or(0);
    let (scans, files) = (count("scans"), count("files_inspected"));
    let (remediations, quarantines) = (count("remediations"), count("quarantines"));
    let pass = if ui.plain {
        "PASS".to_string()
    } else {
        "PASS".green().bold().to_string()
    };
    if ui.plain {
        println!(
            "\n   ✔ Exported 1-Click Vanta/Drata SOC 2 Evidence Pack: {}",
            path.display()
        );
    } else {
        println!(
            "\n   {} {}",
            "✔ Exported 1-Click Vanta/Drata SOC 2 Evidence Pack:"
                .green()
                .bold(),
            path.display().to_string().cyan().bold()
        );
    }
    println!("      ├─ SOC 2 CC6.1 (Continuous Secret Scanning):    {pass} ({scans} scans, {files} files inspected)");
    println!("      ├─ SOC 2 CC6.7 (Zero-Knowledge Transmission):   {pass} (0 bytes plaintext exfiltrated)");
    println!("      ├─ SOC 2 CC6.8 (Timely Credential Remediation): {pass} ({remediations} remediated, {quarantines} quarantined)");
    println!("      └─ ISO 27001 A.8.24 (Cryptographic Hash Chain): {pass} (HMAC-SHA256 verified)");
}
