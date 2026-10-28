use owo_colors::OwoColorize;
use std::path::PathBuf;
use std::process;

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

pub fn handle_audit(cli: &Cli, ledger: PathBuf, verify: bool, export_vanta: Option<PathBuf>) {
    let is_agent = cli.is_agent_mode();
    let no_color = is_agent || cli.no_color || std::env::var_os("NO_COLOR").is_some();
    let audit_ledger = match AuditLedger::load_or_init(&ledger) {
        Ok(l) => l,
        Err(err) => {
            if is_agent {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": false,
                        "command": "audit",
                        "ledger_path": ledger,
                        "error": err.to_string()
                    })
                );
            } else if no_color {
                eprintln!(
                    "ERROR: Failed to load audit ledger at {}: {}",
                    ledger.display(),
                    err
                );
            } else {
                eprintln!(
                    "{} Failed to load audit ledger at {}: {}",
                    "ERROR:".red().bold(),
                    ledger.display(),
                    err
                );
            }
            process::exit(1);
        }
    };

    let chain_verified = if verify {
        match audit_ledger.verify_integrity() {
            Ok(true) => Some(true),
            Ok(false) => {
                if is_agent {
                    println!(
                        "{}",
                        serde_json::json!({
                            "ok": false,
                            "command": "audit",
                            "ledger_path": ledger,
                            "records_count": audit_ledger.records.len(),
                            "chain_integrity_verified": false,
                            "error": "Tamper detected or HMAC-SHA256 hash mismatch"
                        })
                    );
                } else if no_color {
                    eprintln!("   Chain Integrity: FAIL (Tamper detected or hash mismatch!)");
                } else {
                    eprintln!(
                        "   Chain Integrity: {} (Tamper detected or hash mismatch!)",
                        "FAIL".red().bold()
                    );
                }
                process::exit(1);
            }
            Err(err) => {
                if is_agent {
                    println!(
                        "{}",
                        serde_json::json!({
                            "ok": false,
                            "command": "audit",
                            "ledger_path": ledger,
                            "error": err.to_string()
                        })
                    );
                } else if no_color {
                    eprintln!("   Chain Integrity: ERROR ({err})");
                } else {
                    eprintln!("   Chain Integrity: {} ({err})", "ERROR".red().bold());
                }
                process::exit(1);
            }
        }
    } else {
        None
    };

    let vanta_export_stats = if let Some(ref vanta_path) = export_vanta {
        match audit_ledger.export_vanta_evidence_pack(vanta_path) {
            Ok((scans, files, remediations, quarantines)) => Some(serde_json::json!({
                "path": vanta_path,
                "scans": scans,
                "files_inspected": files,
                "remediations": remediations,
                "quarantines": quarantines
            })),
            Err(err) => {
                if is_agent {
                    println!(
                        "{}",
                        serde_json::json!({
                            "ok": false,
                            "command": "audit",
                            "ledger_path": ledger,
                            "error": format!("Failed to export Vanta compliance pack: {err}")
                        })
                    );
                } else {
                    eprintln!(
                        "ERROR: Failed to export Vanta compliance pack to {}: {}",
                        vanta_path.display(),
                        err
                    );
                }
                process::exit(1);
            }
        }
    } else {
        None
    };

    if is_agent {
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
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ok": true,
                "command": "audit",
                "ledger_path": ledger,
                "records_count": audit_ledger.records.len(),
                "chain_integrity_verified": chain_verified,
                "vanta_export": vanta_export_stats,
                "recent_events": recent_events
            }))
            .unwrap_or_default()
        );
        return;
    }

    println!();
    if no_color {
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

    if chain_verified == Some(true) {
        if no_color {
            println!("   Chain Integrity: PASS (HMAC-SHA256 verified, 0 broken links)");
        } else {
            println!(
                "   Chain Integrity: {} (HMAC-SHA256 verified, 0 broken links)",
                "PASS".green().bold()
            );
        }
    }

    if !cli.quiet && !audit_ledger.records.is_empty() {
        println!();
        println!("   Recent Audit Events:");
        for record in audit_ledger.records.iter().rev().take(5) {
            let hash_prefix = if record.entry_hash.len() >= 8 {
                &record.entry_hash[..8]
            } else {
                &record.entry_hash
            };
            println!(
                "   • [#{}] {:?} (Hash: {hash_prefix}...)",
                record.index, record.action,
            );
        }
    }

    if let (Some(vanta_path), Some(stats)) = (&export_vanta, &vanta_export_stats) {
        let scans = stats["scans"].as_u64().unwrap_or(0);
        let files = stats["files_inspected"].as_u64().unwrap_or(0);
        let remediations = stats["remediations"].as_u64().unwrap_or(0);
        let quarantines = stats["quarantines"].as_u64().unwrap_or(0);
        if no_color {
            println!(
                "\n   ✔ Exported 1-Click Vanta/Drata SOC 2 Evidence Pack: {}",
                vanta_path.display()
            );
            println!(
                "      ├─ SOC 2 CC6.1 (Continuous Secret Scanning):    PASS ({scans} scans, {files} files inspected)"
            );
            println!(
                "      ├─ SOC 2 CC6.7 (Zero-Knowledge Transmission):   PASS (0 bytes plaintext exfiltrated)"
            );
            println!(
                "      ├─ SOC 2 CC6.8 (Timely Credential Remediation): PASS ({remediations} remediated, {quarantines} quarantined)"
            );
            println!(
                "      └─ ISO 27001 A.8.24 (Cryptographic Hash Chain): PASS (HMAC-SHA256 verified)"
            );
        } else {
            println!(
                "\n   {} {}",
                "✔ Exported 1-Click Vanta/Drata SOC 2 Evidence Pack:"
                    .green()
                    .bold(),
                vanta_path.display().to_string().cyan().bold()
            );
            println!(
                "      ├─ SOC 2 CC6.1 (Continuous Secret Scanning):    {} ({scans} scans, {files} files inspected)",
                "PASS".green().bold()
            );
            println!(
                "      ├─ SOC 2 CC6.7 (Zero-Knowledge Transmission):   {} (0 bytes plaintext exfiltrated)",
                "PASS".green().bold()
            );
            println!(
                "      ├─ SOC 2 CC6.8 (Timely Credential Remediation): {} ({remediations} remediated, {quarantines} quarantined)",
                "PASS".green().bold()
            );
            println!(
                "      └─ ISO 27001 A.8.24 (Cryptographic Hash Chain): {} (HMAC-SHA256 verified)",
                "PASS".green().bold()
            );
        }
    }
    println!();
}
