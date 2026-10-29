pub mod audit;
pub mod cloud;
pub mod quarantine;
pub mod remediate;
pub mod review;
pub mod scan;
mod scan_output;

use owo_colors::OwoColorize;

use crate::cli::{Cli, Commands};

const AUDIT_LEDGER_PATH: &str = ".sentris/audit_ledger.json";

/// Best-effort append to the SOC 2 audit ledger; a ledger problem never fails the command.
pub(super) fn record_audit_event(action: crate::audit::AuditAction, details: serde_json::Value) {
    if let Ok(mut ledger) = crate::audit::AuditLedger::load_or_init(AUDIT_LEDGER_PATH) {
        let _ = ledger.record_event(action, details);
        let _ = ledger.save();
    }
}

/// Pretty-prints a machine-readable (agent mode) result to stdout.
pub(super) fn print_json(value: serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(&value).unwrap_or_default()
    );
}

/// Prints `ERROR: <context>: <err>` to stderr and exits with status 1.
pub(super) fn die(context: &str, err: impl std::fmt::Display) -> ! {
    eprintln!("{} {}: {}", "ERROR:".red().bold(), context, err);
    std::process::exit(1)
}

/// Dispatches the parsed CLI subcommand to its modular handler.
pub fn execute(cli: Cli) {
    let command = cli.command.clone();
    match command {
        Commands::Scan {
            path,
            staged,
            git_history,
            since,
            format,
            fail_on_secret,
            webhook,
            baseline,
            record_baseline,
            min_severity,
            cloud,
            verify,
        } => scan::handle_scan(
            &cli,
            path,
            staged,
            git_history,
            since,
            format,
            fail_on_secret,
            webhook,
            baseline,
            record_baseline,
            min_severity,
            cloud,
            verify,
        ),
        Commands::Install { force } => audit::handle_install(force),
        Commands::Uninstall => audit::handle_uninstall(),
        Commands::Remediate {
            finding_id,
            dry_run,
            yes,
            backend,
            rotate,
            all,
        } => remediate::handle_remediate(&cli, finding_id, dry_run, yes, backend, rotate, all),
        Commands::Rollback { session } => remediate::handle_rollback(&cli, session),
        Commands::Quarantine { finding_id, branch } => {
            quarantine::handle_quarantine(&cli, finding_id, branch)
        }
        Commands::Completions { shell } => audit::handle_completions(shell),
        Commands::Init { force } => audit::handle_init(force),
        Commands::Review { path, min_severity } => review::handle_review(&cli, path, min_severity),
        Commands::Baseline { subcommand } => review::handle_baseline(subcommand),
        Commands::Audit {
            ledger,
            verify,
            export_vanta,
        } => audit::handle_audit(&cli, ledger, verify, export_vanta),
        Commands::MigrateGitleaks {
            input,
            output,
            force,
        } => audit::handle_migrate_gitleaks(&cli, input, output, force),
        Commands::Auth { subcommand } => cloud::handle_auth(&cli, subcommand),
        Commands::Sync { path, repo, branch } => cloud::handle_sync(&cli, path, repo, branch),
        Commands::Team => cloud::handle_team(&cli),
        Commands::Mcp { print_config } => cloud::handle_mcp(&cli, print_config),
        Commands::Lsp => cloud::handle_lsp(),
        Commands::Agent { setup, path } => cloud::handle_agent(setup, path),
    }
}

/// Prints `ERROR: <message>` to stderr and exits with status 1.
pub(super) fn fail(message: &str) -> ! {
    eprintln!("{} {}", "ERROR:".red().bold(), message);
    std::process::exit(1)
}
