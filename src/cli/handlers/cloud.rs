use owo_colors::OwoColorize;
use std::path::PathBuf;
use std::process;

use super::scan_output::print_blast_radius;
use super::{die, fail, print_json};
use crate::cli::Cli;
use crate::cloud::{build_cloud_payload, upload_scan, Credentials, TeamInfo};
use crate::git::GitManager;
use crate::scanner::Scanner;

pub fn handle_sync(cli: &Cli, path: PathBuf, repo: Option<String>, branch: Option<String>) {
    if cli.offline {
        fail("Cannot sync in zero-egress offline mode.");
    }
    let creds = Credentials::load_default().unwrap_or_else(|err| {
        eprintln!("{} {}", "Authentication required:".yellow().bold(), err);
        println!("Run `sentris auth login --token <TOKEN>` to link your Pro account.");
        process::exit(1);
    });
    let scanner = Scanner::new().unwrap_or_else(|err| die("Failed to initialize scanner", err));
    let report = scanner
        .scan_path(&path)
        .unwrap_or_else(|err| die("Failed during scan", err));

    let effective_repo = repo.or_else(|| {
        GitManager::find_git_root()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
    });
    let effective_branch = branch.or_else(|| GitManager::get_head_branch().ok().flatten());
    let commit = GitManager::get_head_commit().ok().flatten();
    let payload = build_cloud_payload(
        &report,
        &creds,
        effective_repo.as_deref(),
        effective_branch.as_deref(),
        commit,
    )
    .unwrap_or_else(|err| fail(&err.to_string()));

    let res = upload_scan(&payload, &creds, false)
        .unwrap_or_else(|err| die("Failed to upload to Sentris Pro Cloud", err));
    if !cli.quiet {
        println!(
            "{} {}",
            "✔ Sentris Pro Cloud:".cyan().bold(),
            res.message.green()
        );
        println!("   Scan ID: {}", res.scan_id.bold());
        println!("   Findings Synced: {}", payload.findings.len());
        println!("   Dashboard: {}", res.dashboard_url.underline());
        print_blast_radius(&res.blast_radius_insights);
    }
}

pub fn handle_team(cli: &Cli) {
    let no_color = cli.no_color || std::env::var_os("NO_COLOR").is_some();
    let creds = Credentials::load_default().unwrap_or_else(|_| Credentials {
        api_key: "sp_preview_token".to_string(),
        server_url: "https://api.sentris.dev".to_string(),
        org_id: "org_sample_team".to_string(),
        org_name: "Sentris Pro Workspace (Preview)".to_string(),
        tier: "Pro ($8/seat)".to_string(),
        seat_limit: 20,
        seats_used: 14,
        user_email: "dev@sentris.dev".to_string(),
        expires_at: None,
        team_secret: None,
    });
    let team = TeamInfo::from_credentials(&creds);
    if cli.is_agent_mode() {
        print_json(serde_json::json!({
            "ok": true,
            "command": "team",
            "org_id": team.org_id,
            "org_name": team.org_name,
            "tier": team.tier,
            "seats_used": team.seats_used,
            "seat_limit": team.seat_limit,
            "unit_price_usd": team.unit_price_usd,
            "monthly_cost_usd": team.seats_used * team.unit_price_usd,
            "zero_knowledge_bytes_ingested": 0,
            "blast_radius_insights": team.blast_radius_insights
        }));
    } else {
        println!("{}", team.render_terminal(no_color));
    }
}

pub fn handle_mcp(cli: &Cli, print_config: bool) {
    if print_config {
        println!("{}", crate::mcp::McpServer::generate_config_snippet());
        return;
    }
    if let Err(err) = crate::mcp::McpServer::run_stdio_loop(cli.offline) {
        die("MCP server error", err);
    }
}

pub fn handle_lsp() {
    if let Err(err) = crate::lsp::LspServer::run_stdio_loop() {
        die("LSP server error", err);
    }
}

pub fn handle_agent(setup: bool, path: PathBuf) {
    if !setup {
        print_json(crate::mcp::McpServer::generate_agent_manifest());
        return;
    }
    let files = crate::mcp::McpServer::setup_workspace_for_agents(&path)
        .unwrap_or_else(|err| die("Agent setup failed", err));
    print_json(serde_json::json!({
        "ok": true,
        "command": "agent_setup",
        "workspace": path.display().to_string(),
        "files_written": files,
        "message": "Workspace configured for AI coding agents (.mcp.json + .agents/skills/sentris-security/SKILL.md)."
    }));
}
