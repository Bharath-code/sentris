use owo_colors::OwoColorize;
use std::path::PathBuf;
use std::process;

use crate::cli::{AuthSubcommand, Cli};
use crate::cloud::auth::{generate_team_secret, validate_team_secret};
use crate::cloud::{build_cloud_payload, upload_scan, Credentials, TeamInfo};
use crate::git::GitManager;
use crate::scanner::Scanner;

pub fn handle_auth(cli: &Cli, subcommand: AuthSubcommand) {
    let no_color = cli.no_color || std::env::var_os("NO_COLOR").is_some();
    match subcommand {
        AuthSubcommand::Login {
            token,
            server,
            team_secret,
        } => match Credentials::from_token(&token, server) {
            Ok(mut creds) => {
                let path = Credentials::default_credentials_path();
                // Precedence: explicit flag > secret already on this machine > new secret
                let (secret, generated) = match team_secret.as_deref().map(validate_team_secret) {
                    Some(Ok(s)) => (s, false),
                    Some(Err(err)) => {
                        eprintln!("{} {}", "ERROR:".red().bold(), err);
                        process::exit(1);
                    }
                    None => match Credentials::load_from_path(&path)
                        .ok()
                        .and_then(|c| c.team_secret)
                    {
                        Some(existing) => (existing, false),
                        None => match generate_team_secret() {
                            Ok(s) => (s, true),
                            Err(err) => {
                                eprintln!("{} {}", "ERROR:".red().bold(), err);
                                process::exit(1);
                            }
                        },
                    },
                };
                creds.team_secret = Some(secret.clone());
                if let Err(err) = creds.save_to_path(&path) {
                    eprintln!(
                        "{} Failed to save credentials: {}",
                        "ERROR:".red().bold(),
                        err
                    );
                    process::exit(1);
                }
                if !cli.quiet {
                    if no_color {
                        println!("✔ Successfully authenticated with Sentris Pro Cloud!");
                        println!("   Organization: {}", creds.org_name);
                        println!("   Tier: {}", creds.tier);
                        println!(
                            "   Seats: {}/{} occupied",
                            creds.seats_used, creds.seat_limit
                        );
                        println!("   Credentials stored: {}", path.display());
                        if generated {
                            println!("   New team secret (share privately with teammates; Sentris never sees it):");
                            println!("     sentris auth login --token <THEIR_KEY> --team-secret {secret}");
                        }
                    } else {
                        println!(
                            "{}",
                            "✔ Successfully authenticated with Sentris Pro Cloud!"
                                .green()
                                .bold()
                        );
                        println!("   Organization: {}", creds.org_name.cyan().bold());
                        println!("   Tier: {}", creds.tier.yellow());
                        println!(
                            "   Seats: {}/{} occupied",
                            creds.seats_used.to_string().bold(),
                            creds.seat_limit
                        );
                        println!(
                            "   Credentials stored: {}",
                            path.display().to_string().dimmed()
                        );
                        if generated {
                            println!(
                                "   {} share privately with teammates; Sentris never sees it:",
                                "New team secret —".yellow().bold()
                            );
                            println!("     sentris auth login --token <THEIR_KEY> --team-secret {secret}");
                        }
                    }
                }
            }
            Err(err) => {
                eprintln!("{} Authentication failed: {}", "ERROR:".red().bold(), err);
                process::exit(1);
            }
        },
        AuthSubcommand::Status => match Credentials::load_default() {
            Ok(creds) => {
                if no_color {
                    println!("Active Sentris Pro Cloud Session:");
                    println!("   Organization: {} ({})", creds.org_name, creds.org_id);
                    println!("   Account: {}", creds.user_email);
                    println!("   Tier: {}", creds.tier);
                    println!(
                        "   Seats: {}/{} occupied ($8/dev/mo Pro Tier)",
                        creds.seats_used, creds.seat_limit
                    );
                    println!("   Endpoint: {}", creds.server_url);
                } else {
                    println!("{}", "Active Sentris Pro Cloud Session:".cyan().bold());
                    println!(
                        "   Organization: {} ({})",
                        creds.org_name.bold(),
                        creds.org_id.dimmed()
                    );
                    println!("   Account: {}", creds.user_email);
                    println!("   Tier: {}", creds.tier.green().bold());
                    println!(
                        "   Seats: {}/{} occupied ($8/dev/mo Pro Tier)",
                        creds.seats_used.to_string().yellow().bold(),
                        creds.seat_limit
                    );
                    println!("   Endpoint: {}", creds.server_url.dimmed());
                }
            }
            Err(err) => {
                if !cli.quiet {
                    if no_color {
                        eprintln!("No active session: {err}");
                        println!("Run `sentris auth login --token <TOKEN>` to authenticate.");
                    } else {
                        eprintln!("{} {}", "No active session:".yellow().bold(), err);
                        println!("Run `sentris auth login --token <TOKEN>` to authenticate.");
                    }
                }
                process::exit(1);
            }
        },
        AuthSubcommand::Logout => {
            let _ = Credentials::delete_default();
            if !cli.quiet {
                println!(
                    "{}",
                    "✔ Logged out from Sentris Pro Cloud. Local credentials cleared.".green()
                );
            }
        }
    }
}

pub fn handle_sync(cli: &Cli, path: PathBuf, repo: Option<String>, branch: Option<String>) {
    if cli.offline {
        eprintln!(
            "{}",
            "ERROR: Cannot sync in zero-egress offline mode."
                .red()
                .bold()
        );
        process::exit(1);
    }
    let creds = match Credentials::load_default() {
        Ok(c) => c,
        Err(err) => {
            eprintln!("{} {}", "Authentication required:".yellow().bold(), err);
            println!("Run `sentris auth login --token <TOKEN>` to link your Pro account.");
            process::exit(1);
        }
    };
    let scanner = match Scanner::new() {
        Ok(s) => s,
        Err(err) => {
            eprintln!(
                "{} Failed to initialize scanner: {}",
                "ERROR:".red().bold(),
                err
            );
            process::exit(1);
        }
    };
    let report = match scanner.scan_path(&path) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("{} Failed during scan: {}", "ERROR:".red().bold(), err);
            process::exit(1);
        }
    };
    let effective_repo = repo.or_else(|| {
        GitManager::find_git_root()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
    });
    let effective_branch = branch.or_else(|| GitManager::get_head_branch().ok().flatten());
    let commit = GitManager::get_head_commit().ok().flatten();
    let payload = match build_cloud_payload(
        &report,
        &creds,
        effective_repo.as_deref(),
        effective_branch.as_deref(),
        commit,
    ) {
        Ok(p) => p,
        Err(err) => {
            eprintln!("{} {}", "ERROR:".red().bold(), err);
            process::exit(1);
        }
    };
    match upload_scan(&payload, &creds, false) {
        Ok(res) => {
            if !cli.quiet {
                println!(
                    "{} {}",
                    "✔ Sentris Pro Cloud:".cyan().bold(),
                    res.message.green()
                );
                println!("   Scan ID: {}", res.scan_id.bold());
                println!("   Findings Synced: {}", payload.findings.len());
                println!("   Dashboard: {}", res.dashboard_url.underline());
                let multi_repo: Vec<_> = res
                    .blast_radius_insights
                    .iter()
                    .filter(|i| i.affected_repos.len() > 1)
                    .collect();
                if !multi_repo.is_empty() {
                    println!(
                        "   {}",
                        "⚡ Zero-Knowledge Multi-Repo Blast Radius Insight (0 Bytes Source Ingested):"
                            .yellow()
                            .bold()
                    );
                    for insight in multi_repo {
                        let short_fp = if insight.zk_fingerprint.len() > 15 {
                            &insight.zk_fingerprint[..15]
                        } else {
                            &insight.zk_fingerprint
                        };
                        println!(
                            "      • {}... ({}) reused across {} repos: [{}]",
                            short_fp.cyan(),
                            insight.rule_id.red().bold(),
                            insight.affected_repos.len(),
                            insight.affected_repos.join(", ").yellow()
                        );
                    }
                }
            }
        }
        Err(err) => {
            eprintln!(
                "{} Failed to upload to Sentris Pro Cloud: {}",
                "ERROR:".red().bold(),
                err
            );
            process::exit(1);
        }
    }
}

pub fn handle_team(cli: &Cli) {
    let is_agent_mode = cli.is_agent_mode();
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
    if is_agent_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
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
            }))
            .unwrap_or_default()
        );
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
        eprintln!("{} MCP server error: {}", "ERROR:".red().bold(), err);
        process::exit(1);
    }
}

pub fn handle_lsp() {
    if let Err(err) = crate::lsp::LspServer::run_stdio_loop() {
        eprintln!("{} LSP server error: {}", "ERROR:".red().bold(), err);
        process::exit(1);
    }
}

pub fn handle_agent(setup: bool, path: PathBuf) {
    if setup {
        match crate::mcp::McpServer::setup_workspace_for_agents(&path) {
            Ok(files) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "command": "agent_setup",
                        "workspace": path.display().to_string(),
                        "files_written": files,
                        "message": "Workspace configured for AI coding agents (.mcp.json + .agents/skills/sentris-security/SKILL.md)."
                    }))
                    .unwrap_or_default()
                );
            }
            Err(err) => {
                eprintln!("{} Agent setup failed: {}", "ERROR:".red().bold(), err);
                process::exit(1);
            }
        }
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&crate::mcp::McpServer::generate_agent_manifest())
                .unwrap_or_default()
        );
    }
}
