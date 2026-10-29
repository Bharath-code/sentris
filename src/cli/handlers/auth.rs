use owo_colors::OwoColorize;
use std::path::Path;
use std::process;

use super::{die, fail};
use crate::cli::{AuthSubcommand, Cli};
use crate::cloud::auth::{generate_team_secret, validate_team_secret};
use crate::cloud::Credentials;

/// Read the team secret from stdin so it never appears in argv or shell history.
fn read_team_secret_from_stdin() -> String {
    use std::io::{BufRead, IsTerminal, Write};
    if std::io::stdin().is_terminal() {
        eprint!("Paste team secret: ");
        let _ = std::io::stderr().flush();
    }
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    line.trim().to_string()
}

pub fn handle_auth(cli: &Cli, subcommand: AuthSubcommand) {
    let plain = cli.no_color || std::env::var_os("NO_COLOR").is_some();
    match subcommand {
        AuthSubcommand::Login {
            token,
            server,
            team_secret,
        } => login(cli, plain, &token, server, team_secret.as_deref()),
        AuthSubcommand::Status => status(cli, plain),
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

fn login(cli: &Cli, plain: bool, token: &str, server: Option<String>, team_secret: Option<&str>) {
    let mut creds = Credentials::from_token(token, server)
        .unwrap_or_else(|err| die("Authentication failed", err));
    if let Err(err) = creds.refresh_from_server() {
        die("Authentication failed", err);
    }
    let path = Credentials::default_credentials_path();
    let (secret, generated) = resolve_team_secret(team_secret, &path);
    creds.team_secret = Some(secret.clone());
    if let Err(err) = creds.save_to_path(&path) {
        die("Failed to save credentials", err);
    }
    if !cli.quiet {
        print_login_summary(plain, &creds, &path, generated.then_some(secret.as_str()));
    }
}

/// Precedence: explicit flag > `SENTRIS_TEAM_SECRET` > secret already on this machine > a new one.
/// The bool is true only for a freshly generated secret, which must be shown to the user once.
fn resolve_team_secret(flag: Option<&str>, path: &Path) -> (String, bool) {
    let provided = match flag {
        Some("-") => Some(read_team_secret_from_stdin()),
        Some(v) => Some(v.to_string()),
        None => std::env::var("SENTRIS_TEAM_SECRET")
            .ok()
            .filter(|v| !v.is_empty()),
    };
    if let Some(value) = provided {
        let secret = validate_team_secret(&value).unwrap_or_else(|err| fail(&err.to_string()));
        return (secret, false);
    }
    if let Some(existing) = Credentials::load_from_path(path)
        .ok()
        .and_then(|c| c.team_secret)
    {
        return (existing, false);
    }
    let secret = generate_team_secret().unwrap_or_else(|err| fail(&err.to_string()));
    (secret, true)
}

fn print_login_summary(plain: bool, creds: &Credentials, path: &Path, new_secret: Option<&str>) {
    if plain {
        println!("✔ Successfully authenticated with Sentris Pro Cloud!");
        println!("   Organization: {}", creds.org_name);
        println!("   Tier: {}", creds.tier);
        println!(
            "   Seats: {}/{} occupied",
            creds.seats_used, creds.seat_limit
        );
        println!("   Credentials stored: {}", path.display());
        if let Some(secret) = new_secret {
            println!("   New team secret (store in your password manager; Sentris never sees it):");
            println!("     {secret}");
            println!("   Teammates join with `sentris auth login --token <THEIR_KEY> --team-secret -` and paste it.");
        }
        return;
    }
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
    if let Some(secret) = new_secret {
        println!(
            "   {} store in your password manager; Sentris never sees it:",
            "New team secret —".yellow().bold()
        );
        println!("     {}", secret.bold());
        println!(
            "   Teammates join with {} and paste it.",
            "sentris auth login --token <THEIR_KEY> --team-secret -".cyan()
        );
    }
}

fn status(cli: &Cli, plain: bool) {
    let creds = match Credentials::load_default() {
        Ok(creds) => creds,
        Err(err) => {
            if !cli.quiet {
                if plain {
                    eprintln!("No active session: {err}");
                } else {
                    eprintln!("{} {}", "No active session:".yellow().bold(), err);
                }
                println!("Run `sentris auth login --token <TOKEN>` to authenticate.");
            }
            process::exit(1);
        }
    };
    if plain {
        println!("Active Sentris Pro Cloud Session:");
        println!("   Organization: {} ({})", creds.org_name, creds.org_id);
        println!("   Account: {}", creds.user_email);
        println!("   Tier: {}", creds.tier);
        println!(
            "   Seats: {}/{} occupied ($8/dev/mo Pro Tier)",
            creds.seats_used, creds.seat_limit
        );
        println!("   Endpoint: {}", creds.server_url);
        return;
    }
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
