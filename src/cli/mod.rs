pub mod completions;
pub mod handlers;

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "sentris",
    author = "Sentris Contributors",
    version = env!("CARGO_PKG_VERSION"),
    about = "High-performance, memory-safe, zero-knowledge secret scanner with autonomous remediation.",
    long_about = "Sentris scans repositories at native speed (>10,000 files/sec), verifies live credentials via provider APIs, and enables safe autonomous remediation without production downtime."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Suppress non-essential informational banners and tips (ideal for CI/CD)
    #[arg(short, long, global = true, default_value_t = false)]
    pub quiet: bool,

    /// Disable colored terminal output (also respects NO_COLOR environment variable)
    #[arg(long, global = true, default_value_t = false)]
    pub no_color: bool,

    /// Zero-egress offline mode: suppress all network requests, live provider API checks, and webhook alerts
    #[arg(long, global = true, default_value_t = false)]
    pub offline: bool,

    /// Machine-readable AI Agent mode: emit structured JSON on stdout across all subcommands, disable ANSI/spinners, and auto-approve non-interactive actions (also activated via SENTRIS_AGENT=1)
    #[arg(long, visible_alias = "agent", global = true, default_value_t = false)]
    pub json: bool,
}

impl Cli {
    /// Returns true if the CLI was invoked in AI Agent / structured JSON mode (`--json`, `--agent`, or `SENTRIS_AGENT=1`).
    pub fn is_agent_mode(&self) -> bool {
        self.json
            || std::env::var("SENTRIS_AGENT")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
    }
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Recursively scan files and directories for hardcoded credentials
    Scan {
        /// Target directory or file path to scan (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Scan only git staged files/diffs (sub-35ms pre-commit mode)
        #[arg(long, default_value_t = false)]
        staged: bool,

        /// Scan deep git commit history and diff logs for leaked credentials
        #[arg(long, default_value_t = false)]
        git_history: bool,

        /// Scan git commits since a given commit ref or branch range (e.g. HEAD~1 or origin/main..HEAD)
        #[arg(long)]
        since: Option<String>,

        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,

        /// Exit with non-zero code (1) if any secrets are detected (useful for CI/CD)
        #[arg(long, default_value_t = false)]
        fail_on_secret: bool,

        /// Dispatch incident alert cards to a Slack or Discord webhook URL
        #[arg(long)]
        webhook: Option<String>,

        /// Path to baseline snapshot file to suppress pre-existing findings
        #[arg(long)]
        baseline: Option<PathBuf>,

        /// Record detected findings into a new baseline snapshot file
        #[arg(long)]
        record_baseline: Option<PathBuf>,

        /// Minimum severity floor (critical, high, medium, low)
        #[arg(long, value_enum)]
        min_severity: Option<crate::model::Severity>,

        /// Synchronize zero-knowledge salted HMAC-SHA256 findings to Sentris Pro Cloud
        #[arg(long, default_value_t = false)]
        cloud: bool,

        /// Verify detected credentials against live provider APIs and map identity/permission scopes
        #[arg(long, default_value_t = false)]
        verify: bool,
    },

    /// Install the Sentris pre-commit hook into .git/hooks/pre-commit
    Install {
        /// Force overwrite of existing pre-commit hook
        #[arg(short, long, default_value_t = false)]
        force: bool,
    },

    /// Uninstall the Sentris pre-commit hook
    Uninstall,

    /// Safely auto-remediate a detected secret finding
    #[command(visible_alias = "fix")]
    Remediate {
        /// The finding ID, file path, or fingerprint prefix to remediate
        finding_id: Option<String>,

        /// Run in dry-run preview mode without making external API changes
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Auto-approve all confirmation prompts (required in non-interactive CI/CD)
        #[arg(short, long, default_value_t = false)]
        yes: bool,

        /// Secret store backend to provision replacement into: env, vault, aws, doppler
        #[arg(long, default_value = "env")]
        backend: String,

        /// Provider-side rotation (not supported yet: errors out before touching anything)
        #[arg(long, default_value_t = false)]
        rotate: bool,

        /// Batch-remediate all detected secrets in the target file or directory
        #[arg(short, long, default_value_t = false)]
        all: bool,
    },

    /// Revert a previous remediation session and restore original files
    Rollback {
        /// The remediation session ID to revert (e.g. rm_a1b2c3d4)
        #[arg(short, long)]
        session: Option<String>,
    },

    /// Isolate a leaked credential into a Zone 3 quarantine branch and generate a scrub playbook
    Quarantine {
        /// The finding ID, rule ID, or fingerprint prefix to quarantine
        finding_id: String,

        /// Custom branch name (defaults to sentris/quarantine/<finding-id>)
        #[arg(short, long)]
        branch: Option<String>,
    },

    /// Generate shell autocompletion scripts (bash, zsh, fish)
    Completions {
        /// Target shell to generate completions for
        #[arg(value_enum)]
        shell: completions::ShellType,
    },

    /// Initialize a new .sentris.toml configuration file in the current repository
    Init {
        /// Force overwrite of existing configuration file
        #[arg(short, long, default_value_t = false)]
        force: bool,
    },

    /// Launch interactive terminal UI review session for detected findings
    Review {
        /// Target directory or file path to scan (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Filter findings by minimum severity floor (critical, high, medium, low)
        #[arg(long, value_enum)]
        min_severity: Option<crate::model::Severity>,
    },

    /// Manage baseline snapshots to suppress legacy secrets
    Baseline {
        #[command(subcommand)]
        subcommand: BaselineSubcommand,
    },

    /// Verify SOC 2 cryptographic hash chain and append-only audit ledger integrity
    Audit {
        /// Path to the audit ledger file (defaults to .sentris/audit_ledger.json)
        #[arg(short, long, default_value = ".sentris/audit_ledger.json")]
        ledger: PathBuf,

        /// Verify integrity of the cryptographic hash chain
        #[arg(long, default_value_t = true)]
        verify: bool,

        /// Export 1-Click Vanta / Drata SOC 2 Type II (CC6.1, CC6.7, CC6.8) compliance evidence JSON pack
        #[arg(long)]
        export_vanta: Option<PathBuf>,
    },

    /// Migrate existing .gitleaks.toml configuration into native .sentris.toml
    MigrateGitleaks {
        /// Path to source .gitleaks.toml file
        #[arg(default_value = ".gitleaks.toml")]
        input: PathBuf,

        /// Destination path for generated .sentris.toml file
        #[arg(short, long, default_value = ".sentris.toml")]
        output: PathBuf,

        /// Force overwrite of existing destination file
        #[arg(short, long, default_value_t = false)]
        force: bool,
    },

    /// Manage Sentris Pro Cloud authentication and developer license tokens
    Auth {
        #[command(subcommand)]
        subcommand: AuthSubcommand,
    },

    /// Synchronize local repository findings to Sentris Pro Cloud dashboard
    Sync {
        /// Target directory or file path to scan and sync (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Repository name override (defaults to current folder name)
        #[arg(long)]
        repo: Option<String>,

        /// Branch name override
        #[arg(long)]
        branch: Option<String>,
    },

    /// View team license utilization, seat allocation ($8/seat Pro tier), and active member roster
    Team,

    /// Start Model Context Protocol (MCP) JSON-RPC 2.0 server over stdio for AI coding agents
    Mcp {
        /// Print ready-to-paste MCP configuration JSON for Cursor, Claude Code, and Antigravity
        #[arg(long, default_value_t = false)]
        print_config: bool,
    },

    /// Start Language Server Protocol (LSP 3.17) server over stdio for real-time IDE diagnostics and Quick Fix code actions
    Lsp,

    /// Emit AI Agent tool schemas, CLI capability manifest, or auto-configure workspace MCP & SKILL.md for coding agents
    #[command(visible_alias = "ai")]
    Agent {
        /// Write .mcp.json and .agents/skills/sentris-security/SKILL.md into the workspace so AI agents auto-discover Sentris
        #[arg(long, default_value_t = false)]
        setup: bool,

        /// Target workspace directory for --setup (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum AuthSubcommand {
    /// Log in with a Sentris Pro license token or API key
    Login {
        /// Sentris Pro API token (starts with `sp_live_` or license key)
        #[arg(short, long)]
        token: String,

        /// Custom Sentris Pro Cloud API endpoint (defaults to https://api.sentris.dev)
        #[arg(long)]
        server: Option<String>,

        /// Join an existing team with the 64-hex team secret from your first teammate's login.
        /// Pass `-` to paste it at a prompt (keeps it out of shell history), or set SENTRIS_TEAM_SECRET.
        /// Omit on the first machine to generate one. Never sent to Sentris Cloud.
        #[arg(long)]
        team_secret: Option<String>,
    },

    /// Check active authentication and organization subscription status
    Status,

    /// Log out and remove stored developer credentials
    Logout,
}

#[derive(Subcommand, Debug, Clone)]
pub enum BaselineSubcommand {
    /// Scan target path and record findings into a baseline file
    Record {
        /// Target directory or file path to scan (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Destination baseline snapshot file (defaults to .sentris-baseline.json)
        #[arg(short, long, default_value = ".sentris-baseline.json")]
        output: PathBuf,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
    Github,
    Gitlab,
}
