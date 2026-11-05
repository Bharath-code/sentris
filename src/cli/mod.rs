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
    long_about = "Sentris scans repositories, git history, Docker/OCI images, stdin streams, and workstation AI/MCP configs at native speed (>10,000 files/sec), verifies live credentials across 12 provider APIs with Canary tripwire immunity, audits Secret Rot & Vault Coverage % (`sentris rot` / `sentris drift`), and performs safe autonomous remediation across source code, IaC, and 6 secret backends with tamper-evident SOC 2 / ISO 27001 / OWASP NHI 2025 / PCI-DSS v4.0 audit logging.",
    after_help = "QUICKSTART EXAMPLES (Human & AI Agent Mode):\n  # 1. Scan repository, staged git hunks (with auto-fix), Docker images, or stdin streams\n  sentris scan . --verify --probe\n  sentris scan --staged --fix\n  sentris scan --docker app:latest\n  gh run view --log | sentris scan --stdin\n\n  # 2. Audit Secret Rot, Vault Coverage % & configuration drift (.env.example vs .env vs vendor keys)\n  sentris rot . --verify --webhook https://hooks.slack.com/services/...\n  sentris drift . --max-age-days 90 --fail-on-drift\n\n  # 3. Autonomously remediate secrets into .env / Vault / AWS / Doppler / 1Password / Infisical\n  sentris fix src/config.ts --yes\n  sentris fix . --all --backend 1password --yes\n  sentris fix --workstation --yes\n\n  # 4. Run commands with secrets in child memory only (zero .env on disk) & export Vanta SOC 2 evidence\n  sentris run --backend env --key STRIPE_SECRET_KEY -- npm start\n  sentris audit --verify --export-vanta vanta-evidence.json\n\n  # 5. AI Coding Agent CLI Mode (deterministic JSON on stdout, zero interactive prompts)\n  sentris scan . --ignore-tests --json\n  sentris agent                  # Emit full AI Agent CLI & MCP tool schema manifest\n  sentris agent --setup          # Auto-configure .mcp.json, SKILL.md & Claude Code hooks"
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

        /// Use findings from a Betterleaks/Gitleaks JSON report (`betterleaks dir . -f json -r report.json`) instead of scanning; each entry is re-checked against the file
        #[arg(long, conflicts_with_all = ["staged", "git_history", "since"])]
        from_report: Option<PathBuf>,

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

        /// Verify detected credentials against 12 live provider APIs (with Canary/Honeytoken tripwire immunity) and map identity/permission scopes
        #[arg(long, default_value_t = false)]
        verify: bool,

        /// Probe each detected Stripe, GitHub, AWS, Hugging Face or GitLab credential read-only to see what it can reach, emit OWASP NHI5 least-privilege advisories, and rank findings by risk tier (makes network calls; never mutates anything)
        #[arg(long, default_value_t = false)]
        probe: bool,

        /// Exit 1 when any finding is at or above this risk tier (critical, high, medium, low); a finding that was not probed counts at its severity
        #[arg(long, value_enum)]
        fail_on: Option<crate::exposure::RiskTier>,

        /// Audit local workstation AI coding agent & MCP config files (.mcp.json, ~/.cursor/mcp.json, ~/.claude.json, ~/.claude/projects/**/*.jsonl, ~/.zsh_history, ~/.npmrc, etc.) for plaintext secrets
        #[arg(long, default_value_t = false)]
        workstation: bool,

        /// Scan an arbitrary stream from standard input (e.g. `gh run view --log | sentris scan --stdin` or `docker history`)
        #[arg(long, default_value_t = false, conflicts_with_all = ["staged", "git_history", "since", "workstation", "from_report"])]
        stdin: bool,

        /// Scan a Docker/OCI container image or exported `.tar` archive across all layers and detect Ghost Layer secrets deleted in later layers
        #[arg(long, conflicts_with_all = ["staged", "git_history", "since", "workstation", "stdin", "from_report"])]
        docker: Option<String>,

        /// Automatically remediate detected findings in-place (and re-stage patched files when combined with `--staged`)
        #[arg(long, default_value_t = false)]
        fix: bool,

        /// Ignore findings inside unit/integration test files and test fixture directories (`tests/`, `__tests__/`, `fixtures/`, `*.test.*`, `*.spec.*`)
        #[arg(long, default_value_t = false)]
        ignore_tests: bool,
    },

    /// Audit Secret Rot & Configuration Drift: watches `.env`, `.env.example`, CI workflows, and vendor keys for stale (>90d), dead/revoked, orphaned, or leaked keys
    #[command(visible_alias = "rot", visible_alias = "doctor")]
    Drift {
        /// Target repository directory to audit (defaults to current directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Exit with non-zero code (1) if any configuration drift, secret rot, missing keys, or hardcoded secrets are detected
        #[arg(long, visible_alias = "fail-on-rot", default_value_t = false)]
        fail_on_drift: bool,

        /// Maximum credential age in days before a key in `.env` is flagged as stale Secret Rot (PCI-DSS v4.0 / OWASP NHI1 default: 90 days)
        #[arg(long, default_value_t = 90)]
        max_age_days: u64,

        /// Verify vendor keys in `.env` against 12 live provider APIs to catch dead/revoked keys after deploy
        #[arg(long, default_value_t = false)]
        verify: bool,

        /// Dispatch a Secret Rot & Drift alert card to a Slack or Discord webhook URL when rot or drift is detected
        #[arg(long)]
        webhook: Option<String>,
    },

    /// Install the Sentris pre-commit & pre-push hooks (and optionally AI agent MCP/hook configs)
    Install {
        /// Force overwrite of existing pre-commit hook
        #[arg(short, long, default_value_t = false)]
        force: bool,

        /// Also configure workspace AI agent protection (.mcp.json, SKILL.md, and .claude/settings.local.json)
        #[arg(long, default_value_t = false)]
        with_ai: bool,

        /// Configure the pre-commit hook to automatically extract staged secrets into `.env`, patch code, and `git add` fixed files so commits succeed without blocking
        #[arg(long, default_value_t = false)]
        auto_fix: bool,
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

        /// Secret store backend to provision replacement into: env, vault, aws, doppler, 1password, infisical
        #[arg(long, default_value = "env")]
        backend: String,

        /// Rotate the leaked key at the provider: creates a replacement and keeps the old key active until `rotate finish` (AWS IAM access keys) or rolls the token value in-place (Cloudflare API tokens)
        #[arg(long, default_value_t = false)]
        rotate: bool,

        /// Batch-remediate all detected secrets in the target file or directory
        #[arg(short, long, default_value_t = false)]
        all: bool,

        /// Remediate findings from a Betterleaks/Gitleaks JSON report instead of scanning; each entry is re-checked against the file
        #[arg(long)]
        from_report: Option<PathBuf>,

        /// Remediate workstation AI/MCP configs (.mcp.json) and scrub local AI `.jsonl` transcripts / shell histories
        #[arg(long, default_value_t = false)]
        workstation: bool,
    },

    /// Guided or API-driven credential revocation with live verification polling and SOC 2 audit logging
    Revoke {
        /// The finding ID, file path, rule ID, or fingerprint prefix to revoke
        finding_id: Option<String>,

        /// Call the provider's revocation API directly when supported (e.g. GitHub `POST /credentials/revoke`)
        #[arg(long, default_value_t = false)]
        api: bool,

        /// Poll the provider's live verification API every 2 seconds until the credential flips to Revoked
        #[arg(long, default_value_t = false)]
        wait: bool,
    },

    /// Execute a command with secrets fetched from a vault/backend into child environment memory only (no `.env` on disk)
    Run {
        /// Secret store backend to fetch from: env, vault, aws, doppler, 1password, infisical
        #[arg(long, default_value = "env")]
        backend: String,

        /// Secret key / environment variable name to fetch and inject (repeatable, e.g. `--key STRIPE_SECRET_KEY`)
        #[arg(short = 'k', long = "key")]
        keys: Vec<String>,

        /// Command and arguments to execute (after `--`)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },

    /// Revert a previous remediation session and restore original files
    Rollback {
        /// The remediation session ID to revert (e.g. rm_a1b2c3d4)
        #[arg(short, long)]
        session: Option<String>,
    },

    /// Claude Code hook: blocks prompts, tool calls, Unicode tag injection, and tool outputs that would expose secrets (reads hook JSON on stdin)
    Hook {
        /// Print the settings.json snippet that registers this hook, then exit
        #[arg(long, default_value_t = false)]
        print_config: bool,

        /// Block (exit 2) when the hook itself fails, e.g. on malformed input; the default is to let the action through
        #[arg(long, default_value_t = false)]
        fail_closed: bool,
    },

    /// Forensics for a leaked key: earliest git commit, `.github/CODEOWNERS` attribution, and AWS CloudTrail activity since introduction (supports post-remediation lookup)
    Investigate {
        /// The finding ID, file path, or fingerprint prefix to investigate
        finding_id: Option<String>,

        /// Source IP you recognise (repeatable); other IPs in the provider log are flagged
        #[arg(long = "known-ip")]
        known_ips: Vec<String>,
    },

    /// Finish, inspect or undo key rotations started with `remediate --rotate`
    Rotate {
        #[command(subcommand)]
        subcommand: RotateSubcommand,
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

        /// Export 1-Click Vanta / Drata compliance evidence JSON pack (SOC 2 Type II CC6.1/CC6.7/CC6.8, ISO 27001 A.8.24, OWASP NHI Top 10:2025 + Vault Coverage %, PCI-DSS v4.0)
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
pub enum RotateSubcommand {
    /// List rotations and their state
    Status,

    /// Deactivate the old key once the grace window has passed and the provider shows no use since rotation began
    Finish {
        /// Rotation id (rot_...)
        id: String,

        /// Deactivate now even inside the grace window or if the old key was used recently
        #[arg(long, default_value_t = false)]
        force: bool,

        /// Also permanently delete the old key after deactivating it
        #[arg(long, default_value_t = false)]
        delete_old: bool,
    },

    /// Reactivate the old key and delete the new one
    Undo {
        /// Rotation id (rot_...)
        id: String,
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
