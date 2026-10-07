pub mod completions;

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
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
}

#[derive(Subcommand, Debug)]
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

        /// Output format
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,

        /// Exit with non-zero code (1) if any secrets are detected (useful for CI/CD)
        #[arg(long, default_value_t = false)]
        fail_on_secret: bool,
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
    Remediate {
        /// The finding ID, file path, or fingerprint prefix to remediate
        finding_id: Option<String>,

        /// Run in dry-run preview mode without making external API changes
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Auto-approve all confirmation prompts (required in non-interactive CI/CD)
        #[arg(short, long, default_value_t = false)]
        yes: bool,
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
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
    Github,
}
